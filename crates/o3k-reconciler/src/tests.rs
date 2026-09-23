#[cfg(test)]
mod reconciler_tests {
    use crate::storage_workflow;
    use crate::*;
    use o3k_kernel::MeteringRepository;
    use o3k_provider::{FailureInjection, FakeComputeProvider};
    use o3k_store::testkit::TestStore;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

    #[test]
    fn test_fault_pause_guard_accepts_only_positive_numeric_durations() {
        assert_eq!(test_fault_pause_ms_value(None), None);
        assert_eq!(test_fault_pause_ms_value(Some(String::new())), None);
        assert_eq!(test_fault_pause_ms_value(Some("0".to_owned())), None);
        assert_eq!(test_fault_pause_ms_value(Some("abc".to_owned())), None);
        assert_eq!(test_fault_pause_ms_value(Some("250".to_owned())), Some(250));
    }

    fn request() -> CreateInstanceRequest {
        CreateInstanceRequest {
            operation_id: Uuid::now_v7(),
            o3k_server_id: Uuid::now_v7(),
            project_id: "project".to_owned(),
            name: "journal-test".to_owned(),
            vcpus: 1,
            memory_mib: 128,
            flavor_id: String::new(),
            disk_gib: 0,
            image_id: None,
            key_name: None,
            keypair_id: None,
            network_ids: Vec::new(),
            placement_provider_id: None,
            placement_allocation_id: None,
            config_drive: None,
            idempotency_key: "journal-test-key".to_owned(),
        }
    }

    async fn journal(
        label: &str,
        max_attempts: u8,
    ) -> Result<
        (
            OperationJournal<TestStore, FakeComputeProvider>,
            Arc<TestStore>,
            Arc<FakeComputeProvider>,
        ),
        ReconcileError,
    > {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-{label}-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
        let provider = Arc::new(FakeComputeProvider::new());
        Ok((
            OperationJournal::new(store.clone(), provider.clone(), max_attempts),
            store,
            provider,
        ))
    }

    async fn bind_observation_command(
        store: &TestStore,
        operation_id: Uuid,
        resource_id: Uuid,
        agent_id: &str,
        agent_epoch: &str,
    ) -> Result<(), ReconcileError> {
        let command_id = format!("observation-command-{operation_id}");
        bind_command(
            store,
            command_id.clone(),
            operation_id,
            resource_id,
            agent_id,
            agent_epoch,
        )
        .await?;
        store
            .update_agent_command(&command_id, AgentCommandState::Succeeded, 1, 1, None, None)
            .await?;
        Ok(())
    }

    async fn bind_command(
        store: &TestStore,
        command_id: String,
        operation_id: Uuid,
        resource_id: Uuid,
        agent_id: &str,
        agent_epoch: &str,
    ) -> Result<(), ReconcileError> {
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id,
                idempotency_key: format!("observation-{operation_id}"),
                operation_id,
                resource_id,
                agent_id: agent_id.to_owned(),
                agent_epoch: agent_epoch.to_owned(),
                payload_fingerprint_sha256: "f".repeat(64),
                payload: Vec::new(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: None,
                provider_resource_id: None,
            })
            .await?;
        Ok(())
    }

    /// Minimal in-memory node registry used to simulate agent registration and
    /// re-registration. A re-registration replaces the stored epoch, mirroring
    /// `NodeRegistry::register` in o3k-compute-agent.
    #[derive(Clone, Default)]
    struct TestAgentRegistry {
        nodes: Arc<tokio::sync::RwLock<HashMap<String, o3k_provider::AgentNodeSnapshot>>>,
    }

    struct TestAgentEpochLease {
        _nodes: tokio::sync::OwnedRwLockReadGuard<HashMap<String, o3k_provider::AgentNodeSnapshot>>,
    }

    impl o3k_provider::AgentEpochLease for TestAgentEpochLease {}

    #[async_trait::async_trait]
    impl o3k_provider::AgentNodeRegistry for TestAgentRegistry {
        async fn all(&self) -> Vec<o3k_provider::AgentNodeSnapshot> {
            self.nodes.read().await.values().cloned().collect()
        }

        async fn snapshot(&self, agent_id: &str) -> Option<o3k_provider::AgentNodeSnapshot> {
            self.nodes.read().await.get(agent_id).cloned()
        }

        async fn lease_current_epoch(
            &self,
            agent_id: &str,
            agent_epoch: &str,
        ) -> Option<Box<dyn o3k_provider::AgentEpochLease>> {
            let nodes = self.nodes.clone().read_owned().await;
            if nodes
                .get(agent_id)
                .is_some_and(|node| node.agent_epoch == agent_epoch)
            {
                Some(Box::new(TestAgentEpochLease { _nodes: nodes }))
            } else {
                None
            }
        }

        fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<o3k_provider::AgentEvent> {
            let (_, receiver) = tokio::sync::broadcast::channel(1);
            receiver
        }
    }

    impl TestAgentRegistry {
        /// Registers (or re-registers) the agent, replacing the stored epoch.
        async fn register(&self, agent_id: &str, agent_epoch: &str) {
            self.nodes.write().await.insert(
                agent_id.to_owned(),
                o3k_provider::AgentNodeSnapshot {
                    agent_id: agent_id.to_owned(),
                    agent_epoch: agent_epoch.to_owned(),
                    availability: o3k_provider::AgentAvailability::Available,
                    administrative_state: o3k_provider::AgentAdministrativeState::Enabled,
                    capabilities: o3k_provider::AgentCapabilities {
                        agent_provider_name: "o3k-compute".to_owned(),
                        agent_provider_version: "test".to_owned(),
                        max_vcpus: 1,
                        max_memory_mib: 128,
                        max_disk_gb: 1,
                        lifecycle_actions: Vec::new(),
                        console_log: false,
                        flags: Vec::new(),
                    },
                },
            );
        }
    }

    struct ForeignOperationProvider {
        inner: FakeComputeProvider,
    }

    impl ForeignOperationProvider {
        fn new() -> Self {
            Self {
                inner: FakeComputeProvider::new(),
            }
        }

        fn foreign(mut operation: o3k_provider::Operation) -> o3k_provider::Operation {
            operation.o3k_operation_id = Uuid::now_v7();
            operation
        }
    }

    #[async_trait::async_trait]
    impl o3k_provider::ComputeProvider for ForeignOperationProvider {
        async fn capabilities(
            &self,
        ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.create_instance(request).await.map(Self::foreign)
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
            self.inner.get_instance(provider_instance_id).await
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.delete_instance(request).await.map(Self::foreign)
        }

        async fn action_instance(
            &self,
            provider_instance_id: &str,
            action: o3k_provider::InstanceAction,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .action_instance(provider_instance_id, action, operation_id, idempotency_key)
                .await
                .map(Self::foreign)
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .get_operation(provider_operation_id)
                .await
                .map(Self::foreign)
        }
    }

    #[tokio::test]
    async fn intent_and_provider_success_are_durable() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("success", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn create_rejects_provider_operation_owned_by_another_request()
    -> Result<(), ReconcileError> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-foreign-create-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
        let provider = Arc::new(ForeignOperationProvider::new());
        let journal = OperationJournal::new(store.clone(), provider, 2);
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;

        assert!(matches!(
            journal.reconcile_once(operation_id).await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_recovery_rejects_foreign_provider_operation() -> Result<(), ReconcileError> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-foreign-unknown-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
        let provider = Arc::new(ForeignOperationProvider::new());
        provider.inner.set_failure(FailureInjection::Timeout)?;
        let journal = OperationJournal::new(store.clone(), provider, 2);
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert!(matches!(
            journal.reconcile_once(operation_id).await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_failed_create_update_marks_resource_error_and_replays_safely()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-create-failed", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            format!("command-{operation_id}"),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        let update = failed_update(
            &operation_id.to_string(),
            &request.o3k_server_id.to_string(),
            "agent-1",
            "epoch-1",
            "gateway preparation failed",
        )?;
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::Failed
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ERROR"
        );
        // A replayed delivery of the same terminal update stays Failed and
        // keeps the ERROR projection without reviving the operation.
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::Failed
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ERROR"
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Failed
        );
        Ok(())
    }

    #[test]
    fn agent_failure_reason_is_sanitized_bounded_and_fallback_safe() {
        // Redaction contract: control characters never reach durable storage
        // or operator logs, so a crafted payload cannot forge log lines.
        assert_eq!(
            bounded_agent_failure_message("gateway preparation failed:\n\tforeign interface\r\n"),
            "gateway preparation failed:  foreign interface"
        );
        // Truncation: oversized reasons are bounded with an explicit marker.
        let long = "x".repeat(MAX_AGENT_FAILURE_MESSAGE_LEN + 100);
        let bounded = bounded_agent_failure_message(&long);
        assert_eq!(bounded.len(), MAX_AGENT_FAILURE_MESSAGE_LEN + 3);
        assert!(bounded.ends_with("..."));
        // Fallback: an empty or whitespace-only reason stays actionable.
        assert_eq!(bounded_agent_failure_message(""), "agent operation failed");
        assert_eq!(
            bounded_agent_failure_message("  \n\t "),
            "agent operation failed"
        );
    }

    #[tokio::test]
    async fn agent_failed_update_persists_the_bounded_agent_reason() -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-failed-reason", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            format!("command-{operation_id}"),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        let update = failed_update(
            &operation_id.to_string(),
            &request.o3k_server_id.to_string(),
            "agent-1",
            "epoch-1",
            "gateway preparation failed:\nexisting interface is foreign",
        )?;
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::Failed
        );
        assert_eq!(
            store
                .get_operation(operation_id)
                .await?
                .error_message
                .as_deref(),
            Some("gateway preparation failed: existing interface is foreign")
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_success_is_durable_and_idempotent() -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-success", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            format!("command-{operation_id}"),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        let update = AgentOperationUpdate {
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            operation_sequence: 1,
            operation_id,
            resource_id: request.o3k_server_id,
            state: AgentOperationState::Succeeded,
            error_category: None,
            redacted_message: None,
            provider_resource_id: Some("agent-domain-1".to_owned()),
        };
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "REQUESTED"
        );
        assert_eq!(
            store
                .get_provider_reference(request.o3k_server_id, "compute-agent")
                .await?
                .provider_resource_id,
            "agent-domain-1"
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_update_rejects_agent_namespace_provider_identity_drift()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-reference-identity", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        let command_id = format!("command-{operation_id}");
        bind_command(
            &store,
            command_id.clone(),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        store
            .attach_provider_reference(&ProviderReference {
                resource_id: request.o3k_server_id,
                provider_name: "agent".to_owned(),
                provider_resource_id: "domain-established".to_owned(),
            })
            .await?;
        let update = AgentOperationUpdate {
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            operation_sequence: 1,
            operation_id,
            resource_id: request.o3k_server_id,
            state: AgentOperationState::Succeeded,
            error_category: None,
            redacted_message: None,
            provider_resource_id: Some("domain-conflict".to_owned()),
        };
        assert!(matches!(
            journal.apply_agent_update(&update).await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store.get_agent_command(&command_id).await?.state,
            AgentCommandState::Pending
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Pending
        );
        assert_eq!(
            store
                .get_provider_reference(request.o3k_server_id, "agent")
                .await?
                .provider_resource_id,
            "domain-established"
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_evidence_rejects_foreign_and_stale_updates() -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-evidence-fence", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            format!("command-{operation_id}"),
            operation_id,
            request.o3k_server_id,
            "agent-a",
            "epoch-a",
        )
        .await?;
        let succeeded = AgentOperationUpdate {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-a".to_owned(),
            operation_sequence: 2,
            operation_id,
            resource_id: request.o3k_server_id,
            state: AgentOperationState::Succeeded,
            error_category: None,
            redacted_message: None,
            provider_resource_id: Some("domain-a".to_owned()),
        };
        assert_eq!(
            journal.apply_agent_update(&succeeded).await?,
            OperationState::Succeeded
        );
        let stale = AgentOperationUpdate {
            operation_sequence: 1,
            state: AgentOperationState::Running,
            error_category: None,
            redacted_message: None,
            provider_resource_id: None,
            ..succeeded.clone()
        };
        assert!(matches!(
            journal.apply_agent_update(&stale).await,
            Err(ReconcileError::InvalidIntent)
        ));
        let foreign = AgentOperationUpdate {
            agent_id: "agent-b".to_owned(),
            agent_epoch: "epoch-b".to_owned(),
            operation_sequence: 3,
            state: AgentOperationState::Failed,
            error_category: Some(AgentErrorCategory::Terminal),
            redacted_message: None,
            ..succeeded.clone()
        };
        assert!(matches!(
            journal.apply_agent_update(&foreign).await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        Ok(())
    }

    /// Without a registry the fence keeps the strict first-evidence anchor: a
    /// same-agent epoch change is indistinguishable from a dead stream and
    /// must stay rejected. This pins the no-registry fallback so the
    /// registry-aware fence (issue #87) cannot weaken it.
    #[tokio::test]
    async fn agent_evidence_epoch_change_is_rejected_without_registry() -> Result<(), ReconcileError>
    {
        let (journal, store, _) = journal("agent-fence-no-registry", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            "command-1".to_owned(),
            operation_id,
            request.o3k_server_id,
            "agent-a",
            "epoch-a",
        )
        .await?;
        let accepted = AgentCommandAccepted {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-a".to_owned(),
            command_id: "command-1".to_owned(),
            operation_id,
            state: AgentOperationState::Accepted,
            operation_sequence: 1,
        };
        assert_eq!(
            journal.apply_agent_acceptance(&accepted).await?,
            OperationState::Running
        );
        let replayed_under_other_epoch = AgentCommandAccepted {
            agent_epoch: "epoch-b".to_owned(),
            ..accepted.clone()
        };
        assert!(matches!(
            journal
                .apply_agent_acceptance(&replayed_under_other_epoch)
                .await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );
        Ok(())
    }

    /// Issue #87 regression: after a compute-agent crash and restart the agent
    /// re-registers with a fresh per-connection epoch and replays its durable
    /// journal for the in-flight operation. The replay is evidence from the
    /// agent's *current* registered epoch and must be applied — not rejected
    /// because the pre-crash acceptance was anchored to the old epoch.
    #[tokio::test]
    async fn agent_replay_after_reregistration_applies_unknown_outcome()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-reregister-replay", 2).await?;
        let registry = TestAgentRegistry::default();
        registry.register("agent-a", "epoch-a").await;
        let journal = journal.with_agent_registry(Arc::new(registry.clone()));

        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            "command-1".to_owned(),
            operation_id,
            request.o3k_server_id,
            "agent-a",
            "epoch-b",
        )
        .await?;
        let accepted = AgentCommandAccepted {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-a".to_owned(),
            command_id: "command-1".to_owned(),
            operation_id,
            state: AgentOperationState::Accepted,
            operation_sequence: 1,
        };
        // Pre-crash: the control plane records the acceptance under epoch-a.
        assert_eq!(
            journal.apply_agent_acceptance(&accepted).await?,
            OperationState::Running
        );

        // The agent crashes and re-registers; the registry now stores epoch-b.
        registry.register("agent-a", "epoch-b").await;

        // Post-restart replay of the same acceptance under the new epoch must
        // stay idempotent, not be fenced as a foreign stream.
        let replayed_accepted = AgentCommandAccepted {
            agent_epoch: "epoch-b".to_owned(),
            ..accepted.clone()
        };
        assert_eq!(
            journal.apply_agent_acceptance(&replayed_accepted).await?,
            OperationState::Running
        );

        // The journal replay then delivers the crashed create's UnknownOutcome
        // and the operation must converge out of Running.
        let update = AgentOperationUpdate {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-b".to_owned(),
            operation_sequence: 2,
            operation_id,
            resource_id: request.o3k_server_id,
            state: AgentOperationState::UnknownOutcome,
            error_category: None,
            redacted_message: None,
            provider_resource_id: None,
        };
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        Ok(())
    }

    /// ASR-015 real-host regression: the agent persists terminal execution
    /// before its E1 stream is lost, then replays that result under E2.  A
    /// preceding terminal observation may win the two-consumer race and make
    /// the operation Succeeded first; the later operation update must still
    /// terminalize the matching durable command instead of leaving it
    /// recoverable forever.
    #[tokio::test]
    async fn terminal_replay_after_reregistration_converges_command_when_operation_is_terminal()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-terminal-reregister-replay", 2).await?;
        let registry = TestAgentRegistry::default();
        registry.register("agent-a", "epoch-a").await;
        let journal = journal.with_agent_registry(Arc::new(registry.clone()));

        let request = request();
        journal.begin_create("project", &request).await?;
        let resource = store.get_resource(request.o3k_server_id).await?;
        store
            .update_resource(
                request.o3k_server_id,
                resource.generation,
                &resource.desired_state,
                server_state_to_storage(ServerState::Active),
                resource.generation,
                Some("domain-a"),
            )
            .await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(request.o3k_server_id, operation_id, LifecycleAction::Reboot)
            .await?;
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: "command-1".to_owned(),
                idempotency_key: format!("asr-015-{operation_id}"),
                operation_id,
                resource_id: request.o3k_server_id,
                agent_id: "agent-a".to_owned(),
                agent_epoch: "epoch-a".to_owned(),
                payload_fingerprint_sha256: "f".repeat(64),
                payload: Vec::new(),
                state: AgentCommandState::Pending,
                accepted_sequence: 0,
                last_sequence: 0,
                provider_operation_id: Some(operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;
        let accepted = AgentCommandAccepted {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-a".to_owned(),
            command_id: "command-1".to_owned(),
            operation_id,
            state: AgentOperationState::Accepted,
            operation_sequence: 1,
        };
        assert_eq!(
            journal.apply_agent_acceptance(&accepted).await?,
            OperationState::Running
        );
        let accepted_command = store.get_agent_command("command-1").await?;
        assert_eq!(accepted_command.state, AgentCommandState::Accepted);

        registry.register("agent-a", "epoch-b").await;
        let stale = AgentOperationUpdate {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-a".to_owned(),
            operation_sequence: 2,
            operation_id,
            resource_id: request.o3k_server_id,
            state: AgentOperationState::Succeeded,
            error_category: None,
            redacted_message: None,
            provider_resource_id: Some("domain-a".to_owned()),
        };
        let operation_before_stale = store.get_operation(operation_id).await?;
        let resource_before_stale = store.get_resource(request.o3k_server_id).await?;
        let command_before_stale = store.get_agent_command("command-1").await?;
        let evidence_before_stale = journal
            .agent_evidence
            .lock()
            .map_err(|_| ReconcileError::InvalidIntent)?
            .clone();
        assert!(matches!(
            journal.apply_agent_update(&stale).await,
            Err(ReconcileError::StaleAgentEvidence)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?,
            operation_before_stale
        );
        assert_eq!(
            store.get_resource(request.o3k_server_id).await?,
            resource_before_stale
        );
        assert_eq!(
            store.get_agent_command("command-1").await?,
            command_before_stale
        );
        assert_eq!(
            journal
                .agent_evidence
                .lock()
                .map_err(|_| ReconcileError::InvalidIntent)?
                .clone(),
            evidence_before_stale
        );

        // This is the real-host ordering: the E2 observation reaches the
        // durable journal before the E2 terminal operation update.
        journal
            .apply_agent_observation(&AgentObservation {
                agent_id: "agent-a".to_owned(),
                agent_epoch: "epoch-b".to_owned(),
                resource_id: request.o3k_server_id,
                provider_resource_id: Some("domain-a".to_owned()),
                state: o3k_provider::InstanceState::Running,
                operation_id,
                operation_state: AgentOperationState::Succeeded,
                observation_sequence: 2,
                observed_at_unix_ms: 2,
                redacted_message: None,
                console_log_bytes: Vec::new(),
                console_log_offset: 0,
                console_log_complete: false,
                console_log_truncated: false,
                block_device: None,
            })
            .await?;
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_agent_command("command-1").await?.state,
            AgentCommandState::Accepted
        );
        let replayed = AgentOperationUpdate {
            agent_epoch: "epoch-b".to_owned(),
            provider_resource_id: Some("domain-a".to_owned()),
            ..stale
        };
        let conflicting = AgentOperationUpdate {
            provider_resource_id: Some("domain-b".to_owned()),
            ..replayed.clone()
        };
        let operation_before_conflict = store.get_operation(operation_id).await?;
        let resource_before_conflict = store.get_resource(request.o3k_server_id).await?;
        let command_before_conflict = store.get_agent_command("command-1").await?;
        let reference_before_conflict = store
            .get_provider_reference(request.o3k_server_id, "compute-agent")
            .await?;
        let agent_fence_before_conflict = journal
            .agent_evidence
            .lock()
            .map_err(|_| ReconcileError::InvalidIntent)?
            .clone();
        let observation_fence_before_conflict = journal
            .observation_evidence
            .lock()
            .map_err(|_| ReconcileError::InvalidIntent)?
            .clone();
        assert!(matches!(
            journal.apply_agent_update(&conflicting).await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?,
            operation_before_conflict
        );
        assert_eq!(
            store.get_resource(request.o3k_server_id).await?,
            resource_before_conflict
        );
        assert_eq!(
            store.get_agent_command("command-1").await?,
            command_before_conflict
        );
        assert_eq!(
            store
                .get_provider_reference(request.o3k_server_id, "compute-agent")
                .await?,
            reference_before_conflict
        );
        assert_eq!(
            journal
                .agent_evidence
                .lock()
                .map_err(|_| ReconcileError::InvalidIntent)?
                .clone(),
            agent_fence_before_conflict
        );
        assert_eq!(
            journal
                .observation_evidence
                .lock()
                .map_err(|_| ReconcileError::InvalidIntent)?
                .clone(),
            observation_fence_before_conflict
        );

        // Model a transient store failure after the in-memory E2 fence was
        // advanced but before command projection committed.  Equal evidence
        // must retry the idempotent durable repair, not be discarded merely
        // because its watermark is already present.
        journal
            .agent_evidence
            .lock()
            .map_err(|_| ReconcileError::InvalidIntent)?
            .insert(
                operation_id,
                AgentEvidenceFence {
                    agent_id: replayed.agent_id.clone(),
                    agent_epoch: replayed.agent_epoch.clone(),
                    sequence: replayed.operation_sequence,
                    state: replayed.state,
                    provider_resource_id: "domain-a".to_owned(),
                },
            );
        assert_eq!(
            journal.apply_agent_update(&replayed).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_agent_command("command-1").await?.state,
            AgentCommandState::Succeeded
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        let terminal_command = store.get_agent_command("command-1").await?;
        assert_eq!(terminal_command.command_id, accepted_command.command_id);
        assert_eq!(
            terminal_command.idempotency_key,
            accepted_command.idempotency_key
        );
        assert_eq!(terminal_command.operation_id, accepted_command.operation_id);
        assert_eq!(terminal_command.resource_id, accepted_command.resource_id);
        assert_eq!(terminal_command.agent_id, accepted_command.agent_id);
        assert_eq!(terminal_command.agent_epoch, accepted_command.agent_epoch);
        assert_eq!(
            terminal_command.payload_fingerprint_sha256,
            accepted_command.payload_fingerprint_sha256
        );
        assert_eq!(terminal_command.payload, accepted_command.payload);
        assert_eq!(terminal_command.accepted_sequence, 1);
        assert_eq!(terminal_command.last_sequence, 2);
        assert_eq!(
            terminal_command.provider_resource_id.as_deref(),
            Some("domain-a")
        );

        // Same-epoch replay is idempotent and cannot change durable identity.
        assert_eq!(
            journal.apply_agent_update(&replayed).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_agent_command("command-1").await?,
            terminal_command
        );
        Ok(())
    }

    /// Issue #87 invariant: evidence minted under an epoch that is no longer
    /// the agent's current registered epoch is a dead/stale stream and must be
    /// rejected, even though the same agent legitimately re-registered under a
    /// newer epoch.
    #[tokio::test]
    async fn agent_evidence_from_dead_epoch_is_rejected_after_reregistration()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-fence-dead-epoch", 2).await?;
        let registry = TestAgentRegistry::default();
        registry.register("agent-a", "epoch-b").await;
        let journal = journal.with_agent_registry(Arc::new(registry.clone()));

        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            "command-1".to_owned(),
            operation_id,
            request.o3k_server_id,
            "agent-a",
            "epoch-b",
        )
        .await?;
        let accepted = AgentCommandAccepted {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-b".to_owned(),
            command_id: "command-1".to_owned(),
            operation_id,
            state: AgentOperationState::Accepted,
            operation_sequence: 1,
        };
        assert_eq!(
            journal.apply_agent_acceptance(&accepted).await?,
            OperationState::Running
        );

        // A stale in-flight update from the agent's previous (dead) epoch must
        // not mutate current state.
        let stale_update = AgentOperationUpdate {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-a".to_owned(),
            operation_sequence: 2,
            operation_id,
            resource_id: request.o3k_server_id,
            state: AgentOperationState::Failed,
            error_category: Some(AgentErrorCategory::Terminal),
            redacted_message: None,
            provider_resource_id: None,
        };
        assert!(matches!(
            journal.apply_agent_update(&stale_update).await,
            Err(ReconcileError::StaleAgentEvidence)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );

        // An epoch that was never registered is equally stale.
        let unknown_epoch_update = AgentOperationUpdate {
            agent_epoch: "epoch-c".to_owned(),
            ..stale_update
        };
        assert!(matches!(
            journal.apply_agent_update(&unknown_epoch_update).await,
            Err(ReconcileError::StaleAgentEvidence)
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );
        Ok(())
    }

    /// ASR-015: once E1 passes current-epoch validation, its lease must keep
    /// E2 registration from becoming current until the caller finishes the
    /// durable projection. This closes the check/write interleaving where an
    /// old stream could otherwise write after E2 registration.
    #[tokio::test]
    async fn current_epoch_lease_serializes_projection_with_reregistration()
    -> Result<(), ReconcileError> {
        let (journal, _, _) = journal("agent-epoch-lease", 2).await?;
        let registry = TestAgentRegistry::default();
        registry.register("agent-a", "epoch-a").await;
        let journal = journal.with_agent_registry(Arc::new(registry.clone()));
        let permit = journal
            .fence_agent_evidence(
                Uuid::now_v7(),
                "agent-a",
                "epoch-a",
                1,
                AgentOperationState::Accepted,
                "",
            )
            .await?;

        let replacement_registry = registry.clone();
        let mut replacement = tokio::spawn(async move {
            replacement_registry.register("agent-a", "epoch-b").await;
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut replacement)
                .await
                .is_err(),
            "replacement epoch became current while E1 projection held its lease"
        );

        drop(permit);
        tokio::time::timeout(std::time::Duration::from_secs(1), replacement)
            .await
            .map_err(|_| ReconcileError::InvalidIntent)?
            .map_err(|_| ReconcileError::InvalidIntent)?;
        assert_eq!(
            o3k_provider::AgentNodeRegistry::snapshot(&registry, "agent-a")
                .await
                .map(|node| node.agent_epoch)
                .as_deref(),
            Some("epoch-b")
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_observation_projects_nova_state_and_replays_without_mutation()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-observation", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_observation_command(
            &store,
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        let observation = AgentObservation {
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            resource_id: request.o3k_server_id,
            provider_resource_id: Some("agent-domain-stopped".to_owned()),
            state: o3k_provider::InstanceState::Stopped,
            operation_id,
            operation_state: AgentOperationState::Succeeded,
            observation_sequence: 1,
            observed_at_unix_ms: 0,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        };
        journal.apply_agent_observation(&observation).await?;
        let first = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(first.observed_state, "SHUTOFF");
        assert_eq!(first.provider_id.as_deref(), Some("agent-domain-stopped"));
        journal.apply_agent_observation(&observation).await?;
        let replay = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(replay.generation, first.generation);
        assert_eq!(replay.observed_state, "SHUTOFF");
        Ok(())
    }

    #[tokio::test]
    async fn stale_agent_observation_cannot_regress_projected_state() -> Result<(), ReconcileError>
    {
        let (journal, store, _) = journal("agent-observation-order", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_observation_command(
            &store,
            operation_id,
            request.o3k_server_id,
            "compute-1",
            "epoch-1",
        )
        .await?;
        let active = AgentObservation {
            agent_id: "compute-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            resource_id: request.o3k_server_id,
            provider_resource_id: Some("agent-domain".to_owned()),
            state: o3k_provider::InstanceState::Running,
            operation_id,
            operation_state: AgentOperationState::Succeeded,
            observation_sequence: 10,
            observed_at_unix_ms: 0,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        };
        journal.apply_agent_observation(&active).await?;
        let stale = AgentObservation {
            state: o3k_provider::InstanceState::Stopped,
            observation_sequence: 9,
            ..active.clone()
        };
        journal.apply_agent_observation(&stale).await?;
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(resource.observed_state, "ACTIVE");
        assert_eq!(resource.provider_id.as_deref(), Some("agent-domain"));
        Ok(())
    }

    #[tokio::test]
    async fn agent_observation_rejects_non_succeeded_operation_state() -> Result<(), ReconcileError>
    {
        let (journal, _, _) = journal("agent-observation-invalid", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        let observation = AgentObservation {
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            resource_id: request.o3k_server_id,
            provider_resource_id: None,
            state: o3k_provider::InstanceState::Creating,
            operation_id,
            operation_state: AgentOperationState::Running,
            observation_sequence: 1,
            observed_at_unix_ms: 0,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        };
        // A non-successful operation state is not a resource observation: the
        // durable state must never be projected from it. Unrepresentable wire
        // states are additionally rejected at the transport boundary, before
        // this journal is reached.
        assert!(matches!(
            journal.apply_agent_observation(&observation).await,
            Err(ReconcileError::InvalidIntent)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn agent_observation_rejects_agent_not_bound_to_durable_command()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-observation-binding", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_observation_command(
            &store,
            operation_id,
            request.o3k_server_id,
            "agent-a",
            "epoch-a",
        )
        .await?;
        let observation = AgentObservation {
            agent_id: "agent-b".to_owned(),
            agent_epoch: "epoch-b".to_owned(),
            resource_id: request.o3k_server_id,
            provider_resource_id: Some("foreign-domain".to_owned()),
            state: o3k_provider::InstanceState::Running,
            operation_id,
            operation_state: AgentOperationState::Succeeded,
            observation_sequence: 1,
            observed_at_unix_ms: 0,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        };
        assert!(matches!(
            journal.apply_agent_observation(&observation).await,
            Err(ReconcileError::InvalidIntent)
        ));
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "REQUESTED"
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_failure_persists_the_contract_redacted_provider_reason()
    -> Result<(), ReconcileError> {
        // Contract: the agent redacts secrets and connection information
        // before sending; the control plane persists the reason bounded and
        // sanitized instead of withholding it entirely (issue #485).
        let (journal, store, _) = journal("agent-failure", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            format!("command-{operation_id}"),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        let update = failed_update(
            &operation_id.to_string(),
            &request.o3k_server_id.to_string(),
            "agent-1",
            "epoch-1",
            "gateway preparation failed: interface is foreign",
        )?;
        assert_eq!(
            journal.apply_agent_update(&update).await?,
            OperationState::Failed
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.error_category.as_deref(), Some("terminal"));
        assert_eq!(
            operation.error_message.as_deref(),
            Some("gateway preparation failed: interface is foreign")
        );
        Ok(())
    }

    #[tokio::test]
    async fn command_acceptance_is_durable_and_idempotent() -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("agent-acceptance", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_command(
            &store,
            "command-1".to_owned(),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        let accepted = AgentCommandAccepted {
            agent_id: "agent-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            command_id: "command-1".to_owned(),
            operation_id,
            state: AgentOperationState::Accepted,
            operation_sequence: 1,
        };

        assert_eq!(
            journal.apply_agent_acceptance(&accepted).await?,
            OperationState::Running
        );
        assert_eq!(
            journal.apply_agent_acceptance(&accepted).await?,
            OperationState::Running
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );
        assert_eq!(
            journal
                .events()
                .iter()
                .filter(|event| event.operation_id == operation_id)
                .count(),
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_outcome_is_observed_without_duplicate_create() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown", 2).await?;
        provider.set_failure(FailureInjection::Timeout)?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(provider.instance_count(), 1);
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        Ok(())
    }

    #[tokio::test]
    async fn partial_create_waits_for_observed_running_without_duplicate_create()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("partial-create", 2).await?;
        provider.set_failure(FailureInjection::PartialCompletion)?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Running
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(resource.observed_state, "BUILD");
        assert!(resource.provider_id.is_some());
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );

        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// Issue #611 test seam: the fake provider's idempotency replay returns
    /// the recorded (Accepted/None) operation on the create re-drive; the
    /// real provider re-executes the create (the transfer re-offer completes
    /// it) and advances the operation to Succeeded with a provider resource.
    /// This wrapper advances the recorded operation exactly when the re-drive
    /// reaches `create_instance` with the operation still Accepted.
    struct AdvancingCreateProvider {
        inner: FakeComputeProvider,
        provider_operation_id: Uuid,
    }

    impl AdvancingCreateProvider {
        fn new(inner: FakeComputeProvider, provider_operation_id: Uuid) -> Self {
            Self {
                inner,
                provider_operation_id,
            }
        }
    }

    #[async_trait::async_trait]
    impl o3k_provider::ComputeProvider for AdvancingCreateProvider {
        async fn capabilities(
            &self,
        ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            if let Ok(operation) = self.inner.get_operation(self.provider_operation_id).await
                && operation.state == o3k_provider::OperationState::Accepted
            {
                self.inner.set_operation_state(
                    self.provider_operation_id,
                    o3k_provider::OperationState::Succeeded,
                )?;
                self.inner.set_operation_provider_resource_id(
                    self.provider_operation_id,
                    Some(format!("fake-{}", request.o3k_server_id)),
                )?;
            }
            self.inner.create_instance(request).await
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
            self.inner.get_instance(provider_instance_id).await
        }

        async fn inspect_instance(
            &self,
            provider_id: &str,
            resource_id: &str,
            provider_instance_id: &str,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .inspect_instance(
                    provider_id,
                    resource_id,
                    provider_instance_id,
                    operation_id,
                    idempotency_key,
                )
                .await
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.delete_instance(request).await
        }

        async fn action_instance(
            &self,
            provider_instance_id: &str,
            action: o3k_provider::InstanceAction,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .action_instance(provider_instance_id, action, operation_id, idempotency_key)
                .await
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.get_operation(provider_operation_id).await
        }
    }

    /// Wraps the stateful fake provider so every instance is observed in the
    /// Stopped state, modeling the issue-87 crash-between-define-and-start
    /// residue: on restart the domain exists (defined) but was never started,
    /// so the adoption reconcile observes a present instance in SHUTOFF.
    struct StoppedInstanceProvider {
        inner: FakeComputeProvider,
    }

    impl StoppedInstanceProvider {
        fn new(inner: FakeComputeProvider) -> Self {
            Self { inner }
        }

        fn instance_count(&self) -> usize {
            self.inner.instance_count()
        }
    }

    #[async_trait::async_trait]
    impl o3k_provider::ComputeProvider for StoppedInstanceProvider {
        async fn capabilities(
            &self,
        ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.create_instance(request).await
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
            let mut instance = self.inner.get_instance(provider_instance_id).await?;
            instance.state = o3k_provider::InstanceState::Stopped;
            Ok(instance)
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.delete_instance(request).await
        }

        async fn action_instance(
            &self,
            provider_instance_id: &str,
            action: o3k_provider::InstanceAction,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .action_instance(provider_instance_id, action, operation_id, idempotency_key)
                .await
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.get_operation(provider_operation_id).await
        }
    }

    /// The issue-87 crash-between-define-and-start adoption: the provider
    /// create succeeded and the domain exists, but the instance is observed
    /// Stopped (defined, never started). Presence observation treats any
    /// present instance as a converged create, so the adoption must reach the
    /// terminal Succeeded state projecting SHUTOFF — never stay Running with
    /// no transition path.
    #[tokio::test]
    async fn adopted_create_with_stopped_instance_converges_to_succeeded_shutoff()
    -> Result<(), ReconcileError> {
        let (_, store, provider) = journal("adopted-shutoff", 2).await?;
        let provider = Arc::new(StoppedInstanceProvider::new(provider.as_ref().clone()));
        let journal = OperationJournal::new(store.clone(), provider.clone(), 2);
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "SHUTOFF"
        );
        assert_eq!(provider.instance_count(), 1);
        // Idempotent terminality: a second reconcile is a no-op and must
        // never duplicate the create or regress the state.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "SHUTOFF"
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// Issue #609 (ASR-021 agent-control-plane-network-interruption): a
    /// retryable provider outcome is by definition not a definitively-known
    /// failure, so exhausting the retry budget must leave the create in
    /// `UnknownOutcome` (error_category `retry_exhausted`, error kept for
    /// diagnosis) — never terminal `Failed` — and the next convergence
    /// re-drive must still converge it to `Succeeded` exactly once when the
    /// provider is healthy. The exhausted create carries no provider
    /// operation identity, so the re-drive observes presence by the durable
    /// placement identity instead of polling (or re-dispatching).
    #[tokio::test]
    async fn retry_budget_exhaustion_leaves_unknown_outcome_and_recovers()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("retry", 2).await?;
        provider.set_failure(FailureInjection::Transient)?;
        let mut request = request();
        // The exhausted create is re-observed by the durable placement
        // identity (SPEC-0021 observe-before-decide), so the intent must
        // name the execution agent.
        request.placement_provider_id = Some("agent-1".to_owned());
        let operation_id = journal.begin_create("project", &request).await?;
        // Dispatch 1: retryable, budget (2) not yet exhausted -> scheduled.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Retryable
        );
        // Dispatch 2: retryable, budget exhausted -> UnknownOutcome, and the
        // exhaustion transition fires the unknown-outcome journal event.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::UnknownOutcome);
        assert_eq!(operation.error_category.as_deref(), Some("retry_exhausted"));
        assert!(
            operation.error_message.is_some(),
            "the exhausted branch must keep the provider error for diagnosis"
        );
        assert!(journal.events().iter().any(|event| {
            event.operation_id == operation_id && event.kind == JournalEventKind::UnknownObserved
        }));
        // The interruption resolves. The create actually landed at the
        // execution boundary during the outage (only the acknowledgement was
        // lost — a timeout is an unknown outcome, not a failure), so exactly
        // one instance exists at the provider.
        provider.set_failure(FailureInjection::None)?;
        provider.create_instance(request.clone()).await?;
        assert_eq!(provider.instance_count(), 1);
        // The next convergence re-drive observes presence and adopts the
        // landed create: Succeeded, resource ACTIVE, still exactly one
        // instance (no re-dispatch, no duplicate).
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// Issue #611 (ASR-021 agent-control-plane-network-interruption): an
    /// ACCEPTED create whose provider operation never produced a provider
    /// resource (Accepted/Running with no provider_resource_id — the create
    /// provably never executed, e.g. the agent reported an unknown outcome
    /// because the committed artifacts were missing) must be re-driven by the
    /// unknown-outcome recovery — the transfer loop re-offers the missing
    /// artifact and the create converges ACTIVE — instead of being parked
    /// Running forever with no recovery path.
    #[tokio::test]
    async fn accepted_create_without_provider_resource_is_redriven_not_parked()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("accepted-never-executed", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("agent-1".to_owned());
        // The create is accepted and then reported unknown (the interrupted
        // artifact delivery shape), leaving an UnknownOutcome operation with a
        // provider operation identity.
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let operation = store.get_operation(operation_id).await?;
        let provider_operation_id = operation
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        // The provider operation is still Accepted and carries no provider
        // resource: the create provably never executed.
        provider.set_operation_state(
            provider_operation_id,
            o3k_provider::OperationState::Accepted,
        )?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The interruption resolves; the next convergence re-drive must
        // re-dispatch the create (never park it Running) and converge ACTIVE.
        provider.set_failure(FailureInjection::None)?;
        let provider = Arc::new(AdvancingCreateProvider::new(
            provider.as_ref().clone(),
            provider_operation_id,
        ));
        let journal = OperationJournal::new(store.clone(), provider.clone(), 2);
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        Ok(())
    }

    /// Issue #610 (ASR-021 agent-control-plane-network-interruption): a
    /// create whose retry budget exhausted before ANY dispatch was accepted —
    /// the durable agent command row is still `pending`, proving the create
    /// never executed — must re-drive the create once the interruption
    /// resolves instead of presence-inspecting it (which would terminalize
    /// the absent create as failed). The re-drive converges ACTIVE exactly
    /// once, mirroring the Running-without-identity sweep shape.
    #[tokio::test]
    async fn exhausted_create_with_pending_command_redrives_after_recovery()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("exhausted-pending-redrive", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("agent-1".to_owned());
        provider.set_failure(FailureInjection::Transient)?;
        let operation_id = journal.begin_create("project", &request).await?;
        // Dispatch 1: retryable, budget (2) not yet exhausted -> scheduled.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Retryable
        );
        // Dispatch 2: retryable, budget exhausted -> UnknownOutcome with no
        // provider operation identity.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::UnknownOutcome);
        assert!(operation.provider_operation_id.is_none());
        // The durable command row is still `pending` — exactly the residue a
        // mid-transfer control-channel drop leaves behind: the create was
        // provably never accepted by the agent.
        bind_command(
            store.as_ref(),
            format!("create-command-{operation_id}"),
            operation_id,
            request.o3k_server_id,
            "agent-1",
            "epoch-1",
        )
        .await?;
        // The interruption resolves; the next convergence re-drive must
        // re-dispatch the create (never presence-terminalize it) and converge
        // ACTIVE with exactly one instance.
        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }
    /// dispatch is rejected as retryable until the budget exhausts must also
    /// land in `UnknownOutcome` (never terminal `Failed`), and the lifecycle
    /// convergence re-drive must converge it by presence once the provider is
    /// healthy — the instance is still present, so the delete is re-driven
    /// and the goal converges to DELETED with zero residue.
    #[tokio::test]
    async fn delete_retry_exhaustion_stays_unknown_and_presence_converges()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("delete-retry-exhaustion", 2).await?;
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;
        provider.set_failure(FailureInjection::Transient)?;
        // Dispatch 1: retryable, budget (2) not yet exhausted -> scheduled.
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Retryable
        );
        // Dispatch 2: retryable, budget exhausted -> UnknownOutcome, and the
        // exhausted operation carries no provider operation identity.
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::UnknownOutcome);
        assert_eq!(operation.error_category.as_deref(), Some("retry_exhausted"));
        assert!(operation.provider_operation_id.is_none());
        // The interruption resolves: the delete never executed during the
        // outage, so the instance is still present and the presence-driven
        // re-drive must re-dispatch the delete and converge to DELETED.
        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(provider.instance_count(), 0);
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "DELETED"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_create_records_observed_provider_failure() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-create-failed", 2).await?;
        provider.set_failure(FailureInjection::Timeout)?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider
            .set_operation_state(provider_operation_id, o3k_provider::OperationState::Failed)?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Failed
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Failed
        );
        Ok(())
    }

    /// Genuine unknown-outcome creates converge by observing instance
    /// presence by durable identity: the provider operation carries no
    /// provider resource id, and the presence inspection finds the instance,
    /// so the create finishes without ever re-dispatching the create.
    #[tokio::test]
    async fn unknown_create_converges_when_presence_inspection_finds_instance()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-present", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        provider.set_failure(FailureInjection::None)?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        // Presence observation must never duplicate the create.
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// A presence inspection that provably finds no instance converges the
    /// unknown create to a terminal failure with the resource projected to
    /// error, so clients polling the server stop waiting.
    #[tokio::test]
    async fn unknown_create_converges_to_failed_when_instance_is_absent()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-absent", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let instance_id = provider
            .get_operation(provider_operation_id)
            .await?
            .provider_resource_id
            .ok_or(ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The instance provably does not exist: the create never took effect.
        provider.remove_instance(&instance_id)?;
        provider.set_failure(FailureInjection::None)?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Failed
        );
        assert_eq!(
            store
                .get_operation(operation_id)
                .await?
                .error_category
                .as_deref(),
            Some("not_found")
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ERROR"
        );
        Ok(())
    }

    /// A presence inspection whose own outcome is unknown (dispatch timeout,
    /// transport loss) preserves the unknown-outcome semantics: the create is
    /// never marked failed on inspection transport loss and stays re-observable.
    #[tokio::test]
    async fn unknown_create_remains_unknown_when_presence_inspection_is_unknown()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-inspect-unknown", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The inspect dispatch itself remains unknown (Timeout still active).
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        assert_ne!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ERROR"
        );
        Ok(())
    }

    /// When the agent completed the presence inspection while the durable
    /// operation record was still in-flight, the terminal agent command
    /// record is the durable evidence and must converge without a second
    /// dispatch (the race where the agent's terminal update overtakes the
    /// reconciler's in-flight write).
    #[tokio::test]
    async fn unknown_create_converges_from_terminal_agent_command_without_redispatch()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-command", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let instance_id = provider
            .get_operation(provider_operation_id)
            .await?
            .provider_resource_id
            .ok_or(ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;

        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{operation_id}").as_bytes(),
        );
        store
            .insert_operation(&OperationRecord {
                id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                kind: "inspect".to_owned(),
                state: OperationState::Running,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: "inspect-command-1".to_owned(),
                idempotency_key: format!("o3k-inspect-create-{operation_id}"),
                operation_id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                payload_fingerprint_sha256: "f".repeat(64),
                payload: Vec::new(),
                state: AgentCommandState::Succeeded,
                accepted_sequence: 1,
                last_sequence: 2,
                provider_operation_id: Some(inspect_operation_id.to_string()),
                provider_resource_id: Some(instance_id.clone()),
            })
            .await?;
        store
            .attach_provider_reference(&ProviderReference {
                resource_id: request.o3k_server_id,
                provider_name: "compute-agent".to_owned(),
                provider_resource_id: instance_id,
            })
            .await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        // The terminal agent command converged the create without dispatching
        // a second inspection.
        assert_eq!(provider.inspect_dispatch_count(), 0);
        Ok(())
    }

    /// A stored terminal `Failed`/`not_found` inspection record (the crash
    /// window between the inspection converging and the create converging)
    /// must converge the create to absence without any dispatch.
    #[tokio::test]
    async fn unknown_create_converges_from_stored_failed_inspection_without_dispatch()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-stored-failed", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let instance_id = provider
            .get_operation(provider_operation_id)
            .await?
            .provider_resource_id
            .ok_or(ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The instance provably does not exist: the create never took effect.
        provider.remove_instance(&instance_id)?;
        provider.set_failure(FailureInjection::None)?;

        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{operation_id}").as_bytes(),
        );
        store
            .insert_operation(&OperationRecord {
                id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                kind: "inspect".to_owned(),
                state: OperationState::Failed,
                provider_operation_id: Some(inspect_operation_id.to_string()),
                error_category: Some("not_found".to_owned()),
                error_message: Some("presence inspection: instance is absent".to_owned()),
            })
            .await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Failed
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ERROR"
        );
        assert_eq!(provider.inspect_dispatch_count(), 0);
        Ok(())
    }

    /// The race mirror of the succeeded-command test: a terminal `Failed`
    /// agent command for the in-flight inspection proves absence (the agent
    /// classifies only absent domains as terminal inspect failures) and must
    /// converge the create without a second dispatch.
    #[tokio::test]
    async fn unknown_create_converges_to_absent_from_terminal_failed_agent_command()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-command-failed", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let instance_id = provider
            .get_operation(provider_operation_id)
            .await?
            .provider_resource_id
            .ok_or(ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The instance provably does not exist: the create never took effect.
        provider.remove_instance(&instance_id)?;
        provider.set_failure(FailureInjection::None)?;

        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{operation_id}").as_bytes(),
        );
        store
            .insert_operation(&OperationRecord {
                id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                kind: "inspect".to_owned(),
                state: OperationState::Running,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;
        store
            .insert_agent_command(&AgentCommandRecord {
                command_id: "inspect-command-failed".to_owned(),
                idempotency_key: format!("o3k-inspect-create-{operation_id}"),
                operation_id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                payload_fingerprint_sha256: "f".repeat(64),
                payload: Vec::new(),
                state: AgentCommandState::Failed,
                accepted_sequence: 1,
                last_sequence: 2,
                provider_operation_id: Some(inspect_operation_id.to_string()),
                provider_resource_id: None,
            })
            .await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Failed
        );
        assert_eq!(
            store
                .get_operation(operation_id)
                .await?
                .error_category
                .as_deref(),
            Some("not_found")
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ERROR"
        );
        assert_eq!(provider.inspect_dispatch_count(), 0);
        Ok(())
    }
    #[tokio::test]
    async fn unknown_create_redispatches_pending_inspection_record() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-pending", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The instance exists; only the inspection record is stuck in Pending.
        provider.set_failure(FailureInjection::None)?;

        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{operation_id}").as_bytes(),
        );
        store
            .insert_operation(&OperationRecord {
                id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                kind: "inspect".to_owned(),
                state: OperationState::Pending,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        // Re-observation must never duplicate the create.
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// An inspection the agent already accepted (`Running`, no terminal
    /// evidence yet) is never re-dispatched: the agent journal guarantees
    /// delivery of the terminal update, so the create stays unknown until
    /// that update arrives instead of duplicating the inspection.
    #[tokio::test]
    async fn unknown_create_does_not_redispatch_accepted_inspection_record()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-running", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        provider.set_failure(FailureInjection::None)?;

        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{operation_id}").as_bytes(),
        );
        store
            .insert_operation(&OperationRecord {
                id: inspect_operation_id,
                resource_id: request.o3k_server_id,
                kind: "inspect".to_owned(),
                state: OperationState::Running,
                provider_operation_id: None,
                error_category: None,
                error_message: None,
            })
            .await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        // The instance was never created and the accepted inspection was not
        // duplicated (no dispatch happened at all).
        assert_eq!(provider.instance_count(), 1);
        assert_eq!(provider.inspect_dispatch_count(), 0);
        Ok(())
    }

    /// When a provider reference was recorded meanwhile (the lost-update
    /// window where the agent completed the create), the presence inspection
    /// passes the known provider identity instead of an empty id.
    #[tokio::test]
    async fn unknown_create_uses_known_provider_reference_for_presence_inspection()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-reference", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        let instance_id = provider
            .get_operation(provider_operation_id)
            .await?
            .provider_resource_id
            .ok_or(ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        provider.set_failure(FailureInjection::None)?;
        store
            .attach_provider_reference(&ProviderReference {
                resource_id: request.o3k_server_id,
                provider_name: "compute-agent".to_owned(),
                provider_resource_id: instance_id.clone(),
            })
            .await?;

        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.instance_count(), 1);
        // The inspection was dispatched exactly once and carried the known
        // provider identity recorded in the reference, not an empty id.
        assert_eq!(provider.inspect_dispatch_count(), 1);
        assert_eq!(
            provider.last_inspect_provider_instance_id().as_deref(),
            Some(instance_id.as_str())
        );
        Ok(())
    }

    /// A stored `UnknownOutcome` inspection record (the outcome of a previous
    /// trigger whose dispatch was lost) stays re-observable: the next trigger
    /// re-dispatches the read-only inspection and converges.
    #[tokio::test]
    async fn unknown_create_redispatches_stored_unknown_inspection() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("unknown-presence-stored-unknown", 2).await?;
        let mut request = request();
        request.placement_provider_id = Some("node-a".to_owned());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        // The first presence observation is itself lost (Timeout still
        // active), leaving a stored UnknownOutcome inspection record.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(provider.inspect_dispatch_count(), 1);
        let inspect_operation_id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("o3k:inspect-create:{operation_id}").as_bytes(),
        );
        assert_eq!(
            store.get_operation(inspect_operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        // The next trigger re-observes: the read-only inspection is
        // re-dispatched and the instance is found.
        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.inspect_dispatch_count(), 2);
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// A create that never recorded an execution agent cannot be observed by
    /// durable identity: the unknown outcome is preserved (never guessed).
    #[tokio::test]
    async fn unknown_create_without_agent_preserves_unknown_outcome() -> Result<(), ReconcileError>
    {
        let (journal, store, provider) = journal("unknown-presence-no-agent", 2).await?;
        let request = request();
        assert!(request.placement_provider_id.is_none());
        provider.set_failure(FailureInjection::Timeout)?;
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider.set_operation_provider_resource_id(provider_operation_id, None)?;
        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        assert_eq!(provider.inspect_dispatch_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_delete_is_observed_without_repeating_mutation() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("delete-unknown", 2).await?;
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        provider.set_failure(FailureInjection::Timeout)?;
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "DELETED"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stale_accepted_delete_gets_one_fresh_idempotent_redrive() -> Result<(), ReconcileError>
    {
        let (journal, store, provider) = journal("delete-stale-accepted", 2).await?;
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;
        provider.set_failure(FailureInjection::StaleAccepted)?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Running
        );
        let stale_provider_operation: Uuid = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        store
            .update_operation(
                operation_id,
                OperationState::UnknownOutcome,
                Some(&stale_provider_operation.to_string()),
                Some("unknown_outcome"),
                None,
            )
            .await?;
        provider.set_failure(FailureInjection::None)?;

        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "DELETED"
        );
        assert_eq!(provider.instance_count(), 0);
        Ok(())
    }

    /// Models the REAL `AgentComputeProvider` delete contract for #575: the
    /// dispatch is asynchronous — `delete_instance` returns an Accepted
    /// operation immediately and the agent-side completion is observed only
    /// later through `get_operation`, never inside the dispatch call (the
    /// flaw that hid the bug in `FakeComputeProvider::delete_instance`, which
    /// returns Succeeded synchronously in the no-injection case). The FIRST
    /// delete dispatch for the instance is the #575 stale command whose
    /// execution was lost in the libvirtd restart: it stays Accepted forever
    /// and counts as zero effective executions. Any later dispatch (the
    /// deterministic redrive command) executes once and completes on its
    /// second `get_operation` poll, mirroring the agent event stream
    /// terminalizing the adapter's volatile projection between sweep ticks.
    /// Re-dispatching an already-recorded operation id reuses the recorded
    /// operation without executing again, mirroring
    /// `AgentComputeProvider::reuse_recorded_command` and the agent journal's
    /// command-identity replay.
    #[derive(Clone)]
    struct AsyncAgentDeleteProvider {
        inner: FakeComputeProvider,
        state: Arc<Mutex<AsyncAgentDeleteState>>,
        store: Option<Arc<dyn o3k_store::ComputeRepository>>,
    }

    struct AsyncAgentDeleteState {
        /// Provider operations keyed by the operation id the reconciler
        /// passed to `delete_instance` (the agent adapter keys its volatile
        /// operation projection by the command's operation id).
        operations: HashMap<Uuid, o3k_provider::Operation>,
        /// The first (stale) delete dispatch's operation id; its execution
        /// was lost and it never completes.
        original_operation_id: Option<Uuid>,
        /// The O3K server id captured at create time (the command ledger's
        /// `resource_id` is the server id, never the provider domain name).
        resource_id: Option<Uuid>,
        /// The durable state the stale command projects through
        /// `get_operation` — `Accepted` models the lost-update shape and
        /// `UnknownOutcome` models the rejected-observation shape (the
        /// exact #575 durable row).
        stale_original_state: o3k_provider::OperationState,
        /// Provider instance id per dispatched operation, used to remove the
        /// instance when that operation's execution completes.
        instance_by_operation: HashMap<Uuid, String>,
        /// `get_operation` poll counts per operation.
        polls: HashMap<Uuid, usize>,
        /// Delete commands whose execution actually ran on the "agent".
        delete_executions: usize,
    }

    impl AsyncAgentDeleteProvider {
        fn with_store(
            store: Arc<dyn o3k_store::ComputeRepository>,
            stale_original_state: o3k_provider::OperationState,
        ) -> Self {
            Self {
                inner: FakeComputeProvider::new(),
                state: Arc::new(Mutex::new(AsyncAgentDeleteState {
                    stale_original_state,
                    operations: HashMap::new(),
                    original_operation_id: None,
                    resource_id: None,
                    instance_by_operation: HashMap::new(),
                    polls: HashMap::new(),
                    delete_executions: 0,
                })),
                store: Some(store),
            }
        }

        fn delete_executions(&self) -> usize {
            self.state
                .lock()
                .map(|state| state.delete_executions)
                .unwrap_or_default()
        }

        fn instance_count(&self) -> usize {
            self.inner.instance_count()
        }
    }

    #[async_trait::async_trait]
    impl ComputeProvider for AsyncAgentDeleteProvider {
        async fn capabilities(&self) -> Result<o3k_provider::Capabilities, ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, ProviderError> {
            self.state
                .lock()
                .map_err(|_| ProviderError::Storage)?
                .resource_id = Some(request.o3k_server_id);
            self.inner.create_instance(request).await
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, ProviderError> {
            self.inner.get_instance(provider_instance_id).await
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, ProviderError> {
            {
                let state = self.state.lock().map_err(|_| ProviderError::Storage)?;
                if let Some(existing) = state.operations.get(&request.operation_id) {
                    // Idempotent re-dispatch of the same command identity:
                    // reuse the recorded operation without a second execution.
                    return Ok(existing.clone());
                }
            }
            // Mirror `AgentComputeProvider::dispatch_recorded`: persist the
            // durable command row BEFORE dispatch. The ledger's foreign key
            // on `operation_id -> operations(id)` is the #575 real-host
            // constraint: a fresh command identity without a durable
            // operation row fails the insert and the dispatch reports
            // Conflict (run local-5752), so the reconciler must create the
            // re-drive operation row first.
            if let Some(store) = &self.store {
                let resource_id = self
                    .state
                    .lock()
                    .map_err(|_| ProviderError::Storage)?
                    .resource_id
                    .ok_or(ProviderError::InvalidRequest)?;
                let record = o3k_store::AgentCommandRecord {
                    command_id: format!("async-agent-delete-{}", request.operation_id),
                    idempotency_key: request.idempotency_key.clone(),
                    operation_id: request.operation_id,
                    resource_id,
                    agent_id: "node-a".to_owned(),
                    agent_epoch: "epoch-1".to_owned(),
                    payload_fingerprint_sha256: "0".repeat(64),
                    payload: Vec::new(),
                    state: o3k_store::AgentCommandState::Pending,
                    accepted_sequence: 0,
                    last_sequence: 0,
                    provider_operation_id: Some(request.operation_id.to_string()),
                    provider_resource_id: None,
                };
                if store.insert_agent_command(&record).await.is_err() {
                    // The insert failed: either the foreign key rejected a
                    // command identity without an operation row, or a
                    // concurrent dispatch inserted first. Only the former is
                    // a conflict — the latter adopts the surviving row.
                    let adopted = self
                        .state
                        .lock()
                        .map_err(|_| ProviderError::Storage)?
                        .operations
                        .contains_key(&request.operation_id);
                    if !adopted {
                        return Err(ProviderError::Conflict);
                    }
                }
            }
            let mut state = self.state.lock().map_err(|_| ProviderError::Storage)?;
            let operation_id = request.operation_id;
            if let Some(existing) = state.operations.get(&operation_id) {
                return Ok(existing.clone());
            }
            let stale = state.original_operation_id.is_none();
            if stale {
                state.original_operation_id = Some(operation_id);
            } else {
                state.delete_executions += 1;
                state
                    .instance_by_operation
                    .insert(operation_id, request.provider_instance_id.clone());
            }
            let operation = o3k_provider::Operation {
                provider_operation_id: operation_id,
                o3k_operation_id: operation_id,
                state: o3k_provider::OperationState::Accepted,
                error_category: None,
                provider_resource_id: None,
            };
            state.operations.insert(operation_id, operation.clone());
            Ok(operation)
        }

        async fn action_instance(
            &self,
            provider_instance_id: &str,
            action: o3k_provider::InstanceAction,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, ProviderError> {
            self.inner
                .action_instance(provider_instance_id, action, operation_id, idempotency_key)
                .await
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, ProviderError> {
            let (operation, instance_to_remove) = {
                let mut state = self.state.lock().map_err(|_| ProviderError::Storage)?;
                let Some(operation) = state.operations.get(&provider_operation_id).cloned() else {
                    return Err(ProviderError::NotFound);
                };
                let polls = state.polls.entry(provider_operation_id).or_insert(0);
                *polls += 1;
                let poll_count = *polls;
                if state.original_operation_id == Some(provider_operation_id) {
                    // The stale command's durable projection: the control
                    // plane projected the operation's own durable state
                    // (`UnknownOutcome` for the rejected-observation shape,
                    // `Accepted` for the lost-update shape), never the
                    // in-flight `Accepted` from the original dispatch.
                    let mut stale = operation;
                    stale.state = state.stale_original_state;
                    (stale, None)
                } else if operation.state != o3k_provider::OperationState::Accepted
                    || poll_count < 2
                {
                    (operation, None)
                } else {
                    // The simulated agent execution completed: the terminal
                    // state and the instance removal are observed now, exactly
                    // as the real agent's terminal events arrive between
                    // sweep ticks.
                    let mut completed = operation.clone();
                    completed.state = o3k_provider::OperationState::Succeeded;
                    state
                        .operations
                        .insert(provider_operation_id, completed.clone());
                    (
                        completed,
                        state.instance_by_operation.remove(&provider_operation_id),
                    )
                }
            };
            if let Some(provider_instance_id) = instance_to_remove {
                let _ = self.inner.remove_instance(&provider_instance_id);
            }
            Ok(operation)
        }
    }

    /// Reproduces the #575 durable state and drives convergence the way the
    /// REAL system does — the `drive_all_lifecycle_convergence` sweep gate
    /// (crates/o3k-compute/src/lib.rs ~805-811) — against a provider fake with
    /// the REAL agent's asynchronous delete contract. The first dispatch is
    /// Accepted with the original provider operation id; the #575 condition
    /// is simulated exactly like the existing regression test (the agent's
    /// non-Succeeded observation was rejected, so the durable operation is
    /// UnknownOutcome with the stale id); then the sweep-gated loop must
    /// redrive the delete with the deterministic fresh command identity and
    /// POLL it to terminal. On current main the redrive arm stores Running
    /// with the redrive id, the sweep gate then skips the operation forever
    /// ("in flight: the agent event stream terminalizes it"), the redrive's
    /// agent evidence is rejected (no operation row carries the redrive id),
    /// and the delete never converges — the resource stays ACTIVE and the
    /// allocation/config-drive media stay held.
    #[tokio::test]
    async fn stale_accepted_delete_converges_under_async_agent_contract()
    -> Result<(), ReconcileError> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-delete-async-agent-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
        let provider = Arc::new(AsyncAgentDeleteProvider::with_store(
            store.clone(),
            o3k_provider::OperationState::Accepted,
        ));
        let journal = OperationJournal::new(store.clone(), provider.clone(), 2);

        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;

        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;
        // First dispatch, exactly like the real agent-backed path: the
        // command is accepted asynchronously and the operation is stored
        // Running with the ORIGINAL provider operation id (the agent adapter
        // keys its operation projection by the command's operation id).
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Running
        );
        let stale_provider_operation: Uuid = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        assert_eq!(stale_provider_operation, operation_id);
        // Issue #575 residue: the agent's non-Succeeded observation was
        // rejected by `apply_agent_observation`, leaving the durable
        // operation UnknownOutcome with the stale provider operation id
        // (exactly the existing regression test's shape).
        store
            .update_operation(
                operation_id,
                OperationState::UnknownOutcome,
                Some(&stale_provider_operation.to_string()),
                Some("unknown_outcome"),
                None,
            )
            .await?;

        // Drive convergence EXACTLY like the real sweep: only Pending /
        // UnknownOutcome / Retryable / Running-without-provider-operation-id
        // are re-driven; Running WITH the identity is skipped as in-flight.
        for _ in 0..20 {
            let operation = store.get_operation(operation_id).await?;
            if matches!(
                operation.state,
                OperationState::Succeeded | OperationState::Failed
            ) {
                break;
            }
            let re_drive = matches!(
                operation.state,
                OperationState::Pending
                    | OperationState::UnknownOutcome
                    | OperationState::Retryable
            ) || (operation.state == OperationState::Running
                && operation.provider_operation_id.is_none());
            if !re_drive {
                continue;
            }
            journal.reconcile_lifecycle_once(operation_id).await?;
        }

        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "DELETED"
        );
        assert_eq!(provider.instance_count(), 0);
        // The lost original command never executed; the redrive executed
        // exactly once. Any repeated gate pass re-dispatches the SAME
        // deterministic redrive command identity, which the provider reuses
        // without a second execution — so the count can never exceed one.
        assert_eq!(provider.delete_executions(), 1);
        Ok(())
    }

    /// The exact #575 durable shape (V1): the stale command's durable
    /// projection is `UnknownOutcome` — the control plane rejected the
    /// agent's non-Succeeded observation, the operation row carries the
    /// stale provider operation id, and the agent's journal only replays the
    /// recorded unknown outcome. `observe_lifecycle`'s UnknownOutcome arm
    /// must therefore re-drive the delete when the instance is still present
    /// (previously it returned UnknownOutcome forever and the redrive arm was
    /// unreachable on the real agent-backed path, because the provider
    /// adapter projected the operation's own durable state).
    #[tokio::test]
    async fn stale_unknown_outcome_delete_redrives_and_converges() -> Result<(), ReconcileError> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-delete-async-unknown-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
        let provider = Arc::new(AsyncAgentDeleteProvider::with_store(
            store.clone(),
            o3k_provider::OperationState::UnknownOutcome,
        ));
        let journal = OperationJournal::new(store.clone(), provider.clone(), 2);

        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;

        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Running
        );
        let stale_provider_operation: Uuid = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        store
            .update_operation(
                operation_id,
                OperationState::UnknownOutcome,
                Some(&stale_provider_operation.to_string()),
                Some("unknown_outcome"),
                None,
            )
            .await?;

        for _ in 0..20 {
            let operation = store.get_operation(operation_id).await?;
            if matches!(
                operation.state,
                OperationState::Succeeded | OperationState::Failed
            ) {
                break;
            }
            let re_drive = matches!(
                operation.state,
                OperationState::Pending
                    | OperationState::UnknownOutcome
                    | OperationState::Retryable
            ) || (operation.state == OperationState::Running
                && operation.provider_operation_id.is_none());
            if !re_drive {
                continue;
            }
            journal.reconcile_lifecycle_once(operation_id).await?;
        }

        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "DELETED"
        );
        assert_eq!(provider.instance_count(), 0);
        assert_eq!(provider.delete_executions(), 1);
        Ok(())
    }

    fn failed_update(
        operation_id: &str,
        resource_id: &str,
        agent_id: &str,
        agent_epoch: &str,
        redacted_message: &str,
    ) -> Result<AgentOperationUpdate, ReconcileError> {
        Ok(AgentOperationUpdate {
            agent_id: agent_id.to_owned(),
            agent_epoch: agent_epoch.to_owned(),
            operation_sequence: 1,
            operation_id: Uuid::parse_str(operation_id)
                .map_err(|_| ReconcileError::InvalidIntent)?,
            resource_id: Uuid::parse_str(resource_id).map_err(|_| ReconcileError::InvalidIntent)?,
            state: AgentOperationState::Failed,
            error_category: Some(AgentErrorCategory::Terminal),
            redacted_message: Some(redacted_message.to_owned()),
            provider_resource_id: None,
        })
    }

    #[tokio::test]
    async fn unknown_action_is_observed_before_finishing_converged_state()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("action-unknown", 2).await?;
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        provider.set_failure(FailureInjection::Timeout)?;
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Stop)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );

        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?
            .parse()
            .map_err(|_| ReconcileError::InvalidIntent)?;
        provider
            .set_operation_state(provider_operation_id, o3k_provider::OperationState::Running)?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Running
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running
        );
        provider.set_operation_state(
            provider_operation_id,
            o3k_provider::OperationState::Succeeded,
        )?;

        provider.set_failure(FailureInjection::None)?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "SHUTOFF"
        );
        Ok(())
    }

    /// A second driver reaching `finish` after the first driver already
    /// converged the same operation (the idempotent-retry show path re-driving
    /// a create whose synchronous pass completed in between) must short-circuit
    /// on the first-writer outcome: no re-attach, no resource churn, no error.
    #[tokio::test]
    async fn finish_is_idempotent_when_operation_already_succeeded() -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("finish-idempotent", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        let provider_operation_id = store
            .get_operation(operation_id)
            .await?
            .provider_operation_id
            .ok_or(ReconcileError::InvalidIntent)?;
        let resource = store.get_resource(request.o3k_server_id).await?;
        let provider_resource_id = format!("fake-{}", request.o3k_server_id);
        let generation_before = resource.generation;
        assert_eq!(
            journal
                .finish(
                    operation_id,
                    resource.clone(),
                    provider_operation_id.clone(),
                    Some(provider_resource_id.clone()),
                )
                .await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_resource(request.o3k_server_id).await?.generation,
            generation_before,
            "a converged second finish must not touch the resource"
        );
        assert_eq!(
            store
                .get_provider_reference(request.o3k_server_id, "compute")
                .await?
                .provider_resource_id,
            provider_resource_id,
            "the first-writer reference must be unchanged"
        );
        Ok(())
    }

    /// A second driver that reaches `finish` while the first driver's attach
    /// already landed (operation still non-terminal) must treat the matching
    /// provider reference as idempotent and converge the projection.
    #[tokio::test]
    async fn finish_converges_when_provider_reference_already_attached()
    -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("finish-attached", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        store
            .update_operation(operation_id, OperationState::Running, None, None, None)
            .await?;
        let provider_resource_id = format!("fake-{}", request.o3k_server_id);
        store
            .attach_provider_reference(&ProviderReference {
                resource_id: request.o3k_server_id,
                provider_name: "compute".to_owned(),
                provider_resource_id: provider_resource_id.clone(),
            })
            .await?;
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(
            journal
                .finish(
                    operation_id,
                    resource,
                    "provider-operation-1".to_owned(),
                    Some(provider_resource_id),
                )
                .await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        Ok(())
    }

    /// A provider reference carrying a DIFFERENT provider resource id is a
    /// genuine identity drift, never a converged duplicate: the second driver
    /// must fail closed instead of overwriting the attached identity.
    #[tokio::test]
    async fn finish_rejects_provider_reference_identity_drift() -> Result<(), ReconcileError> {
        let (journal, store, _) = journal("finish-drift", 2).await?;
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        store
            .update_operation(operation_id, OperationState::Running, None, None, None)
            .await?;
        store
            .attach_provider_reference(&ProviderReference {
                resource_id: request.o3k_server_id,
                provider_name: "compute".to_owned(),
                provider_resource_id: "foreign-domain".to_owned(),
            })
            .await?;
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert!(matches!(
            journal
                .finish(
                    operation_id,
                    resource,
                    "provider-operation-1".to_owned(),
                    Some(format!("fake-{}", request.o3k_server_id)),
                )
                .await,
            Err(ReconcileError::Store(
                StoreError::ProviderReferenceAlreadyExists
            ))
        ));
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::Running,
            "a drifted finish must not project success"
        );
        assert_eq!(
            store
                .get_provider_reference(request.o3k_server_id, "compute")
                .await?
                .provider_resource_id,
            "foreign-domain",
            "the attached identity must be preserved"
        );
        Ok(())
    }

    /// Wraps the stateful fake provider with the agent-registry lifecycle of
    /// the issue-87 empty-registry defect: while the agent is in reconnect
    /// backoff no node is registered, so `create_instance` reports NotFound —
    /// the command can provably never be delivered — and after `register()`
    /// (the agent re-registering on a later sweep tick) the fake behaves
    /// normally.
    struct NotFoundUntilRegisteredProvider {
        inner: FakeComputeProvider,
        registered: std::sync::atomic::AtomicBool,
    }

    impl NotFoundUntilRegisteredProvider {
        fn new() -> Self {
            Self {
                inner: FakeComputeProvider::new(),
                registered: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn register(&self) {
            self.registered
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn instance_count(&self) -> usize {
            self.inner.instance_count()
        }
    }

    #[async_trait::async_trait]
    impl o3k_provider::ComputeProvider for NotFoundUntilRegisteredProvider {
        async fn capabilities(
            &self,
        ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            if !self.registered.load(std::sync::atomic::Ordering::SeqCst) {
                // No agent is registered: `selected_agent` fails before any
                // dispatch, so the create command was never delivered.
                return Err(o3k_provider::ProviderError::NotFound);
            }
            self.inner.create_instance(request).await
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
            self.inner.get_instance(provider_instance_id).await
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.delete_instance(request).await
        }

        async fn action_instance(
            &self,
            provider_instance_id: &str,
            action: o3k_provider::InstanceAction,
            operation_id: Uuid,
            idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner
                .action_instance(provider_instance_id, action, operation_id, idempotency_key)
                .await
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.get_operation(provider_operation_id).await
        }
    }

    /// The empty-registry dispatch (issue #87): a create driven while no
    /// agent is registered — a preserved agent still in reconnect backoff —
    /// must NOT become terminal Failed. The command was provably never
    /// delivered, so the operation stays `Running` without a provider
    /// operation identity, the exact residue shape the create-convergence
    /// sweep re-drives; once an agent registers on a later sweep tick the
    /// create re-dispatches and converges to ACTIVE. The retry budget is
    /// never consumed by the empty-registry condition (no `retry_or_fail`).
    #[tokio::test]
    async fn create_dispatch_against_empty_registry_is_redriven_not_terminal()
    -> Result<(), ReconcileError> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-empty-registry-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
        let provider = Arc::new(NotFoundUntilRegisteredProvider::new());
        let journal = OperationJournal::new(store.clone(), provider.clone(), 2);
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;

        // First sweep tick: the agent is not registered yet (reconnect
        // backoff), so the create cannot be delivered to any agent.
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Running
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::Running);
        assert!(
            operation.provider_operation_id.is_none(),
            "an undelivered create must not carry a provider operation identity"
        );

        // A later sweep tick after the agent registered re-dispatches the
        // create and converges: the empty-registry condition must never
        // strand the server in a terminal error.
        provider.register();
        assert_eq!(
            journal.reconcile_once(operation_id).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert_eq!(provider.instance_count(), 1);
        Ok(())
    }

    /// Wraps the stateful fake provider so every lifecycle action is
    /// rejected as an invalid request before any provider mutation, exactly
    /// what the agent provider reports for a genuinely invalid command
    /// (bad payload, unknown action). Pins the reconciler's terminalization
    /// of a real validation rejection: the issue-87 transport-stall
    /// reclassification must never weaken real validation.
    struct RejectingActionProvider {
        inner: FakeComputeProvider,
    }

    impl RejectingActionProvider {
        fn new(inner: FakeComputeProvider) -> Self {
            Self { inner }
        }
    }

    #[async_trait::async_trait]
    impl o3k_provider::ComputeProvider for RejectingActionProvider {
        async fn capabilities(
            &self,
        ) -> Result<o3k_provider::Capabilities, o3k_provider::ProviderError> {
            self.inner.capabilities().await
        }

        async fn create_instance(
            &self,
            request: CreateInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.create_instance(request).await
        }

        async fn get_instance(
            &self,
            provider_instance_id: &str,
        ) -> Result<o3k_provider::Instance, o3k_provider::ProviderError> {
            self.inner.get_instance(provider_instance_id).await
        }

        async fn delete_instance(
            &self,
            request: o3k_provider::DeleteInstanceRequest,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.delete_instance(request).await
        }

        async fn action_instance(
            &self,
            _provider_instance_id: &str,
            _action: o3k_provider::InstanceAction,
            _operation_id: Uuid,
            _idempotency_key: &str,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            Err(o3k_provider::ProviderError::InvalidRequest)
        }

        async fn get_operation(
            &self,
            provider_operation_id: Uuid,
        ) -> Result<o3k_provider::Operation, o3k_provider::ProviderError> {
            self.inner.get_operation(provider_operation_id).await
        }
    }

    /// Issue #87 B2 invariant: a lifecycle dispatch rejected as
    /// `InvalidRequest` by the provider — a genuinely invalid command — must
    /// STILL terminalize as `Failed` with `invalid_request`, wiping no
    /// recovery path behind it. The transport-stall fix reclassifies the
    /// stall at the provider boundary; it must not turn real validation
    /// rejections into unknown outcomes.
    #[tokio::test]
    async fn rejected_lifecycle_action_still_terminalizes_as_invalid_request()
    -> Result<(), ReconcileError> {
        let (_, store, inner) = journal("rejected-action", 2).await?;
        let provider = Arc::new(RejectingActionProvider::new(inner.as_ref().clone()));
        let journal = OperationJournal::new(store.clone(), provider.clone(), 2);
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Reboot)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Failed
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::Failed);
        assert_eq!(
            operation.error_category.as_deref(),
            Some("invalid_request"),
            "a genuine validation rejection must keep its classified category"
        );
        assert_eq!(
            operation.error_message.as_deref(),
            Some("provider rejected the request")
        );
        assert!(
            operation.provider_operation_id.is_none(),
            "a rejected request never dispatches, so no provider identity exists"
        );
        // The resource stays ACTIVE: the rejected reboot never mutated it.
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "ACTIVE"
        );
        Ok(())
    }

    /// Issue #87 B2: a lifecycle operation already in `UnknownOutcome` (the
    /// state the transport-stall fix now produces) must ADOPT the agent's
    /// re-delivered terminal observation instead of staying stuck: when the
    /// stalled stream is restored and the agent replays the terminal
    /// observation it produced during the hold, `apply_agent_observation`
    /// promotes the operation to `Succeeded` and projects the resource
    /// ACTIVE — the durable inconsistency (failed operation + succeeded
    /// agent command + ACTIVE resource) never forms.
    #[tokio::test]
    async fn unknown_lifecycle_adopts_late_terminal_observation() -> Result<(), ReconcileError> {
        let (journal, store, provider) = journal("adopt-late-observation", 2).await?;
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        provider.set_failure(FailureInjection::Timeout)?;
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Reboot)
            .await?;
        bind_observation_command(&store, operation_id, resource.id, "agent-1", "epoch-1").await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::UnknownOutcome
        );
        assert_eq!(
            store.get_operation(operation_id).await?.state,
            OperationState::UnknownOutcome
        );
        provider.set_failure(FailureInjection::None)?;
        // The stream is restored; the agent re-delivers the terminal
        // observation it already produced during the hold (the reboot
        // executed: state Running/ACTIVE).
        journal
            .apply_agent_observation(&AgentObservation {
                agent_id: "agent-1".to_owned(),
                agent_epoch: "epoch-1".to_owned(),
                resource_id: resource.id,
                provider_resource_id: resource.provider_id.clone(),
                state: o3k_provider::InstanceState::Running,
                operation_id,
                operation_state: AgentOperationState::Succeeded,
                observation_sequence: 1,
                observed_at_unix_ms: 1,
                redacted_message: Some("rebooted".to_owned()),
                console_log_bytes: Vec::new(),
                console_log_offset: 0,
                console_log_complete: false,
                console_log_truncated: false,
                block_device: None,
            })
            .await?;
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(
            operation.state,
            OperationState::Succeeded,
            "the re-delivered terminal observation must be adopted by the unknown lifecycle"
        );
        assert!(
            operation.provider_operation_id.is_some(),
            "the adopted operation keeps its provider operation identity"
        );
        assert_eq!(
            store.get_resource(resource.id).await?.observed_state,
            "ACTIVE"
        );
        Ok(())
    }

    type MeteringObservations = Vec<(String, String, String, String)>;

    /// Recording observer that captures every projected lifecycle state in
    /// order, so tests can assert the exact sequence the authority saw. It can
    /// be toggled to fail, so tests can prove a lost projection is repaired.
    #[derive(Clone, Default)]
    struct RecordingMeteringObserver {
        observed: Arc<Mutex<MeteringObservations>>,
        failing: Arc<std::sync::atomic::AtomicBool>,
    }

    impl RecordingMeteringObserver {
        fn set_failing(&self, failing: bool) {
            self.failing
                .store(failing, std::sync::atomic::Ordering::SeqCst);
        }

        fn observations(&self) -> MeteringObservations {
            match self.observed.lock() {
                Ok(entries) => entries.clone(),
                Err(_) => Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl o3k_kernel::LifecycleMeteringObserver for RecordingMeteringObserver {
        async fn observe_resource_state(
            &self,
            kind: &str,
            project_id: &str,
            resource_id: &str,
            observed_state: &str,
        ) -> Result<(), o3k_kernel::KernelError> {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(o3k_kernel::KernelError::MeteringUnavailable(
                    "observer failing".to_owned(),
                ));
            }
            if let Ok(mut observed) = self.observed.lock() {
                observed.push((
                    kind.to_owned(),
                    project_id.to_owned(),
                    resource_id.to_owned(),
                    observed_state.to_owned(),
                ));
            }
            Ok(())
        }

        async fn observe_allocation(
            &self,
            _meter_key: &str,
            _project_id: &str,
            _resource_id: &str,
            _quantity: u64,
            _consuming: bool,
        ) -> Result<(), o3k_kernel::KernelError> {
            Ok(())
        }
    }

    struct FailingMeteringObserver;

    #[async_trait::async_trait]
    impl o3k_kernel::LifecycleMeteringObserver for FailingMeteringObserver {
        async fn observe_resource_state(
            &self,
            _kind: &str,
            _project_id: &str,
            _resource_id: &str,
            _observed_state: &str,
        ) -> Result<(), o3k_kernel::KernelError> {
            Err(o3k_kernel::KernelError::MeteringUnavailable(
                "observer down".to_owned(),
            ))
        }

        async fn observe_allocation(
            &self,
            _meter_key: &str,
            _project_id: &str,
            _resource_id: &str,
            _quantity: u64,
            _consuming: bool,
        ) -> Result<(), o3k_kernel::KernelError> {
            Ok(())
        }
    }

    /// Durable lifecycle projections must reach metering authority in the
    /// order the resource state actually changes, and replaying a converged
    /// drive must not project a second distinct state change.
    #[tokio::test]
    async fn metering_observer_receives_lifecycle_projection_sequence() -> Result<(), ReconcileError>
    {
        let observer = RecordingMeteringObserver::default();
        let (journal, store, _provider) = journal("metering-lifecycle", 2).await?;
        let journal = journal.with_metering_observer(Arc::new(observer.clone()));

        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        let delete_operation = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, delete_operation, LifecycleAction::Delete)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(delete_operation).await?,
            OperationState::Succeeded
        );

        let projected = match observer.observed.lock() {
            Ok(entries) => entries.clone(),
            Err(_) => Vec::new(),
        };
        let states: Vec<&str> = projected.iter().map(|entry| entry.3.as_str()).collect();
        assert_eq!(states, vec!["ACTIVE", "DELETED"]);
        for (kind, project_id, resource_id, _) in &projected {
            assert_eq!(kind, "compute_instance");
            assert_eq!(project_id, "project");
            assert_eq!(resource_id, &request.o3k_server_id.to_string());
        }

        assert_eq!(
            journal.reconcile_lifecycle_once(delete_operation).await?,
            OperationState::Succeeded
        );
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let replayed: Vec<String> = match observer.observed.lock() {
            Ok(entries) => entries.iter().map(|entry| entry.3.clone()).collect(),
            Err(_) => Vec::new(),
        };
        assert_eq!(replayed, vec!["ACTIVE", "DELETED"]);
        Ok(())
    }

    /// A metering authority failure during a durable projection must surface,
    /// never be silently dropped.
    #[tokio::test]
    async fn failing_metering_observer_surfaces_reconcile_error() -> Result<(), ReconcileError> {
        let (journal, _store, _provider) = journal("metering-failure", 2).await?;
        let journal = journal.with_metering_observer(Arc::new(FailingMeteringObserver));
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        let result = journal.reconcile_once(create_operation).await;
        assert!(
            matches!(result, Err(ReconcileError::Metering(_))),
            "expected a surfaced metering failure, got {result:?}"
        );
        Ok(())
    }

    /// Fails the first projection and succeeds every later one, so a test can
    /// prove a crashed/failed observation is repaired by re-driving the step.
    struct FailOnceMeteringObserver {
        failed: std::sync::atomic::AtomicBool,
    }

    impl FailOnceMeteringObserver {
        fn new() -> Self {
            Self {
                failed: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl o3k_kernel::LifecycleMeteringObserver for FailOnceMeteringObserver {
        async fn observe_resource_state(
            &self,
            _kind: &str,
            _project_id: &str,
            _resource_id: &str,
            _observed_state: &str,
        ) -> Result<(), o3k_kernel::KernelError> {
            if !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return Err(o3k_kernel::KernelError::MeteringUnavailable(
                    "first projection fails".to_owned(),
                ));
            }
            Ok(())
        }

        async fn observe_allocation(
            &self,
            _meter_key: &str,
            _project_id: &str,
            _resource_id: &str,
            _quantity: u64,
            _consuming: bool,
        ) -> Result<(), o3k_kernel::KernelError> {
            Ok(())
        }
    }

    /// The observation must precede the step's durable writes: when it fails,
    /// the operation stays non-terminal and the resource is not yet projected,
    /// so the same idempotent drive repairs it on retry instead of losing the
    /// observation behind a terminal operation.
    #[tokio::test]
    async fn metering_observation_precedes_durable_writes() -> Result<(), ReconcileError> {
        let (journal, store, _provider) = journal("metering-ordering", 2).await?;
        let journal = journal.with_metering_observer(Arc::new(FailOnceMeteringObserver::new()));

        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        let result = journal.reconcile_once(create_operation).await;
        assert!(
            matches!(result, Err(ReconcileError::Metering(_))),
            "expected the first projection to surface, got {result:?}"
        );
        let operation = store.get_operation(create_operation).await?;
        assert!(
            !matches!(
                operation.state,
                OperationState::Succeeded | OperationState::Failed
            ),
            "a failed projection must leave the step retriable, got {:?}",
            operation.state
        );
        assert_ne!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE",
            "the resource must not be projected before the observation lands"
        );

        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded,
            "the same drive must converge once the observer recovers"
        );
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        Ok(())
    }

    /// Delegating durable store that fails exactly one
    /// `update_resource_from_observation` call with `StaleGeneration`, so a
    /// test can prove a lost generation CAS records no metering observation.
    /// Every other call passes through to the real store.
    struct StaleObservationStore {
        inner: TestStore,
        stale_observation: Arc<std::sync::atomic::AtomicBool>,
    }

    impl StaleObservationStore {
        fn new(inner: TestStore) -> Self {
            Self {
                inner,
                stale_observation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }

        fn fail_next_observation(&self) {
            self.stale_observation
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl DurableStore for StaleObservationStore {
        async fn get_idempotency_reservation(
            &self,
            owner_scope: &str,
            action: &str,
            key: &str,
        ) -> Result<Option<o3k_store::StoredIdempotencyReservation>, StoreError> {
            self.inner
                .get_idempotency_reservation(owner_scope, action, key)
                .await
        }

        async fn insert_resource(&self, resource: &ResourceRecord) -> Result<(), StoreError> {
            self.inner.insert_resource(resource).await
        }

        async fn get_resource(&self, id: Uuid) -> Result<ResourceRecord, StoreError> {
            self.inner.get_resource(id).await
        }

        async fn list_resources(
            &self,
            project_id: &str,
            kind: &str,
        ) -> Result<Vec<ResourceRecord>, StoreError> {
            self.inner.list_resources(project_id, kind).await
        }

        async fn list_resources_page(
            &self,
            project_id: &str,
            kind: &str,
            after_id: Option<&str>,
            limit: usize,
        ) -> Result<o3k_store::RepositoryPage<ResourceRecord>, StoreError> {
            self.inner
                .list_resources_page(project_id, kind, after_id, limit)
                .await
        }

        async fn update_resource(
            &self,
            id: Uuid,
            expected_generation: i64,
            desired_state: &str,
            observed_state: &str,
            observed_generation: i64,
            provider_id: Option<&str>,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .update_resource(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                )
                .await
        }

        async fn update_resource_and_complete_operation(
            &self,
            resource_id: Uuid,
            expected_generation: i64,
            desired_state: &str,
            observed_state: &str,
            observed_generation: i64,
            provider_id: Option<&str>,
            operation_id: Uuid,
            lifecycle: &o3k_store::CanonicalOperationLifecycleUpdate,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .update_resource_and_complete_operation(
                    resource_id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation_id,
                    lifecycle,
                )
                .await
        }

        async fn update_resource_from_observation(
            &self,
            id: Uuid,
            update: &ObservationUpdate<'_>,
        ) -> Result<ResourceRecord, StoreError> {
            if self
                .stale_observation
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(StoreError::StaleGeneration);
            }
            self.inner
                .update_resource_from_observation(id, update)
                .await
        }

        async fn terminalize_lifecycle(
            &self,
            terminalization: &o3k_store::LifecycleTerminalization<'_>,
        ) -> Result<(OperationRecord, ResourceRecord), StoreError> {
            self.inner.terminalize_lifecycle(terminalization).await
        }

        async fn insert_operation(&self, operation: &OperationRecord) -> Result<(), StoreError> {
            self.inner.insert_operation(operation).await
        }

        async fn reserve_idempotent_operation(
            &self,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner.reserve_idempotent_operation(request).await
        }

        async fn create_or_replay_idempotent_operation(
            &self,
            operation: &OperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner
                .create_or_replay_idempotent_operation(operation, request)
                .await
        }

        async fn create_or_replay_canonical_idempotent_operation(
            &self,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner
                .create_or_replay_canonical_idempotent_operation(operation, canonical, request)
                .await
        }

        async fn create_or_replay_canonical_scoped_operation(
            &self,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner
                .create_or_replay_canonical_scoped_operation(operation, canonical, request)
                .await
        }

        async fn create_or_replay_canonical_resource_operation(
            &self,
            resource: &ResourceRecord,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
            expected_placement_allocation_id: Option<&str>,
        ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
            self.inner
                .create_or_replay_canonical_resource_operation(
                    resource,
                    operation,
                    canonical,
                    request,
                    expected_placement_allocation_id,
                )
                .await
        }

        async fn create_or_replay_canonical_lifecycle_operation(
            &self,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
            self.inner
                .create_or_replay_canonical_lifecycle_operation(operation, canonical, request)
                .await
        }

        async fn get_operation(&self, id: Uuid) -> Result<OperationRecord, StoreError> {
            self.inner.get_operation(id).await
        }

        async fn get_canonical_operation(
            &self,
            id: Uuid,
        ) -> Result<CanonicalOperationRecord, StoreError> {
            self.inner.get_canonical_operation(id).await
        }

        async fn list_canonical_operations_page(
            &self,
            owner_scope: &str,
            after_id: Option<Uuid>,
            limit: u32,
        ) -> Result<Vec<CanonicalOperationRecord>, StoreError> {
            self.inner
                .list_canonical_operations_page(owner_scope, after_id, limit)
                .await
        }

        async fn update_canonical_operation_lifecycle(
            &self,
            id: Uuid,
            update: &o3k_store::CanonicalOperationLifecycleUpdate,
        ) -> Result<CanonicalOperationRecord, StoreError> {
            self.inner
                .update_canonical_operation_lifecycle(id, update)
                .await
        }

        async fn update_operation(
            &self,
            id: Uuid,
            state: OperationState,
            provider_operation_id: Option<&str>,
            error_category: Option<&str>,
            error_message: Option<&str>,
        ) -> Result<OperationRecord, StoreError> {
            self.inner
                .update_operation(
                    id,
                    state,
                    provider_operation_id,
                    error_category,
                    error_message,
                )
                .await
        }

        async fn list_non_terminal_lifecycle_operations(
            &self,
        ) -> Result<Vec<OperationRecord>, StoreError> {
            self.inner.list_non_terminal_lifecycle_operations().await
        }

        async fn attach_provider_reference(
            &self,
            reference: &ProviderReference,
        ) -> Result<(), StoreError> {
            self.inner.attach_provider_reference(reference).await
        }

        async fn get_provider_reference(
            &self,
            resource_id: Uuid,
            provider_name: &str,
        ) -> Result<ProviderReference, StoreError> {
            self.inner
                .get_provider_reference(resource_id, provider_name)
                .await
        }

        async fn insert_agent_command(
            &self,
            command: &AgentCommandRecord,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner.insert_agent_command(command).await
        }

        async fn get_agent_command(
            &self,
            command_id: &str,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner.get_agent_command(command_id).await
        }

        async fn get_agent_command_by_idempotency_key(
            &self,
            idempotency_key: &str,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner
                .get_agent_command_by_idempotency_key(idempotency_key)
                .await
        }

        async fn get_agent_command_by_operation(
            &self,
            operation_id: Uuid,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner
                .get_agent_command_by_operation(operation_id)
                .await
        }

        async fn update_agent_command(
            &self,
            command_id: &str,
            state: AgentCommandState,
            accepted_sequence: u64,
            last_sequence: u64,
            provider_operation_id: Option<&str>,
            provider_resource_id: Option<&str>,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner
                .update_agent_command(
                    command_id,
                    state,
                    accepted_sequence,
                    last_sequence,
                    provider_operation_id,
                    provider_resource_id,
                )
                .await
        }

        async fn list_recoverable_agent_commands(
            &self,
        ) -> Result<Vec<AgentCommandRecord>, StoreError> {
            self.inner.list_recoverable_agent_commands().await
        }

        async fn insert_artifact_transfer(
            &self,
            transfer: &o3k_store::ArtifactTransferRecord,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner.insert_artifact_transfer(transfer).await
        }

        async fn get_artifact_transfer(
            &self,
            transfer_id: &str,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner.get_artifact_transfer(transfer_id).await
        }

        async fn rebind_artifact_transfer_epoch(
            &self,
            transfer_id: &str,
            expected_agent_epoch: &str,
            new_agent_epoch: &str,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner
                .rebind_artifact_transfer_epoch(transfer_id, expected_agent_epoch, new_agent_epoch)
                .await
        }

        async fn update_artifact_transfer(
            &self,
            transfer_id: &str,
            expected_agent_epoch: &str,
            update: o3k_store::ArtifactTransferUpdate,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner
                .update_artifact_transfer(transfer_id, expected_agent_epoch, update)
                .await
        }

        async fn list_recoverable_artifact_transfers(
            &self,
        ) -> Result<Vec<o3k_store::ArtifactTransferRecord>, StoreError> {
            self.inner.list_recoverable_artifact_transfers().await
        }

        async fn expire_transfers_of_terminal_operations(&self) -> Result<u64, StoreError> {
            self.inner.expire_transfers_of_terminal_operations().await
        }

        async fn insert_image_overlay(
            &self,
            overlay: &o3k_store::ImageOverlayOwnershipRecord,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner.insert_image_overlay(overlay).await
        }

        async fn get_image_overlay(
            &self,
            overlay_id: &str,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner.get_image_overlay(overlay_id).await
        }

        async fn update_image_overlay(
            &self,
            overlay_id: &str,
            expected_identity: &o3k_store::ImageOverlayIdentity,
            update: o3k_store::ImageOverlayUpdate,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner
                .update_image_overlay(overlay_id, expected_identity, update)
                .await
        }

        async fn list_image_overlays(
            &self,
            resource_id: Uuid,
        ) -> Result<Vec<o3k_store::ImageOverlayOwnershipRecord>, StoreError> {
            self.inner.list_image_overlays(resource_id).await
        }

        async fn count_image_overlay_references(
            &self,
            base_sha256: &str,
            base_format: &str,
        ) -> Result<u64, StoreError> {
            self.inner
                .count_image_overlay_references(base_sha256, base_format)
                .await
        }

        async fn delete_image_overlay(
            &self,
            overlay_id: &str,
            expected_identity: &o3k_store::ImageOverlayIdentity,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner
                .delete_image_overlay(overlay_id, expected_identity)
                .await
        }

        async fn increment_operation_retry(&self, operation_id: Uuid) -> Result<u8, StoreError> {
            self.inner.increment_operation_retry(operation_id).await
        }

        async fn insert_resource_and_operation(
            &self,
            resource: &ResourceRecord,
            operation: &OperationRecord,
            expected_placement_allocation_id: Option<&str>,
        ) -> Result<(), StoreError> {
            self.inner
                .insert_resource_and_operation(
                    resource,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
        }

        async fn revive_resource_and_operation(
            &self,
            id: Uuid,
            expected_generation: i64,
            desired_state: &str,
            observed_state: &str,
            observed_generation: i64,
            provider_id: Option<&str>,
            operation: &OperationRecord,
            expected_placement_allocation_id: Option<&str>,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .revive_resource_and_operation(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
        }

        async fn readiness_check(&self) -> Result<(), StoreError> {
            self.inner.readiness_check().await
        }
    }

    /// Delegating durable store for the issue-#1041 crash boundary. Every
    /// method passes through to the real store except
    /// `terminalize_lifecycle`, which supports two fault modes:
    ///
    /// - `fail_next_terminalization()`: the NEXT terminalization fails on a
    ///   sabotaged operation identity, so the REAL primitive fails with its
    ///   genuine `OperationNotFound` error. This is the control-plane crash
    ///   at the worst possible moment — the provider mutation has already
    ///   succeeded and the durable terminalization is about to commit — and
    ///   the invariant under test is that a failed terminalization commits
    ///   nothing (the transaction is all-or-nothing).
    /// - `arm_atomic_terminalization_assertion()`: after a delegated
    ///   terminalization, the returned rows must BOTH be terminal. A split
    ///   commit would surface here deterministically instead of needing a
    ///   racy external observer.
    struct TerminalizationFaultStore {
        inner: TestStore,
        fail_next: Arc<AtomicBool>,
        assert_atomic: Arc<AtomicBool>,
    }

    impl TerminalizationFaultStore {
        fn new(inner: TestStore) -> Self {
            Self {
                inner,
                fail_next: Arc::new(AtomicBool::new(false)),
                assert_atomic: Arc::new(AtomicBool::new(false)),
            }
        }

        fn fail_next_terminalization(&self) {
            self.fail_next
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        fn arm_atomic_terminalization_assertion(&self) {
            self.assert_atomic
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl DurableStore for TerminalizationFaultStore {
        async fn get_idempotency_reservation(
            &self,
            owner_scope: &str,
            action: &str,
            key: &str,
        ) -> Result<Option<o3k_store::StoredIdempotencyReservation>, StoreError> {
            self.inner
                .get_idempotency_reservation(owner_scope, action, key)
                .await
        }

        async fn insert_resource(&self, resource: &ResourceRecord) -> Result<(), StoreError> {
            self.inner.insert_resource(resource).await
        }

        async fn get_resource(&self, id: Uuid) -> Result<ResourceRecord, StoreError> {
            self.inner.get_resource(id).await
        }

        async fn list_resources(
            &self,
            project_id: &str,
            kind: &str,
        ) -> Result<Vec<ResourceRecord>, StoreError> {
            self.inner.list_resources(project_id, kind).await
        }

        async fn list_resources_page(
            &self,
            project_id: &str,
            kind: &str,
            after_id: Option<&str>,
            limit: usize,
        ) -> Result<o3k_store::RepositoryPage<ResourceRecord>, StoreError> {
            self.inner
                .list_resources_page(project_id, kind, after_id, limit)
                .await
        }

        async fn update_resource(
            &self,
            id: Uuid,
            expected_generation: i64,
            desired_state: &str,
            observed_state: &str,
            observed_generation: i64,
            provider_id: Option<&str>,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .update_resource(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                )
                .await
        }

        async fn update_resource_and_complete_operation(
            &self,
            resource_id: Uuid,
            expected_generation: i64,
            desired_state: &str,
            observed_state: &str,
            observed_generation: i64,
            provider_id: Option<&str>,
            operation_id: Uuid,
            lifecycle: &o3k_store::CanonicalOperationLifecycleUpdate,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .update_resource_and_complete_operation(
                    resource_id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation_id,
                    lifecycle,
                )
                .await
        }

        async fn update_resource_from_observation(
            &self,
            id: Uuid,
            update: &ObservationUpdate<'_>,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .update_resource_from_observation(id, update)
                .await
        }

        async fn terminalize_lifecycle(
            &self,
            terminalization: &o3k_store::LifecycleTerminalization<'_>,
        ) -> Result<(OperationRecord, ResourceRecord), StoreError> {
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                // The simulated crash runs through the REAL primitive with a
                // sabotaged operation identity: a genuine store failure, and
                // (because the primitive is one transaction) provably no
                // durable effect.
                return self
                    .inner
                    .terminalize_lifecycle(&o3k_store::LifecycleTerminalization {
                        operation_id: Uuid::now_v7(),
                        ..terminalization.clone()
                    })
                    .await;
            }
            let outcome = self.inner.terminalize_lifecycle(terminalization).await?;
            if self.assert_atomic.load(std::sync::atomic::Ordering::SeqCst) {
                assert!(
                    matches!(
                        outcome.0.state,
                        OperationState::Succeeded | OperationState::Failed
                    ),
                    "terminalize_lifecycle observed a non-terminal operation: {:?}",
                    outcome.0.state
                );
                assert_eq!(
                    outcome.1.observed_state, terminalization.observed_state,
                    "terminalize_lifecycle observed a resource projection that does not \
                     match the terminalization"
                );
            }
            Ok(outcome)
        }

        async fn insert_operation(&self, operation: &OperationRecord) -> Result<(), StoreError> {
            self.inner.insert_operation(operation).await
        }

        async fn reserve_idempotent_operation(
            &self,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner.reserve_idempotent_operation(request).await
        }

        async fn create_or_replay_idempotent_operation(
            &self,
            operation: &OperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner
                .create_or_replay_idempotent_operation(operation, request)
                .await
        }

        async fn create_or_replay_canonical_idempotent_operation(
            &self,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner
                .create_or_replay_canonical_idempotent_operation(operation, canonical, request)
                .await
        }

        async fn create_or_replay_canonical_scoped_operation(
            &self,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<o3k_store::IdempotencyReservation, StoreError> {
            self.inner
                .create_or_replay_canonical_scoped_operation(operation, canonical, request)
                .await
        }

        async fn create_or_replay_canonical_resource_operation(
            &self,
            resource: &ResourceRecord,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
            expected_placement_allocation_id: Option<&str>,
        ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
            self.inner
                .create_or_replay_canonical_resource_operation(
                    resource,
                    operation,
                    canonical,
                    request,
                    expected_placement_allocation_id,
                )
                .await
        }

        async fn create_or_replay_canonical_lifecycle_operation(
            &self,
            operation: &OperationRecord,
            canonical: &CanonicalOperationRecord,
            request: &IdempotencyReservationRequest,
        ) -> Result<CanonicalAcceptanceOutcome, StoreError> {
            self.inner
                .create_or_replay_canonical_lifecycle_operation(operation, canonical, request)
                .await
        }

        async fn get_operation(&self, id: Uuid) -> Result<OperationRecord, StoreError> {
            self.inner.get_operation(id).await
        }

        async fn get_canonical_operation(
            &self,
            id: Uuid,
        ) -> Result<CanonicalOperationRecord, StoreError> {
            self.inner.get_canonical_operation(id).await
        }

        async fn list_canonical_operations_page(
            &self,
            owner_scope: &str,
            after_id: Option<Uuid>,
            limit: u32,
        ) -> Result<Vec<CanonicalOperationRecord>, StoreError> {
            self.inner
                .list_canonical_operations_page(owner_scope, after_id, limit)
                .await
        }

        async fn update_canonical_operation_lifecycle(
            &self,
            id: Uuid,
            update: &o3k_store::CanonicalOperationLifecycleUpdate,
        ) -> Result<CanonicalOperationRecord, StoreError> {
            self.inner
                .update_canonical_operation_lifecycle(id, update)
                .await
        }

        async fn update_operation(
            &self,
            id: Uuid,
            state: OperationState,
            provider_operation_id: Option<&str>,
            error_category: Option<&str>,
            error_message: Option<&str>,
        ) -> Result<OperationRecord, StoreError> {
            self.inner
                .update_operation(
                    id,
                    state,
                    provider_operation_id,
                    error_category,
                    error_message,
                )
                .await
        }

        async fn list_non_terminal_lifecycle_operations(
            &self,
        ) -> Result<Vec<OperationRecord>, StoreError> {
            self.inner.list_non_terminal_lifecycle_operations().await
        }

        async fn attach_provider_reference(
            &self,
            reference: &ProviderReference,
        ) -> Result<(), StoreError> {
            self.inner.attach_provider_reference(reference).await
        }

        async fn get_provider_reference(
            &self,
            resource_id: Uuid,
            provider_name: &str,
        ) -> Result<ProviderReference, StoreError> {
            self.inner
                .get_provider_reference(resource_id, provider_name)
                .await
        }

        async fn insert_agent_command(
            &self,
            command: &AgentCommandRecord,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner.insert_agent_command(command).await
        }

        async fn get_agent_command(
            &self,
            command_id: &str,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner.get_agent_command(command_id).await
        }

        async fn get_agent_command_by_idempotency_key(
            &self,
            idempotency_key: &str,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner
                .get_agent_command_by_idempotency_key(idempotency_key)
                .await
        }

        async fn get_agent_command_by_operation(
            &self,
            operation_id: Uuid,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner
                .get_agent_command_by_operation(operation_id)
                .await
        }

        async fn update_agent_command(
            &self,
            command_id: &str,
            state: AgentCommandState,
            accepted_sequence: u64,
            last_sequence: u64,
            provider_operation_id: Option<&str>,
            provider_resource_id: Option<&str>,
        ) -> Result<AgentCommandRecord, StoreError> {
            self.inner
                .update_agent_command(
                    command_id,
                    state,
                    accepted_sequence,
                    last_sequence,
                    provider_operation_id,
                    provider_resource_id,
                )
                .await
        }

        async fn list_recoverable_agent_commands(
            &self,
        ) -> Result<Vec<AgentCommandRecord>, StoreError> {
            self.inner.list_recoverable_agent_commands().await
        }

        async fn insert_artifact_transfer(
            &self,
            transfer: &o3k_store::ArtifactTransferRecord,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner.insert_artifact_transfer(transfer).await
        }

        async fn get_artifact_transfer(
            &self,
            transfer_id: &str,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner.get_artifact_transfer(transfer_id).await
        }

        async fn rebind_artifact_transfer_epoch(
            &self,
            transfer_id: &str,
            expected_agent_epoch: &str,
            new_agent_epoch: &str,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner
                .rebind_artifact_transfer_epoch(transfer_id, expected_agent_epoch, new_agent_epoch)
                .await
        }

        async fn update_artifact_transfer(
            &self,
            transfer_id: &str,
            expected_agent_epoch: &str,
            update: o3k_store::ArtifactTransferUpdate,
        ) -> Result<o3k_store::ArtifactTransferRecord, StoreError> {
            self.inner
                .update_artifact_transfer(transfer_id, expected_agent_epoch, update)
                .await
        }

        async fn list_recoverable_artifact_transfers(
            &self,
        ) -> Result<Vec<o3k_store::ArtifactTransferRecord>, StoreError> {
            self.inner.list_recoverable_artifact_transfers().await
        }

        async fn expire_transfers_of_terminal_operations(&self) -> Result<u64, StoreError> {
            self.inner.expire_transfers_of_terminal_operations().await
        }

        async fn insert_image_overlay(
            &self,
            overlay: &o3k_store::ImageOverlayOwnershipRecord,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner.insert_image_overlay(overlay).await
        }

        async fn get_image_overlay(
            &self,
            overlay_id: &str,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner.get_image_overlay(overlay_id).await
        }

        async fn update_image_overlay(
            &self,
            overlay_id: &str,
            expected_identity: &o3k_store::ImageOverlayIdentity,
            update: o3k_store::ImageOverlayUpdate,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner
                .update_image_overlay(overlay_id, expected_identity, update)
                .await
        }

        async fn list_image_overlays(
            &self,
            resource_id: Uuid,
        ) -> Result<Vec<o3k_store::ImageOverlayOwnershipRecord>, StoreError> {
            self.inner.list_image_overlays(resource_id).await
        }

        async fn count_image_overlay_references(
            &self,
            base_sha256: &str,
            base_format: &str,
        ) -> Result<u64, StoreError> {
            self.inner
                .count_image_overlay_references(base_sha256, base_format)
                .await
        }

        async fn delete_image_overlay(
            &self,
            overlay_id: &str,
            expected_identity: &o3k_store::ImageOverlayIdentity,
        ) -> Result<o3k_store::ImageOverlayOwnershipRecord, StoreError> {
            self.inner
                .delete_image_overlay(overlay_id, expected_identity)
                .await
        }

        async fn increment_operation_retry(&self, operation_id: Uuid) -> Result<u8, StoreError> {
            self.inner.increment_operation_retry(operation_id).await
        }

        async fn insert_resource_and_operation(
            &self,
            resource: &ResourceRecord,
            operation: &OperationRecord,
            expected_placement_allocation_id: Option<&str>,
        ) -> Result<(), StoreError> {
            self.inner
                .insert_resource_and_operation(
                    resource,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
        }

        async fn revive_resource_and_operation(
            &self,
            id: Uuid,
            expected_generation: i64,
            desired_state: &str,
            observed_state: &str,
            observed_generation: i64,
            provider_id: Option<&str>,
            operation: &OperationRecord,
            expected_placement_allocation_id: Option<&str>,
        ) -> Result<ResourceRecord, StoreError> {
            self.inner
                .revive_resource_and_operation(
                    id,
                    expected_generation,
                    desired_state,
                    observed_state,
                    observed_generation,
                    provider_id,
                    operation,
                    expected_placement_allocation_id,
                )
                .await
        }

        async fn readiness_check(&self) -> Result<(), StoreError> {
            self.inner.readiness_check().await
        }
    }

    async fn fault_journal(
        label: &str,
    ) -> Result<
        (
            OperationJournal<TerminalizationFaultStore, FakeComputeProvider>,
            Arc<TerminalizationFaultStore>,
            Arc<FakeComputeProvider>,
        ),
        ReconcileError,
    > {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-{label}-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let raw = o3k_store::testkit::open_file(&path).await?;
        let store = Arc::new(TerminalizationFaultStore::new(raw));
        let provider = Arc::new(FakeComputeProvider::new());
        Ok((
            OperationJournal::new(store.clone(), provider.clone(), 2),
            store,
            provider,
        ))
    }

    /// Issue #1041, crash arm: the durable terminalization fails after the
    /// provider delete already succeeded — the worst split-write moment. The
    /// atomic primitive must commit NOTHING: the operation stays non-terminal,
    /// the resource projection stays non-terminal, and re-driving the same
    /// operation converges exactly once.
    #[tokio::test]
    async fn lifecycle_terminalization_failure_commits_nothing_and_recovers()
    -> Result<(), ReconcileError> {
        let (journal, store, provider) = fault_journal("terminalization-fault").await?;
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let generation_before = store.get_resource(request.o3k_server_id).await?.generation;
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;

        // The crash: the provider delete succeeds, then the terminalization
        // fails inside the store.
        store.fail_next_terminalization();
        let outcome = journal.reconcile_lifecycle_once(operation_id).await;
        assert!(
            matches!(
                outcome,
                Err(ReconcileError::Store(StoreError::OperationNotFound))
            ),
            "the injected terminalization failure must propagate: {outcome:?}"
        );
        // The provider side effect DID happen — that is why this state must be
        // re-drivable rather than terminal.
        assert_eq!(provider.instance_count(), 0);
        // Issue #1041 invariant after the crash: NEITHER durable half is
        // committed, exactly as if the terminalization never ran.
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(
            operation.state,
            OperationState::Running,
            "a failed terminalization must leave the operation non-terminal"
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_ne!(
            resource.observed_state, "DELETED",
            "a failed terminalization must leave the resource projection non-terminal"
        );
        assert_eq!(
            resource.generation, generation_before,
            "a failed terminalization must not bump the resource generation"
        );

        // Re-drive converges once: the absent instance proves the delete, the
        // atomic primitive commits both halves together.
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::Succeeded);
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(resource.observed_state, "DELETED");
        assert_eq!(
            resource.generation,
            generation_before + 1,
            "re-drive must apply the terminalization exactly once"
        );
        Ok(())
    }

    /// Issue #1041, success arm: `finish_lifecycle` commits the terminal
    /// operation and the terminal resource projection in one transaction, and
    /// a replay of the terminal operation neither errors nor re-applies.
    #[tokio::test]
    async fn lifecycle_terminalization_commits_both_halves_together() -> Result<(), ReconcileError>
    {
        let (journal, store, _provider) = fault_journal("terminalization-atomic").await?;
        store.arm_atomic_terminalization_assertion();
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let generation_before = store.get_resource(request.o3k_server_id).await?.generation;
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Delete)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        // Both halves terminal, applied exactly once (the wrapper's
        // post-call assertion proves no split outcome was observable).
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::Succeeded);
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(resource.observed_state, "DELETED");
        assert_eq!(
            resource.generation,
            generation_before + 1,
            "terminalization must apply exactly once"
        );
        // Reconcile of the now-terminal operation is an idempotent no-op.
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(
            resource.generation,
            generation_before + 1,
            "a terminal replay must not double-apply the projection"
        );
        assert_eq!(resource.observed_state, "DELETED");
        Ok(())
    }

    /// Issue #1041: the terminalization primitive also serves the
    /// start/stop/reboot arms of `finish_lifecycle`, whose observed state is
    /// derived from the provider instance rather than hard-coded to DELETED.
    #[tokio::test]
    async fn stop_lifecycle_terminalization_commits_both_halves_together()
    -> Result<(), ReconcileError> {
        let (journal, store, _provider) = fault_journal("terminalization-stop").await?;
        store.arm_atomic_terminalization_assertion();
        let request = request();
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        let generation_before = store.get_resource(request.o3k_server_id).await?.generation;
        let resource = store.get_resource(request.o3k_server_id).await?;
        let operation_id = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, operation_id, LifecycleAction::Stop)
            .await?;
        assert_eq!(
            journal.reconcile_lifecycle_once(operation_id).await?,
            OperationState::Succeeded
        );
        let operation = store.get_operation(operation_id).await?;
        assert_eq!(operation.state, OperationState::Succeeded);
        let resource = store.get_resource(request.o3k_server_id).await?;
        assert_eq!(
            resource.observed_state, "SHUTOFF",
            "the stop projection must be committed atomically with the terminal operation"
        );
        assert_eq!(
            resource.generation,
            generation_before + 1,
            "terminalization must apply exactly once"
        );
        Ok(())
    }

    /// A generation-CAS observation that loses the race must record no
    /// metering observation: the loser's state never became durable, so
    /// metering it would fabricate usage. The projection is applied only after
    /// the CAS succeeds, using the state actually written.
    #[tokio::test]
    async fn stale_generation_observation_records_no_metering() -> Result<(), ReconcileError> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-metering-stale-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let raw = o3k_store::testkit::open_file(&path).await?;
        let store = Arc::new(StaleObservationStore::new(raw.clone()));
        let observer = RecordingMeteringObserver::default();
        let journal = OperationJournal::new(store.clone(), Arc::new(FakeComputeProvider::new()), 2)
            .with_metering_observer(Arc::new(observer.clone()));

        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_observation_command(
            &raw,
            operation_id,
            request.o3k_server_id,
            "compute-1",
            "epoch-1",
        )
        .await?;

        store.fail_next_observation();
        let observation = AgentObservation {
            agent_id: "compute-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            resource_id: request.o3k_server_id,
            provider_resource_id: None,
            state: o3k_provider::InstanceState::Running,
            operation_id,
            operation_state: AgentOperationState::Succeeded,
            observation_sequence: 1,
            observed_at_unix_ms: 1,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        };
        let result = journal.apply_agent_observation(&observation).await;
        assert!(
            matches!(
                result,
                Err(ReconcileError::Store(StoreError::StaleGeneration))
            ),
            "expected the losing CAS to surface StaleGeneration, got {result:?}"
        );
        let observed = match observer.observed.lock() {
            Ok(entries) => entries.clone(),
            Err(_) => Vec::new(),
        };
        assert!(
            observed.is_empty(),
            "a losing generation CAS must record no observation, saw {observed:?}"
        );
        Ok(())
    }

    fn running_observation(operation_id: Uuid, resource_id: Uuid) -> AgentObservation {
        AgentObservation {
            agent_id: "compute-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            resource_id,
            provider_resource_id: None,
            state: o3k_provider::InstanceState::Running,
            operation_id,
            operation_state: AgentOperationState::Succeeded,
            observation_sequence: 1,
            observed_at_unix_ms: 1,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        }
    }

    /// A metering failure while applying an agent observation is best-effort:
    /// the observation is durably applied, `apply_agent_observation` returns
    /// `Ok`, and the agent observation is never dropped because metering is
    /// unhappy.
    #[tokio::test]
    async fn failing_metering_observer_does_not_fail_agent_observation()
    -> Result<(), ReconcileError> {
        let (journal, store, _provider) = journal("observation-metering-fail", 2).await?;
        let journal = journal.with_metering_observer(Arc::new(FailingMeteringObserver));
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_observation_command(
            &store,
            operation_id,
            request.o3k_server_id,
            "compute-1",
            "epoch-1",
        )
        .await?;

        journal
            .apply_agent_observation(&running_observation(operation_id, request.o3k_server_id))
            .await?;
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        Ok(())
    }

    /// A projection lost after a committed observation is repaired by the next
    /// delivery for the same resource: the non-New fence short-circuit
    /// re-projects the durable `observed_state` (idempotent, not a fabrication).
    #[tokio::test]
    async fn duplicate_observation_repairs_a_lost_projection() -> Result<(), ReconcileError> {
        let observer = RecordingMeteringObserver::default();
        observer.set_failing(true);
        let (journal, store, _provider) = journal("observation-metering-repair", 2).await?;
        let journal = journal.with_metering_observer(Arc::new(observer.clone()));
        let request = request();
        let operation_id = journal.begin_create("project", &request).await?;
        bind_observation_command(
            &store,
            operation_id,
            request.o3k_server_id,
            "compute-1",
            "epoch-1",
        )
        .await?;
        let observation = running_observation(operation_id, request.o3k_server_id);

        // First delivery: the CAS commits but the projection fails, so nothing
        // is recorded.
        journal.apply_agent_observation(&observation).await?;
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "ACTIVE"
        );
        assert!(
            observer.observations().is_empty(),
            "a failing observer must record nothing"
        );

        // The same observation is re-delivered (the fence reports a duplicate);
        // the durable state is re-projected and now lands.
        observer.set_failing(false);
        journal.apply_agent_observation(&observation).await?;
        assert_eq!(
            observer.observations(),
            vec![(
                "compute_instance".to_owned(),
                "project".to_owned(),
                request.o3k_server_id.to_string(),
                "ACTIVE".to_owned(),
            )]
        );
        Ok(())
    }

    /// A UTC hour boundary: 2023-11-14T22:00:00Z.
    const METERING_BASE_MS: i64 = 1_699_999_200_000;
    const METERING_HOUR_MS: i64 = 3_600_000;

    /// Test metering authority: forwards compute-instance lifecycle
    /// observations into the durable store through the real
    /// [`MeteringRepository`], using the single shared state→consuming mapping.
    ///
    /// It carries a deterministic clock (`set_observed_at_ms`) and a one-shot
    /// injected projection failure (`fail_next_projection`), so tests can prove
    /// that a lost best-effort observation close is still healed by the
    /// surfaced `finish_lifecycle` projection — without sleeping on wall-clock
    /// timing.
    struct AuthorityMeteringObserver {
        store: Arc<TestStore>,
        observed_at_ms: Arc<AtomicI64>,
        fail_next: Arc<AtomicBool>,
        failure_count: Arc<AtomicUsize>,
        record_count: Arc<AtomicUsize>,
    }

    impl AuthorityMeteringObserver {
        fn new(store: Arc<TestStore>, observed_at_ms: i64) -> Self {
            Self {
                store,
                observed_at_ms: Arc::new(AtomicI64::new(observed_at_ms)),
                fail_next: Arc::new(AtomicBool::new(false)),
                failure_count: Arc::new(AtomicUsize::new(0)),
                record_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_observed_at_ms(&self, observed_at_ms: i64) {
            self.observed_at_ms.store(observed_at_ms, Ordering::SeqCst);
        }

        fn fail_next_projection(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }

        fn failed_projections(&self) -> usize {
            self.failure_count.load(Ordering::SeqCst)
        }

        fn recorded_projections(&self) -> usize {
            self.record_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl o3k_kernel::LifecycleMeteringObserver for AuthorityMeteringObserver {
        async fn observe_resource_state(
            &self,
            kind: &str,
            project_id: &str,
            resource_id: &str,
            observed_state: &str,
        ) -> Result<(), o3k_kernel::KernelError> {
            if kind != "compute_instance" {
                return Ok(());
            }
            if self.fail_next.swap(false, Ordering::SeqCst) {
                self.failure_count.fetch_add(1, Ordering::SeqCst);
                return Err(o3k_kernel::KernelError::MeteringUnavailable(
                    "injected metering projection failure".to_owned(),
                ));
            }
            let Some(consuming) = crate::compute_instance_state_consuming(observed_state) else {
                return Err(o3k_kernel::KernelError::MeteringCorrupt(format!(
                    "unknown compute instance state `{observed_state}`"
                )));
            };
            let result = self
                .store
                .record_observation(&o3k_kernel::MeterObservation {
                    meter_key: "compute:instance_seconds".to_owned(),
                    scope: project_id.to_owned(),
                    resource_id: resource_id.to_owned(),
                    quantity: if consuming { 1 } else { 0 },
                    consuming,
                    observed_at_ms: self.observed_at_ms.load(Ordering::SeqCst),
                    authority: "test-lifecycle".to_owned(),
                })
                .await;
            if result.is_ok() {
                self.record_count.fetch_add(1, Ordering::SeqCst);
            }
            result
        }

        async fn observe_allocation(
            &self,
            _meter_key: &str,
            _project_id: &str,
            _resource_id: &str,
            _quantity: u64,
            _consuming: bool,
        ) -> Result<(), o3k_kernel::KernelError> {
            Ok(())
        }
    }

    async fn authority_usage(
        store: &TestStore,
        evaluated_at_ms: i64,
    ) -> Result<o3k_kernel::MeterUsageReport, ReconcileError> {
        use o3k_kernel::{UsageGranularity, UsageQuery};
        store
            .usage(&UsageQuery {
                scope: "project".to_owned(),
                meter_keys: vec!["compute:instance_seconds".to_owned()],
                start_ms: METERING_BASE_MS,
                end_ms: METERING_BASE_MS + METERING_HOUR_MS,
                granularity: UsageGranularity::Hour,
                resource_id: None,
                evaluated_at_ms,
            })
            .await
            .map_err(|_| ReconcileError::InvalidIntent)
    }

    fn metering_path(label: &str) -> PathBuf {
        let path = PathBuf::from(format!(
            "/tmp/o3k-reconciler-{label}-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// R2 (i): a create rejected at dispatch terminalizes `Failed` without ever
    /// opening the compute runtime meter. The real metering authority reports
    /// exactly `0.000` — before and after a store restart and a replay.
    #[tokio::test]
    async fn dispatch_rejected_create_accrues_no_compute_metering() -> Result<(), ReconcileError> {
        let path = metering_path("metering-dispatch-rejected");
        let request = request();
        let operation_id;
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            store
                .ensure_authority(METERING_BASE_MS)
                .await
                .map_err(|_| ReconcileError::InvalidIntent)?;
            let provider = Arc::new(FakeComputeProvider::new());
            provider.set_failure(FailureInjection::Terminal)?;
            let journal =
                OperationJournal::new(store.clone(), provider, 3).with_metering_observer(Arc::new(
                    AuthorityMeteringObserver::new(store.clone(), METERING_BASE_MS),
                ));
            operation_id = journal.begin_create("project", &request).await?;
            assert_eq!(
                journal.reconcile_once(operation_id).await?,
                OperationState::Failed
            );

            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(report.meters[0].total, "0.000");
            assert_eq!(report.meters[0].status, o3k_kernel::UsageStatus::Complete);
        }
        // Restart the durable store: reopening the same database must show no
        // open interval and no accrual.
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(
                report.meters[0].total, "0.000",
                "no open interval may survive a restart"
            );
            assert_eq!(report.meters[0].status, o3k_kernel::UsageStatus::Complete);
        }
        // Replaying the terminal failed create must not accrue or open.
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            let provider = Arc::new(FakeComputeProvider::new());
            provider.set_failure(FailureInjection::Terminal)?;
            let journal = OperationJournal::new(store.clone(), provider, 3).with_metering_observer(
                Arc::new(AuthorityMeteringObserver::new(
                    store.clone(),
                    METERING_BASE_MS + METERING_HOUR_MS,
                )),
            );
            assert_eq!(
                journal.reconcile_once(operation_id).await?,
                OperationState::Failed
            );
            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(
                report.meters[0].total, "0.000",
                "a replayed failed create must not accrue"
            );
        }
        Ok(())
    }

    /// R2 (ii): a create re-scheduled by the retry path and then rejected
    /// terminally also finalizes `Failed` with exactly `0.000` metered runtime.
    #[tokio::test]
    async fn retried_create_terminal_failure_accrues_no_compute_metering()
    -> Result<(), ReconcileError> {
        let path = metering_path("metering-retried-terminal");
        let request = request();
        let operation_id;
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            store
                .ensure_authority(METERING_BASE_MS)
                .await
                .map_err(|_| ReconcileError::InvalidIntent)?;
            let provider = Arc::new(FakeComputeProvider::new());
            provider.set_failure(FailureInjection::Transient)?;
            let journal = OperationJournal::new(store.clone(), provider.clone(), 3)
                .with_metering_observer(Arc::new(AuthorityMeteringObserver::new(
                    store.clone(),
                    METERING_BASE_MS,
                )));
            operation_id = journal.begin_create("project", &request).await?;
            // First dispatch is scheduled for retry.
            assert_eq!(
                journal.reconcile_once(operation_id).await?,
                OperationState::Retryable
            );
            provider.set_failure(FailureInjection::Terminal)?;
            assert_eq!(
                journal.reconcile_once(operation_id).await?,
                OperationState::Failed
            );
            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(report.meters[0].total, "0.000");
            assert_eq!(report.meters[0].status, o3k_kernel::UsageStatus::Complete);
        }
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(report.meters[0].total, "0.000");
        }
        Ok(())
    }

    /// R2 (ii, exhaustion): exhausting the retry budget leaves the operation
    /// `UnknownOutcome` (never `Failed`) and never opens the runtime meter, even
    /// across a restart and a replay.
    #[tokio::test]
    async fn retry_exhaustion_accrues_no_compute_metering() -> Result<(), ReconcileError> {
        let path = metering_path("metering-retry-exhausted");
        let request = request();
        let operation_id;
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            store
                .ensure_authority(METERING_BASE_MS)
                .await
                .map_err(|_| ReconcileError::InvalidIntent)?;
            let provider = Arc::new(FakeComputeProvider::new());
            provider.set_failure(FailureInjection::Transient)?;
            let journal = OperationJournal::new(store.clone(), provider.clone(), 3)
                .with_metering_observer(Arc::new(AuthorityMeteringObserver::new(
                    store.clone(),
                    METERING_BASE_MS,
                )));
            operation_id = journal.begin_create("project", &request).await?;
            let mut last = OperationState::Pending;
            for _ in 0..3 {
                last = journal.reconcile_once(operation_id).await?;
            }
            assert_eq!(
                last,
                OperationState::UnknownOutcome,
                "retry exhaustion must not terminalize a retryable dispatch"
            );
            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(report.meters[0].total, "0.000");
        }
        {
            let store = Arc::new(o3k_store::testkit::open_file(&path).await?);
            let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
            assert_eq!(
                report.meters[0].total, "0.000",
                "retry exhaustion must not open an interval that survives a restart"
            );
        }
        Ok(())
    }

    /// A file-backed journal with the authority observer attached, the
    /// observer shared with the test for clock control and projection counts.
    async fn metered_journal(
        label: &str,
        observed_at_ms: i64,
    ) -> Result<
        (
            OperationJournal<TestStore, FakeComputeProvider>,
            Arc<TestStore>,
            Arc<AuthorityMeteringObserver>,
        ),
        ReconcileError,
    > {
        let (journal, store, _provider) = journal(label, 2).await?;
        let observer = Arc::new(AuthorityMeteringObserver::new(
            store.clone(),
            observed_at_ms,
        ));
        let journal = journal.with_metering_observer(observer.clone());
        Ok((journal, store, observer))
    }

    fn stopped_observation(operation_id: Uuid, resource_id: Uuid) -> AgentObservation {
        AgentObservation {
            agent_id: "compute-1".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
            resource_id,
            provider_resource_id: None,
            state: o3k_provider::InstanceState::Stopped,
            operation_id,
            operation_state: AgentOperationState::Succeeded,
            observation_sequence: 1,
            observed_at_unix_ms: 1,
            redacted_message: None,
            console_log_bytes: Vec::new(),
            console_log_offset: 0,
            console_log_complete: false,
            console_log_truncated: false,
            block_device: None,
        }
    }

    /// The safety net for a best-effort agent-observation close: the surfaced
    /// `finish_lifecycle` projection still closes the interval exactly once at
    /// the transitioned instant, and no replay double-counts or reopens it.
    ///
    /// The observer fails ONLY on the `apply_agent_observation` best-effort
    /// projection (a one-shot injected failure) while the `finish_lifecycle`
    /// surfaced projection succeeds.
    #[tokio::test]
    async fn observation_close_failure_is_healed_by_surfaced_lifecycle_close()
    -> Result<(), ReconcileError> {
        let (journal, store, observer) =
            metered_journal("metering-observation-close-healed", METERING_BASE_MS).await?;
        let request = request();

        // The create completes ACTIVE and opens the interval at BASE.
        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        assert_eq!(observer.recorded_projections(), 1);

        // A Stopped observation carries the close, but its best-effort
        // projection fails and is swallowed: the close is lost while the
        // durable projection still moves to SHUTOFF.
        bind_observation_command(
            &store,
            create_operation,
            request.o3k_server_id,
            "compute-1",
            "epoch-1",
        )
        .await?;
        observer.fail_next_projection();
        journal
            .apply_agent_observation(&stopped_observation(
                create_operation,
                request.o3k_server_id,
            ))
            .await?;
        assert_eq!(observer.failed_projections(), 1);
        assert_eq!(
            store
                .get_resource(request.o3k_server_id)
                .await?
                .observed_state,
            "SHUTOFF"
        );
        let still_open = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS)
            .await?
            .meters[0]
            .total
            .clone();
        assert_eq!(
            still_open, "3600.000",
            "the observation close was lost, so the interval is still open"
        );

        // The canonical stop lifecycle completes through the surfaced
        // (retried) projection at the transitioned instant.
        let resource = store.get_resource(request.o3k_server_id).await?;
        let stop_operation = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, stop_operation, LifecycleAction::Stop)
            .await?;
        observer.set_observed_at_ms(METERING_BASE_MS + 1_800_000);
        assert_eq!(
            journal.reconcile_lifecycle_once(stop_operation).await?,
            OperationState::Succeeded
        );
        assert_eq!(observer.recorded_projections(), 2);
        let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
        assert_eq!(
            report.meters[0].total, "1800.000",
            "the surfaced lifecycle close must close the interval exactly once at +30min"
        );

        // Replays: the terminal lifecycle short-circuits, and the duplicate
        // observation repairs nothing (idle states are never projected), so the
        // total and the projection count are unchanged.
        assert_eq!(
            journal.reconcile_lifecycle_once(stop_operation).await?,
            OperationState::Succeeded
        );
        journal
            .apply_agent_observation(&stopped_observation(
                create_operation,
                request.o3k_server_id,
            ))
            .await?;
        assert_eq!(observer.recorded_projections(), 2);
        let replay = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
        assert_eq!(replay.meters[0].total, "1800.000");
        Ok(())
    }

    /// When the first lifecycle drive's surfaced projection fails too, the
    /// operation stays retriable and the interval stays open; the retried drive
    /// closes it through the surfaced path, and a later observation of the same
    /// resource never leaves it open.
    #[tokio::test]
    async fn surfaced_lifecycle_close_retries_until_the_interval_closes()
    -> Result<(), ReconcileError> {
        let (journal, store, observer) =
            metered_journal("metering-surfaced-close-retry", METERING_BASE_MS).await?;
        let request = request();

        let create_operation = journal.begin_create("project", &request).await?;
        assert_eq!(
            journal.reconcile_once(create_operation).await?,
            OperationState::Succeeded
        );
        assert_eq!(observer.recorded_projections(), 1);

        // The observation close is lost (best-effort projection fails).
        bind_observation_command(
            &store,
            create_operation,
            request.o3k_server_id,
            "compute-1",
            "epoch-1",
        )
        .await?;
        observer.fail_next_projection();
        journal
            .apply_agent_observation(&stopped_observation(
                create_operation,
                request.o3k_server_id,
            ))
            .await?;
        assert_eq!(observer.failed_projections(), 1);

        let resource = store.get_resource(request.o3k_server_id).await?;
        let stop_operation = Uuid::now_v7();
        journal
            .begin_lifecycle(resource.id, stop_operation, LifecycleAction::Stop)
            .await?;
        observer.set_observed_at_ms(METERING_BASE_MS + 1_800_000);

        // First drive: the surfaced projection fails too, so the lifecycle must
        // stay retriable and the interval open.
        observer.fail_next_projection();
        assert!(matches!(
            journal.reconcile_lifecycle_once(stop_operation).await,
            Err(ReconcileError::Metering(_))
        ));
        assert_eq!(observer.failed_projections(), 2);
        assert!(
            !matches!(
                store.get_operation(stop_operation).await?.state,
                OperationState::Succeeded | OperationState::Failed
            ),
            "a failed surfaced projection must leave the lifecycle retriable"
        );
        let still_open = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS)
            .await?
            .meters[0]
            .total
            .clone();
        assert_eq!(
            still_open, "3600.000",
            "a failed surfaced projection must not close the interval"
        );

        // The retried drive (observer recovered) closes it through the surfaced
        // path.
        assert_eq!(
            journal.reconcile_lifecycle_once(stop_operation).await?,
            OperationState::Succeeded
        );
        assert_eq!(observer.recorded_projections(), 2);
        let report = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
        assert_eq!(report.meters[0].total, "1800.000");

        // A later observation of the same resource must not leave it open.
        journal
            .apply_agent_observation(&stopped_observation(
                create_operation,
                request.o3k_server_id,
            ))
            .await?;
        assert_eq!(observer.recorded_projections(), 2);
        let after = authority_usage(&store, METERING_BASE_MS + METERING_HOUR_MS).await?;
        assert_eq!(
            after.meters[0].total, "1800.000",
            "the stop interval must remain closed after a later observation"
        );
        Ok(())
    }
}
