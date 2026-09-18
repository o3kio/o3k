#[cfg(test)]
mod tests {
    use crate::cleanup::cleanup_config_drive_artifact;
    use crate::cleanup::reap_config_drive_artifacts;
    use crate::dhcp::DhcpRuntime;
    use crate::network::{DomainPresence, cleanup_instance_network};
    use crate::process::pid_is_alive;
    use crate::runtime::{
        CommittedArtifact, CommittedCreateInputs, CreateDomainIdentity, OwnedTap,
        StartupDomainRestore, StartupJournalRefresh, StartupTapRestore, capacity_failure_result,
        create_disk_gib, definitive_create_failure_result, definitive_failure_result,
        inspect_not_found_result, resolve_create_domain_spec,
        restore_expected_running_domains_with_window, verify_owned_domain,
    };
    use crate::*;
    use async_trait::async_trait;
    use o3k_compute_agent::ArtifactStore;
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    use std::path::PathBuf;

    #[test]
    fn hostname_normalization_discards_nul_padding_and_bounds_identity() {
        assert_eq!(
            normalized_hostname("compute-agent\0\0\0\n"),
            Some("compute-agent".to_owned())
        );
        assert!(normalized_hostname(&"x".repeat(254)).is_none());
        assert!(normalized_hostname("compute\0agent").is_none());
    }

    #[test]
    fn test_fault_pause_guard_accepts_only_positive_numeric_durations() {
        assert_eq!(test_fault_pause_ms_value(None), None);
        assert_eq!(test_fault_pause_ms_value(Some(String::new())), None);
        assert_eq!(test_fault_pause_ms_value(Some("0".to_owned())), None);
        assert_eq!(test_fault_pause_ms_value(Some("abc".to_owned())), None);
        assert_eq!(test_fault_pause_ms_value(Some("250".to_owned())), Some(250));
    }

    /// Serializes a [`ReadyBody`] and parses it back as JSON. Asserts the
    /// round-trip and returns `None` (the caller returns from the test) on
    /// any serialization failure, avoiding `unwrap` in tests.
    fn ready_body_json(body: &ReadyBody) -> Option<serde_json::Value> {
        let encoded = match serde_json::to_string(body) {
            Ok(encoded) => encoded,
            Err(error) => {
                // Plain fields cannot fail serialization; the assertion
                // condition is data-dependent so clippy's
                // assertions_on_constants rule stays satisfied.
                assert!(
                    error.to_string().is_empty(),
                    "ReadyBody must serialize: {error}"
                );
                return None;
            }
        };
        match serde_json::from_str(&encoded) {
            Ok(value) => Some(value),
            Err(error) => {
                assert!(
                    error.to_string().is_empty(),
                    "ReadyBody must deserialize: {error}"
                );
                None
            }
        }
    }

    /// Issue #617: the 200 /readyz body is the additive self-report contract
    /// `o3k doctor` reads — the existing `status` key is preserved, the new
    /// identity fields are present, and an absent epoch is omitted entirely
    /// (never `null`) so the doctor can parse leniently.
    #[test]
    fn readyz_body_reports_live_agent_identity_additively() {
        let Some(body) = ready_body_json(&ReadyBody {
            status: "ready",
            agent_id: "agent-1".to_owned(),
            agent_epoch: Some("epoch-1".to_owned()),
            software_version: "0.2.0-alpha.1".to_owned(),
            capabilities: ReadyCapabilities {
                max_vcpus: 8,
                max_memory_mib: 16_384,
                max_disk_gb: 10,
            },
        }) else {
            return;
        };
        assert_eq!(body["status"], "ready");
        assert_eq!(body["agent_id"], "agent-1");
        assert_eq!(body["agent_epoch"], "epoch-1");
        assert_eq!(body["software_version"], "0.2.0-alpha.1");
        assert_eq!(body["capabilities"]["max_vcpus"], 8);
        assert_eq!(body["capabilities"]["max_memory_mib"], 16_384);
        assert_eq!(body["capabilities"]["max_disk_gb"], 10);

        let Some(body) = ready_body_json(&ReadyBody {
            status: "ready",
            agent_id: "agent-1".to_owned(),
            agent_epoch: None,
            software_version: "0.2.0-alpha.1".to_owned(),
            capabilities: ReadyCapabilities {
                max_vcpus: 8,
                max_memory_mib: 16_384,
                max_disk_gb: 10,
            },
        }) else {
            return;
        };
        assert!(body.get("agent_epoch").is_none());
    }

    fn network_attachment(
        port_id: &str,
        fixed_ipv4: &str,
        subnet_cidr: &str,
        gateway_ipv4: &str,
    ) -> proto::NetworkAttachment {
        proto::NetworkAttachment {
            port_id: port_id.to_owned(),
            mac: "02:00:00:00:00:01".to_owned(),
            fixed_ipv4: fixed_ipv4.to_owned(),
            subnet_cidr: subnet_cidr.to_owned(),
            gateway_ipv4: gateway_ipv4.to_owned(),
        }
    }

    fn inspection(xml: &str) -> o3k_libvirt::DomainInspection {
        o3k_libvirt::DomainInspection {
            name: "o3k-domain".to_owned(),
            active: false,
            persistent: true,
            state: "shutoff".to_owned(),
            max_memory_kib: 128 * 1024,
            vcpus: 1,
            xml: xml.to_owned(),
        }
    }

    #[test]
    fn absent_domain_inspection_is_a_redacted_not_found_failure() {
        let result = inspect_not_found_result("o3k-domain".to_owned());
        assert_eq!(result.state, proto::OperationState::Failed as i32);
        assert_eq!(result.error_category, proto::ErrorCategory::NotFound as i32);
        assert_eq!(result.resource_state, proto::ResourceState::Error as i32);
        assert_eq!(result.redacted_message, "requested domain was not found");
        assert_eq!(result.provider_resource_id, "o3k-domain");
        assert!(result.console_log.is_none());
    }

    /// The issue-87 C-1 qemu-img shape: a create that failed before libvirt
    /// could define the domain (image materialization here) is absent by
    /// construction — no provider side effect can exist. The result must
    /// therefore carry the absence-proven category ("not_found" in the
    /// durable record) that the control plane's local-delete completion
    /// accepts, a terminal Failed state, and no provider resource identity.
    /// A generic "terminal" category would leave the failed create
    /// permanently undeletable: the accepted create carries a provider
    /// operation identity, so the delete guard's never-accepted condition
    /// cannot apply.
    #[test]
    fn definitive_pre_libvirt_failure_reports_absence_proven_category() {
        let result = definitive_failure_result(&AgentError::Protocol(
            "instance image overlay could not be realized".to_owned(),
        ));
        assert_eq!(result.state, proto::OperationState::Failed as i32);
        assert_eq!(
            result.error_category,
            proto::ErrorCategory::NotFound as i32,
            "a definitive pre-libvirt failure must record the absence-proven \
             category so the control plane can complete a local delete"
        );
        assert_eq!(result.resource_state, proto::ResourceState::Error as i32);
        assert!(
            result
                .redacted_message
                .contains("instance image overlay could not be realized"),
            "the redacted reason must be carried in the result for the durable record"
        );
        assert_eq!(
            result.provider_resource_id, "",
            "no provider resource identity can exist for a pre-libvirt failure"
        );
        assert!(result.console_log.is_none());
    }

    #[test]
    fn lifecycle_mutations_require_matching_owned_metadata() {
        let xml = "<domain><metadata><o3k:domain xmlns:o3k=\"urn:o3k:compute:domain\" server_id=\"server-1\" project_id=\"project\" generation=\"1\" operation_id=\"operation\" managed_by=\"o3k-compute\" /></metadata></domain>";
        assert!(verify_owned_domain(&inspection(xml), "server-1").is_ok());
        assert!(verify_owned_domain(&inspection(xml), "server-2").is_err());
        assert!(verify_owned_domain(&inspection("<domain />"), "server-1").is_err());
    }

    #[test]
    fn console_observation_requires_matching_owned_metadata() {
        let owned = "<domain><metadata><o3k:domain xmlns:o3k=\"urn:o3k:compute:domain\" server_id=\"server-console\" project_id=\"project\" generation=\"1\" operation_id=\"operation\" managed_by=\"o3k-compute\" /></metadata></domain>";
        assert!(verify_owned_domain(&inspection(owned), "server-console").is_ok());
        assert!(verify_owned_domain(&inspection(owned), "other-project-server").is_err());
        assert!(
            verify_owned_domain(
                &inspection("<domain><metadata /></domain>"),
                "server-console"
            )
            .is_err()
        );
    }

    #[test]
    fn dhcp_runtime_rejects_mixed_flat_networks_before_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!(
            "o3k-compute-dhcp-validation-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        let attachments = vec![
            network_attachment("port-1", "192.0.2.2", "192.0.2.0/29", "192.0.2.1"),
            network_attachment("port-2", "198.51.100.2", "198.51.100.0/29", "198.51.100.1"),
        ];
        assert!(runtime.validate(&attachments).is_err());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Issue #88 C6a (DEV-1 stale-binding deviation): a create whose DHCP
    /// start fails (the injected `O3K_COMPUTE_DHCP_BINARY` is missing) must
    /// roll back the durable bindings of the ports it added BEFORE the
    /// failed start. Leaving them behind means a later agent restart
    /// re-serves them (#570 live-bindings re-serve), re-creates the bridge,
    /// and spawns an owned dnsmasq for a deleted port — the real-host
    /// observed leak.
    #[test]
    fn failed_dhcp_start_rolls_back_durable_bindings() -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        let attachments = vec![network_attachment(
            "port-1",
            "192.0.2.10",
            "192.0.2.0/24",
            "192.0.2.1",
        )];

        assert!(
            runtime.apply(&attachments).is_err(),
            "the DHCP start must fail with the injected missing binary"
        );

        assert_eq!(
            runtime.service.bindings().count(),
            0,
            "a failed DHCP start must roll back the durable bindings of the added ports"
        );
        assert!(
            runtime.supervisor.is_none(),
            "no supervisor may survive a failed DHCP start"
        );
        // A later restart must not re-serve the rolled-back port.
        assert!(
            runtime.service.binding("port-1").is_none(),
            "the rolled-back port must have no durable binding"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The delete path's DHCP cleanup removes exactly the deleted port's
    /// durable binding and leaves other ports' bindings untouched (the
    /// supervisor is stopped only when the last binding is gone).
    #[test]
    fn delete_cleanup_removes_only_the_ports_durable_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-delete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        runtime.service.configure(o3k_dhcp::DhcpConfig {
            subnet: "192.0.2.0/24".to_owned(),
            gateway: "192.0.2.1".parse()?,
            dns: vec!["192.0.2.1".parse()?],
            interface: "o3k-br0".to_owned(),
            lease_seconds: 3600,
        })?;
        for (port_id, address, mac) in [
            ("port-1", "192.0.2.10", "02:00:00:00:00:01"),
            ("port-2", "192.0.2.11", "02:00:00:00:00:02"),
        ] {
            runtime.service.upsert_binding(o3k_dhcp::Binding {
                port_id: port_id.to_owned(),
                mac: mac.to_owned(),
                address: address.parse()?,
            })?;
        }

        runtime.remove_ports(&["port-1".to_owned()])?;

        assert!(
            runtime.service.binding("port-1").is_none(),
            "the deleted port's durable binding must be removed"
        );
        assert!(
            runtime.service.binding("port-2").is_some(),
            "another port's live binding must survive the delete"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Binding rollback/delete is idempotent: removing an already-absent
    /// binding is a no-op, and repeated rollbacks are safe.
    #[test]
    fn dhcp_binding_rollback_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        runtime.service.configure(o3k_dhcp::DhcpConfig {
            subnet: "192.0.2.0/24".to_owned(),
            gateway: "192.0.2.1".parse()?,
            dns: vec!["192.0.2.1".parse()?],
            interface: "o3k-br0".to_owned(),
            lease_seconds: 3600,
        })?;
        runtime.service.upsert_binding(o3k_dhcp::Binding {
            port_id: "port-1".to_owned(),
            mac: "02:00:00:00:00:01".to_owned(),
            address: "192.0.2.10".parse()?,
        })?;

        runtime.remove_ports(&["port-1".to_owned(), "port-absent".to_owned()])?;
        runtime.remove_ports(&["port-1".to_owned()])?;

        assert_eq!(
            runtime.service.bindings().count(),
            0,
            "removing an absent binding must be a no-op"
        );
        // Once the last binding is gone the flat bridge returns to unbound
        // state, so a later attachment with a different subnet (for example
        // the P15.7 journey network after an earlier lifecycle server was
        // deleted) can bind instead of failing on a stale configuration.
        assert!(
            runtime.service.configuration().is_none(),
            "the bridge must be unbound after the last binding is removed"
        );
        assert!(
            runtime
                .validate(&[proto::NetworkAttachment {
                    port_id: "port-next".to_owned(),
                    mac: "02:00:00:00:00:09".to_owned(),
                    fixed_ipv4: "198.18.0.2".to_owned(),
                    subnet_cidr: "198.18.0.0/29".to_owned(),
                    gateway_ipv4: "198.18.0.1".to_owned(),
                }])
                .is_ok(),
            "a different subnet must be bindable once the bridge is unbound"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Issue #608: `remove_ports` on a DHCP service that was never configured
    /// (the crashed create never wrote dnsmasq.conf) is absent state, not an
    /// error. Nothing can be rendered, reloaded, or stopped — the supervisor
    /// cannot exist without a configuration — and the delete/reap must
    /// continue into TAP and bridge cleanup. The pre-fix code aborted with
    /// "DHCP configuration cleanup failed" (render_config -> InvalidConfig),
    /// which stopped `cleanup_instance_network` before any TAP or bridge
    /// cleanup.
    #[test]
    fn remove_ports_without_configuration_is_absent_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        assert!(runtime.service.configuration().is_none());

        runtime.remove_ports(&["port-1".to_owned()])?;

        assert!(
            runtime.service.bindings().next().is_none(),
            "a never-configured DHCP cannot hold bindings"
        );
        assert!(
            runtime.supervisor.is_none(),
            "no supervisor may exist without a configuration"
        );
        assert!(
            !root.join("dnsmasq.conf").exists(),
            "a never-configured DHCP must not render a config during cleanup"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Issue #608: the instance delete/reap of a never-configured instance
    /// (create crashed before DHCP configuration) must continue through the
    /// DHCP cleanup into TAP and bridge cleanup and reach zero residue. The
    /// manifest is empty, so a successful cleanup issues no host command; the
    /// pre-fix DHCP abort failed here before the TAP and bridge cleanup could
    /// run.
    #[test]
    fn cleanup_of_a_never_configured_instance_reaches_zero_residue()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-never-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dhcp_root = root.join("dhcp");
        let runtime = DhcpRuntime::open(&dhcp_root, "/does/not/exist", "o3k-br0".to_owned())?;
        let dhcp = Arc::new(Mutex::new(runtime));
        let network = o3k_network::HostNetworkManager::with_ownership_root(
            o3k_network::HostNetworkConfig {
                bridge_name: "o3k-br0".to_owned(),
                uplink: None,
            },
            root.join("network"),
        )?;

        cleanup_instance_network(&network, &dhcp, "server-never-configured")?;

        assert!(
            !dhcp_root.join("dnsmasq.conf").exists(),
            "no dnsmasq.conf may be written for a never-configured DHCP"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Startup DHCP reconciliation (issue #87): a DHCP that cannot start at
    /// boot (missing capabilities, port conflict, a host dnsmasq on
    /// 127.0.0.1:53, ...) must be a logged error, never a fatal one — the
    /// agent stays up for control-plane connection and journal replay, and
    /// DHCP is retried on the next restart or the next create. The pre-fix
    /// call site in main() propagated the error out of the process, which
    /// this test pins via the reconciliation seam that main() now calls.
    #[test]
    fn startup_dhcp_failure_is_non_fatal_and_preserves_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-startup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        // Persisted bindings make the restart reconciliation proceed; the
        // binary is irrelevant because the reconciliation fails before any
        // dnsmasq spawn (see the ownership manifest below).
        let mut runtime =
            DhcpRuntime::open(root.join("dhcp"), "/does/not/exist", "o3k-br0".to_owned())?;
        runtime.service.configure(o3k_dhcp::DhcpConfig {
            subnet: "192.0.2.0/24".to_owned(),
            gateway: "192.0.2.1".parse()?,
            dns: vec!["192.0.2.1".parse()?],
            interface: "o3k-br0".to_owned(),
            lease_seconds: 3600,
        })?;
        runtime.service.upsert_binding(o3k_dhcp::Binding {
            port_id: "port-1".to_owned(),
            mac: "02:00:00:00:00:01".to_owned(),
            address: "192.0.2.10".parse()?,
        })?;

        // Pre-seed an ownership manifest recording a different gateway so
        // the reconciliation fails at ensure_gateway (ownership conflict)
        // before any host mutation — the startup-DHCP-cannot-start shape.
        let network_root = root.join("network");
        std::fs::create_dir_all(&network_root)?;
        std::fs::write(
            network_root.join("ownership.json"),
            serde_json::to_vec(&o3k_network::NetworkOwnershipManifest {
                bridge: Some(o3k_network::BridgeOwnership {
                    name: "o3k-br0".to_owned(),
                    uplink: None,
                    created_by_o3k: true,
                    identity: None,
                    gateway: Some(o3k_network::GatewayOwnership {
                        address: "203.0.113.1".parse()?,
                        prefix_len: 24,
                    }),
                }),
                taps: Default::default(),
            })?,
        )?;
        let network = o3k_network::HostNetworkManager::with_ownership_root(
            o3k_network::HostNetworkConfig {
                bridge_name: "o3k-br0".to_owned(),
                uplink: None,
            },
            &network_root,
        )?;

        let dhcp = Arc::new(Mutex::new(runtime));
        let result = reconcile_dhcp_on_startup(&dhcp, &network);
        assert!(
            result.is_err(),
            "a DHCP that cannot start at boot must be a logged, non-fatal failure"
        );
        let error = match result {
            Ok(()) => String::new(),
            Err(error) => error,
        };
        assert!(
            error.contains("DHCP reconciliation failed"),
            "unexpected reconciliation error: {error}"
        );
        let runtime = dhcp.lock().map_err(|_| "DHCP runtime lock is poisoned")?;
        assert!(
            runtime.supervisor.is_none(),
            "no dnsmasq may be spawned when startup reconciliation fails"
        );
        assert_eq!(
            runtime.service.bindings().count(),
            1,
            "durable DHCP state must survive a failed startup reconciliation"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Spawns a real, long-lived fake owned dnsmasq: a shell process whose
    /// argv carries the O3K dhcp-root flags exactly like the supervisor's
    /// `launch()` (`--conf-file=<root>/dnsmasq.conf --pid-file=<root>/<name>`)
    /// so the ownership check passes. TERM runs a trap that kills the
    /// background sleep first, so the reap (or the test cleanup) never
    /// orphans a process.
    #[cfg(unix)]
    fn spawn_fake_owned_dnsmasq(
        root: &std::path::Path,
        pidfile: &str,
    ) -> std::io::Result<std::process::Child> {
        // Keep the shell as the single process with its original argv: the
        // reap's ownership check reads the command line, and a shell that
        // `exec`s away its argv would lose the `--conf-file=<root>/...`
        // marker. The TERM trap is installed as the FIRST statement so the
        // reap's pidfd SIGTERM always finds it, the foreground loop keeps
        // the shell alive until then, the loop is bounded so a fake the
        // reap legitimately skipped cannot outlive the suite, and stdio is
        // detached so an unreaped fake never keeps the test harness's
        // output pipe open (cargo test waits for EOF).
        let child = std::process::Command::new("sh")
            .arg("-c")
            .arg("trap 'exit 0' TERM; n=0; while [ $n -lt 300 ]; do sleep 1; n=$((n+1)); done")
            .arg("dnsmasq")
            .arg(format!("--conf-file={}/dnsmasq.conf", root.display()))
            .arg(format!("--pid-file={}/{}", root.display(), pidfile))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        // Wait for the fork-to-exec window to close: a forked child inherits
        // the parent's address space, so /proc/<pid>/cmdline shows the
        // PARENT's argv until execve() lands — a non-empty check breaks
        // immediately and the reap then reads the parent's argv and skips a
        // live owned fake (the dnsmasq-reap CI flakes). Wait for the exec'd
        // argv marker (the dhcp-root conf-file) instead; on a busy host the
        // exec can lag well beyond a short budget.
        let pid = child.id();
        let expected_marker = format!("--conf-file={}/dnsmasq.conf", root.display());
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
        let mut exec_landed = false;
        while std::time::Instant::now() < deadline {
            if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
                let cmdline = String::from_utf8_lossy(&raw);
                if cmdline.contains(&expected_marker) {
                    exec_landed = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if !exec_landed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fake dnsmasq exec did not land in time",
            ));
        }
        // Record the spawn identity exactly like the production supervisor:
        // the kernel start time of the child, stored next to the pidfile.
        // The reap only signals a process whose start time matches.
        let starttime = o3k_dhcp::process_starttime(pid as i32).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "fake dnsmasq start time unreadable",
            )
        })?;
        std::fs::write(root.join(format!("{pidfile}.owner")), starttime.to_string())?;
        Ok(child)
    }

    /// Issue #88 S3: an agent that crashed after starting dnsmasq leaves the
    /// process running (reparented to init) with zero durable bindings. The
    /// reap is ungated on bindings — at startup the supervisor is always
    /// None, so any owned dnsmasq is a leftover — and must kill it and
    /// remove its pidfile.
    #[cfg(unix)]
    #[test]
    fn reap_owned_dnsmasq_kills_owned_zero_binding_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        let mut owned = spawn_fake_owned_dnsmasq(&root, "dnsmasq-test.pid")?;
        std::fs::write(root.join("dnsmasq-test.pid"), owned.id().to_string())?;
        assert!(
            pid_is_alive(owned.id() as i32),
            "the fake dnsmasq must be running before the reap"
        );

        runtime.reap_owned_dnsmasq()?;

        assert!(
            owned.try_wait()?.is_some(),
            "the owned zero-binding dnsmasq must be killed"
        );
        assert!(
            !root.join("dnsmasq-test.pid").exists(),
            "the reap must remove the pidfile"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The reap is NOT gated on durable bindings (issue #88 S4 Window B): at
    /// startup the supervisor is always None, so an owned dnsmasq is a
    /// leftover of a previous process even when its binding is live — the
    /// process must be killed and its pidfile removed while the durable
    /// binding survives, so `start_after_restart` re-serves it with a fresh
    /// supervisor afterward (asserted at the sequence level).
    #[cfg(unix)]
    #[test]
    fn reap_owned_dnsmasq_kills_owned_process_while_bindings_exist()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        runtime.service.configure(o3k_dhcp::DhcpConfig {
            subnet: "192.0.2.0/24".to_owned(),
            gateway: "192.0.2.1".parse()?,
            dns: vec!["192.0.2.1".parse()?],
            interface: "o3k-br0".to_owned(),
            lease_seconds: 3600,
        })?;
        runtime.service.upsert_binding(o3k_dhcp::Binding {
            port_id: "port-1".to_owned(),
            mac: "02:00:00:00:00:01".to_owned(),
            address: "192.0.2.10".parse()?,
        })?;
        let mut owned = spawn_fake_owned_dnsmasq(&root, "dnsmasq-bound.pid")?;
        std::fs::write(root.join("dnsmasq-bound.pid"), owned.id().to_string())?;

        runtime.reap_owned_dnsmasq()?;

        assert!(
            owned.try_wait()?.is_some(),
            "an owned dnsmasq must be killed at the reap level even while \
             bindings exist — the startup supervisor is always None"
        );
        assert!(
            !root.join("dnsmasq-bound.pid").exists(),
            "the reap must remove the pidfile"
        );
        assert_eq!(
            runtime.service.bindings().count(),
            1,
            "the durable live binding must survive for start_after_restart to re-serve"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// A pidfile whose process is already gone is removed; a pidfile pointing
    /// at a foreign process (cmdline without the O3K dhcp root) and a pidfile
    /// with garbage content are skipped with a warning and left in place
    /// (fail-open: the process inventory and verifier catch residue).
    #[cfg(unix)]
    #[test]
    fn reap_owned_dnsmasq_removes_dead_and_skips_foreign_pidfiles()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-mixed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        // Dead: a pid of an already-exited process.
        let mut dead = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()?;
        let dead_pid = dead.id();
        dead.wait()?;
        std::fs::write(root.join("dnsmasq-dead.pid"), dead_pid.to_string())?;
        // Foreign: a live process whose cmdline lacks the dhcp root.
        let mut foreign = std::process::Command::new("sleep").arg("300").spawn()?;
        std::fs::write(root.join("dnsmasq-foreign.pid"), foreign.id().to_string())?;
        // Garbage: content that cannot be a pid.
        std::fs::write(root.join("dnsmasq-garbage.pid"), "not-a-pid")?;

        runtime.reap_owned_dnsmasq()?;

        assert!(
            !root.join("dnsmasq-dead.pid").exists(),
            "a pidfile whose process is already gone must be removed"
        );
        assert!(
            pid_is_alive(foreign.id() as i32),
            "a foreign process must never be killed"
        );
        assert!(
            root.join("dnsmasq-foreign.pid").exists(),
            "a foreign pidfile must be left for the inventory"
        );
        assert!(
            root.join("dnsmasq-garbage.pid").exists(),
            "an unreadable pidfile must be left for the inventory"
        );
        foreign.kill()?;
        foreign.wait()?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// A same-user process whose argv mimics the O3K dnsmasq command line but
    /// has NO recorded spawn identity is not provably O3K-owned (ASR-013
    /// invariant E): argv similarity alone must never be sufficient authority,
    /// so the reap fails closed and the spoof survives.
    #[cfg(unix)]
    #[test]
    fn reap_skips_argv_spoof_without_recorded_identity() -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-dhcp-spoof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        let mut spoof = spawn_fake_owned_dnsmasq(&root, "dnsmasq-spoof.pid")?;
        std::fs::write(root.join("dnsmasq-spoof.pid"), spoof.id().to_string())?;
        // Remove the recorded identity: the process still matches by argv
        // alone, which must never be sufficient authority for a signal.
        std::fs::remove_file(root.join("dnsmasq-spoof.pid.owner"))?;

        runtime.reap_owned_dnsmasq()?;

        assert!(
            pid_is_alive(spoof.id() as i32),
            "an argv-spoofing process without a recorded identity must survive the reap"
        );
        assert!(
            root.join("dnsmasq-spoof.pid").exists(),
            "an unprovable pidfile must be left for the inventory"
        );
        spoof.kill()?;
        spoof.wait()?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// A process whose kernel start time does not match the recorded spawn
    /// identity — a PID-reuse replacement or a same-user argv spoof started
    /// at a different time — must never be signaled: the reap fails closed
    /// (ASR-013 invariants D and E).
    #[cfg(unix)]
    #[test]
    fn reap_skips_process_with_mismatched_spawn_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let root =
            env::temp_dir().join(format!("o3k-compute-dhcp-mismatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
        let mut spoof = spawn_fake_owned_dnsmasq(&root, "dnsmasq-mismatch.pid")?;
        std::fs::write(root.join("dnsmasq-mismatch.pid"), spoof.id().to_string())?;
        // Corrupt the recorded identity: even with a perfect argv match, the
        // start time mismatch must make the reap skip the process.
        std::fs::write(root.join("dnsmasq-mismatch.pid.owner"), "0")?;

        runtime.reap_owned_dnsmasq()?;

        assert!(
            pid_is_alive(spoof.id() as i32),
            "a process whose start time mismatches the recorded identity must survive"
        );
        assert!(
            root.join("dnsmasq-mismatch.pid").exists(),
            "an identity-mismatched pidfile must be left for the inventory"
        );
        spoof.kill()?;
        spoof.wait()?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The stable-handle semantics that make the O3K signal path race-safe on
    /// a real Linux kernel: once the target exits, `pidfd_send_signal` on the
    /// stale pidfd returns ESRCH and can never be redirected to a later
    /// process that reuses the same numeric PID. This is the same kernel
    /// primitive (`pidfd_open` + `pidfd_send_signal`) the ownership reap uses.
    #[cfg(target_os = "linux")]
    #[test]
    fn stale_pidfd_never_retargets_a_reused_numeric_pid() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut victim = std::process::Command::new("sleep").arg("60").spawn()?;
        let numeric_pid = Pid::from_raw(victim.id() as i32)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid pid"))?;
        let pidfd = pidfd_open(numeric_pid, PidfdFlags::empty()).map_err(std::io::Error::from)?;
        victim.kill()?;
        victim.wait()?;
        // The handle is now stale: signaling through it must fail with ESRCH
        // (the process is gone), never deliver to anything else.
        let signal_error = match pidfd_send_signal(&pidfd, Signal::Term) {
            Ok(()) => {
                return Err(std::io::Error::other(
                    "signaling a stale pidfd unexpectedly succeeded",
                )
                .into());
            }
            Err(error) => error,
        };
        assert_eq!(
            signal_error,
            rustix::io::Errno::SRCH,
            "a stale pidfd must report ESRCH, got {signal_error}"
        );
        // Aggressively churn numeric PIDs: every replacement process must
        // survive — the stale handle cannot retarget any of them.
        let mut replacements = Vec::new();
        for _ in 0..64 {
            replacements.push(
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg("sleep 0.05")
                    .spawn()?,
            );
        }
        for mut replacement in replacements {
            let status = replacement.wait()?;
            assert!(
                status.success(),
                "a replacement process must never be signaled"
            );
        }
        Ok(())
    }

    /// Race stress over the ownership reap (ASR-013 section 8): 100 iterations
    /// with the owned process killed at varied points relative to the reap
    /// window. Required outcome on every iteration: the owned process is
    /// terminated exactly once (by the reap, or already dead), no watcher
    /// process is ever signaled, and the pidfile/identity pair is removed.
    #[cfg(unix)]
    #[test]
    fn reap_stress_never_signals_unowned_processes() -> Result<(), Box<dyn std::error::Error>> {
        for iteration in 0..100 {
            let root = env::temp_dir().join(format!(
                "o3k-compute-dhcp-stress-{}-{}",
                std::process::id(),
                iteration
            ));
            let _ = std::fs::remove_dir_all(&root);
            let runtime = DhcpRuntime::open(&root, "/does/not/exist", "o3k-br0".to_owned())?;
            // A watcher with a deliberately dnsmasq-shaped but NOT O3K-owned
            // argv (no dhcp root, no identity file): it must never receive a
            // signal from the reap.
            let mut watcher = std::process::Command::new("sh")
                .arg("-c")
                .arg("n=0; while [ $n -lt 60 ]; do sleep 0.1; n=$((n+1)); done")
                .arg("dnsmasq")
                .arg("--conf-file=/nonexistent/dnsmasq.conf")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let mut owned = spawn_fake_owned_dnsmasq(&root, "dnsmasq-stress.pid")?;
            std::fs::write(root.join("dnsmasq-stress.pid"), owned.id().to_string())?;
            match iteration % 4 {
                // The owned process exits before the reap runs.
                0 | 1 => {
                    owned.kill()?;
                    owned.wait()?;
                }
                // The owned process exits concurrently with the reap window
                // (short delay: usually lands before pidfd acquisition, but
                // the reap must be safe in every interleaving).
                2 => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    owned.kill()?;
                    owned.wait()?;
                }
                // The owned process is still alive when the reap runs.
                _ => {}
            }
            runtime.reap_owned_dnsmasq()?;
            assert!(
                pid_is_alive(watcher.id() as i32),
                "iteration {iteration}: the watcher process must never be signaled"
            );
            // The owned process must be terminated — by the test kill
            // (iterations 0-2, before the reap) or by the reap itself
            // (iteration 3, SIGTERM through the pidfd and the TERM trap).
            let mut status = owned.try_wait()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while status.is_none() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(10));
                status = owned.try_wait()?;
            }
            assert!(
                status.is_some(),
                "iteration {iteration}: the owned process must be terminated by the reap \
                 (alive={}, cmdline={:?}, pidfile={:?}, identity={:?}, starttime_now={:?}, starttime_recorded={:?})",
                pid_is_alive(owned.id() as i32),
                std::fs::read(format!("/proc/{}/cmdline", owned.id())).ok(),
                std::fs::read_to_string(root.join("dnsmasq-stress.pid")).ok(),
                std::fs::read_to_string(root.join("dnsmasq-stress.pid.owner")).ok(),
                o3k_dhcp::process_starttime(owned.id() as i32),
                std::fs::read_to_string(root.join("dnsmasq-stress.pid.owner"))
                    .ok()
                    .and_then(|raw| raw.trim().parse::<u64>().ok()),
            );
            if status.is_none() {
                let _ = owned.kill();
                let _ = owned.wait();
            }
            assert!(
                !root.join("dnsmasq-stress.pid").exists(),
                "iteration {iteration}: the pidfile must be removed"
            );
            assert!(
                !root.join("dnsmasq-stress.pid.owner").exists(),
                "iteration {iteration}: the identity file must be removed"
            );
            watcher.kill()?;
            watcher.wait()?;
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    /// Fake domain-presence probe for the startup residue sequence tests:
    /// the bin's default test build has no libvirt feature, so the real
    /// adapter can never produce the absent (`NotFound`) classification.
    struct FakeDomainPresence {
        absent: bool,
    }

    #[async_trait]
    impl DomainPresence for FakeDomainPresence {
        async fn domain_is_absent(&self, _name: &str) -> Result<bool, AgentError> {
            Ok(self.absent)
        }
    }

    /// Builds the S3-shaped startup fixture: durable DHCP state (config plus
    /// the binding of `port_id`, exactly as the crash leaves it — DHCP prep
    /// completed before the kill), an owned-manifest TAP record binding the
    /// port to `instance_id` (no bridge/gateway records, so the
    /// manifest-only cleanup path is deterministic without kernel
    /// interfaces), and a live fake owned dnsmasq with its pidfile.
    #[cfg(unix)]
    #[allow(clippy::type_complexity)]
    fn startup_residue_fixture(
        root: &std::path::Path,
        instance_id: &str,
        port_id: &str,
        pidfile: &str,
    ) -> Result<
        (
            Arc<Mutex<DhcpRuntime>>,
            o3k_network::HostNetworkManager,
            std::process::Child,
        ),
        Box<dyn std::error::Error>,
    > {
        let dhcp_root = root.join("dhcp");
        let mut runtime = DhcpRuntime::open(&dhcp_root, "/does/not/exist", "o3k-br0".to_owned())?;
        runtime.service.configure(o3k_dhcp::DhcpConfig {
            subnet: "192.0.2.0/24".to_owned(),
            gateway: "192.0.2.1".parse()?,
            dns: vec!["192.0.2.1".parse()?],
            interface: "o3k-br0".to_owned(),
            lease_seconds: 3600,
        })?;
        runtime.service.upsert_binding(o3k_dhcp::Binding {
            port_id: port_id.to_owned(),
            mac: "02:00:00:00:00:01".to_owned(),
            address: "192.0.2.10".parse()?,
        })?;
        let owned = spawn_fake_owned_dnsmasq(&dhcp_root, pidfile)?;
        std::fs::write(dhcp_root.join(pidfile), owned.id().to_string())?;
        let tap_interface = o3k_network::HostNetworkManager::tap_name(port_id)?;
        let network_root = root.join("network");
        std::fs::create_dir_all(&network_root)?;
        std::fs::write(
            network_root.join("ownership.json"),
            serde_json::to_vec(&o3k_network::NetworkOwnershipManifest {
                bridge: None,
                taps: std::collections::BTreeMap::from([(
                    tap_interface.clone(),
                    o3k_network::TapOwnership {
                        interface: tap_interface,
                        instance_id: instance_id.to_owned(),
                        port_id: port_id.to_owned(),
                        mac: "02:00:00:00:00:01".to_owned(),
                        bridge: "o3k-br0".to_owned(),
                        created_by_o3k: true,
                    },
                )]),
            })?,
        )?;
        let network = o3k_network::HostNetworkManager::with_ownership_root(
            o3k_network::HostNetworkConfig {
                bridge_name: "o3k-br0".to_owned(),
                uplink: None,
            },
            &network_root,
        )?;
        Ok((Arc::new(Mutex::new(runtime)), network, owned))
    }

    /// Issue #88 S3 rerun (PR #569): a create whose DHCP prep completed
    /// before the agent crash leaves a PERSISTED durable binding; the
    /// orphaned dnsmasq (reparented to init) keeps running. The startup
    /// residue sequence must remove the stale binding FIRST (the
    /// stale-network reap of the absent domain) and only THEN run the
    /// zero-binding orphan reap — running the reap before the binding
    /// removal would gate on the stale binding and leave the process running
    /// forever (the real-host rerun caught exactly this: owned dnsmasq leak,
    /// pid 53279). This test drives the exact startup sequence function
    /// (`reap_startup_residue`) with a fake absent-domain presence probe.
    #[cfg(unix)]
    #[tokio::test]
    async fn startup_residue_reaps_dnsmasq_of_stale_bound_absent_instance()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!(
            "o3k-compute-startup-residue-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let (dhcp, network, mut owned) =
            startup_residue_fixture(&root, "instance-absent-1", "port-1", "dnsmasq-crashed.pid")?;
        assert!(
            pid_is_alive(owned.id() as i32),
            "the orphaned dnsmasq must be running before the sequence"
        );

        reap_startup_residue(&network, &dhcp, &FakeDomainPresence { absent: true }).await?;

        assert!(
            owned.try_wait()?.is_some(),
            "the orphaned dnsmasq of a stale-bound absent instance must be killed"
        );
        assert!(
            !root.join("dhcp/dnsmasq-crashed.pid").exists(),
            "the reap must remove the pidfile"
        );
        assert_eq!(
            dhcp.lock()
                .map_err(|_| "DHCP runtime lock is poisoned")?
                .service
                .bindings()
                .count(),
            0,
            "the stale binding of the absent instance must be removed by the sequence"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// A binding whose instance is still present (the domain exists) is NOT
    /// removed by the stale-network reap, but the startup residue reap still
    /// kills the owned dnsmasq: at startup the supervisor is always None, so
    /// every owned dnsmasq is a leftover of a previous process regardless of
    /// bindings (issue #88 S4 Window B — the live-bound orphan held the DHCP
    /// socket and blocked the fresh supervisor). The durable live binding
    /// survives and `start_after_restart` re-serves it afterward.
    #[cfg(unix)]
    #[tokio::test]
    async fn startup_residue_reaps_dnsmasq_of_live_bound_instance()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-startup-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (dhcp, network, mut owned) =
            startup_residue_fixture(&root, "instance-live-1", "port-1", "dnsmasq-live.pid")?;

        reap_startup_residue(&network, &dhcp, &FakeDomainPresence { absent: false }).await?;

        assert!(
            owned.try_wait()?.is_some(),
            "the owned dnsmasq of a live-bound instance must be killed by the \
             startup residue reap — the supervisor is None at startup, and \
             start_after_restart re-serves the live binding afterward"
        );
        assert!(
            !root.join("dhcp/dnsmasq-live.pid").exists(),
            "the reap must remove the pidfile"
        );
        assert_eq!(
            dhcp.lock()
                .map_err(|_| "DHCP runtime lock is poisoned")?
                .service
                .bindings()
                .count(),
            1,
            "the live durable binding must survive for start_after_restart to re-serve"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn create_fails_closed_when_transfer_and_tap_ownership_are_not_resolvable() {
        let command = proto::Command {
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                image_id: "image".to_owned(),
                flavor_id: "flavor".to_owned(),
                network_port_ids: vec!["port-1".to_owned()],
                resolved: Some(proto::ResolvedCreateInputs {
                    image_artifact_id: "image-artifact".to_owned(),
                    image_sha256: "a".repeat(64),
                    image_format: "qcow2".to_owned(),
                    vcpus: 1,
                    memory_mib: 512,
                    disk_gib: 1,
                    config_drive_artifact_id: "config-artifact".to_owned(),
                    config_drive_sha256: "b".repeat(64),
                    image_transfer: None,
                    config_drive_transfer: None,
                    project_id: "project-1".to_owned(),
                    network_attachments: vec![proto::NetworkAttachment {
                        port_id: "port-1".to_owned(),
                        mac: "02:00:00:00:00:01".to_owned(),
                        fixed_ipv4: "192.0.2.10".to_owned(),
                        subnet_cidr: String::new(),
                        gateway_ipv4: String::new(),
                    }],
                }),
            })),
            ..Default::default()
        };

        let result = resolve_create_domain_spec(&command, None);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.to_string().contains("committed artifact bytes"));
            assert!(error.to_string().contains("owned TAP names"));
        }
    }

    #[test]
    fn create_rejects_missing_resolved_artifacts_before_any_host_lookup() {
        let command = proto::Command {
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    image_artifact_id: String::new(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };

        let result = resolve_create_domain_spec(&command, None);
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(
                error
                    .to_string()
                    .contains("artifact references are incomplete")
            );
        }
    }

    /// Issue #606 agent-side capacity backstop: an over-capacity create is
    /// classified `Capacity` (the same durable category the placement gate
    /// produces) and the guard that produces it is a pure protobuf read, so
    /// no TAP, bridge, overlay, or domain can exist when it fires.
    #[test]
    fn over_capacity_create_is_rejected_with_capacity_classification() {
        let mut command = proto::Command {
            command_id: "command-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            resource_id: "server-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                image_id: "image".to_owned(),
                flavor_id: "flavor".to_owned(),
                network_port_ids: vec!["port-1".to_owned()],
                resolved: Some(proto::ResolvedCreateInputs {
                    image_artifact_id: "image-artifact".to_owned(),
                    image_sha256: "a".repeat(64),
                    image_format: "qcow2".to_owned(),
                    vcpus: 1,
                    memory_mib: 512,
                    disk_gib: 10,
                    config_drive_artifact_id: "config-artifact".to_owned(),
                    config_drive_sha256: "b".repeat(64),
                    project_id: "project-1".to_owned(),
                    network_attachments: vec![network_attachment("port-1", "192.0.2.10", "", "")],
                    ..Default::default()
                }),
            })),
            ..Default::default()
        };
        assert_eq!(create_disk_gib(&command), Some(10));

        let result = capacity_failure_result(10, 1);
        assert_eq!(result.state, proto::OperationState::Failed as i32);
        assert_eq!(
            result.error_category,
            proto::ErrorCategory::Capacity as i32,
            "the agent-side rejection must carry the capacity classification"
        );
        assert_eq!(result.resource_state, proto::ResourceState::Error as i32);
        assert!(
            result.provider_resource_id.is_empty(),
            "a pre-mutation rejection must reference no provider resource"
        );
        assert!(result.redacted_message.contains("10 GiB"));
        assert!(result.redacted_message.contains("1 GiB"));

        // A within-capacity demand stays under the configured ceiling.
        if let Some(proto::command::Action::Create(create)) = command.action.as_mut()
            && let Some(resolved) = create.resolved.as_mut()
        {
            resolved.disk_gib = 1;
        }
        assert_eq!(create_disk_gib(&command), Some(1));

        // Non-create commands have no resolved disk demand.
        command.action = Some(proto::command::Action::Inspect(proto::InspectCommand {}));
        assert_eq!(create_disk_gib(&command), None);
        let unresolved = proto::Command {
            action: Some(proto::command::Action::Create(
                proto::CreateCommand::default(),
            )),
            ..Default::default()
        };
        assert_eq!(create_disk_gib(&unresolved), None);
    }

    #[test]
    fn typed_contract_rejects_artifact_identity_mismatch() {
        let command = proto::Command {
            command_id: "command-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            resource_id: "server-1".to_owned(),
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    image_artifact_id: "image-artifact".to_owned(),
                    image_sha256: "a".repeat(64),
                    image_format: "qcow2".to_owned(),
                    vcpus: 1,
                    memory_mib: 512,
                    config_drive_artifact_id: "config-artifact".to_owned(),
                    config_drive_sha256: "b".repeat(64),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let committed = CommittedCreateInputs {
            image: CommittedArtifact {
                artifact_id: "different-image".to_owned(),
                kind: proto::ArtifactKind::ImageBase,
                format: "qcow2".to_owned(),
                sha256: "a".repeat(64),
                path: PathBuf::from("/var/lib/o3k/artifacts/image.qcow2"),
            },
            config_drive: CommittedArtifact {
                artifact_id: "config-artifact".to_owned(),
                kind: proto::ArtifactKind::ConfigDriveIso,
                format: "iso".to_owned(),
                sha256: "b".repeat(64),
                path: PathBuf::from("/var/lib/o3k/artifacts/config.iso"),
            },
            owned_taps: Vec::new(),
            identity: CreateDomainIdentity {
                server_id: "server-1".to_owned(),
                project_id: "project-1".to_owned(),
                generation: 1,
                operation_id: "operation-1".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
        };

        let result = resolve_create_domain_spec(&command, Some(&committed));
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.to_string().contains("does not match"));
        }
    }

    #[test]
    fn typed_contract_rejects_unowned_tap_even_with_matching_port_data() {
        let command = proto::Command {
            command_id: "command-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            resource_id: "server-1".to_owned(),
            action: Some(proto::command::Action::Create(proto::CreateCommand {
                resolved: Some(proto::ResolvedCreateInputs {
                    image_artifact_id: "image-artifact".to_owned(),
                    image_sha256: "a".repeat(64),
                    image_format: "qcow2".to_owned(),
                    vcpus: 1,
                    memory_mib: 512,
                    config_drive_artifact_id: "config-artifact".to_owned(),
                    config_drive_sha256: "b".repeat(64),
                    network_attachments: vec![proto::NetworkAttachment {
                        port_id: "port-1".to_owned(),
                        mac: "02:00:00:00:00:01".to_owned(),
                        fixed_ipv4: "192.0.2.10".to_owned(),
                        subnet_cidr: String::new(),
                        gateway_ipv4: String::new(),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let committed = CommittedCreateInputs {
            image: CommittedArtifact {
                artifact_id: "image-artifact".to_owned(),
                kind: proto::ArtifactKind::ImageBase,
                format: "qcow2".to_owned(),
                sha256: "a".repeat(64),
                path: PathBuf::from("/var/lib/o3k/artifacts/image.qcow2"),
            },
            config_drive: CommittedArtifact {
                artifact_id: "config-artifact".to_owned(),
                kind: proto::ArtifactKind::ConfigDriveIso,
                format: "iso".to_owned(),
                sha256: "b".repeat(64),
                path: PathBuf::from("/var/lib/o3k/artifacts/config.iso"),
            },
            owned_taps: vec![OwnedTap {
                port_id: "port-1".to_owned(),
                tap_name: "o3ktap-port1".to_owned(),
                mac_address: "02:00:00:00:00:01".to_owned(),
                ownership_token: String::new(),
            }],
            identity: CreateDomainIdentity {
                server_id: "server-1".to_owned(),
                project_id: "project-1".to_owned(),
                generation: 1,
                operation_id: "operation-1".to_owned(),
                managed_by: "o3k-compute".to_owned(),
            },
        };

        let result = resolve_create_domain_spec(&command, Some(&committed));
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.to_string().contains("owned TAP evidence"));
        }
    }

    /// Commits an artifact through the same store API the agent's transfer
    /// protocol uses, returning its transfer id so tests can assert on the
    /// durable manifest. Content is a single 4-byte chunk; the digest
    /// constants are precomputed sha256 values of the fixed contents.
    fn commit_artifact(
        root: &std::path::Path,
        resource_id: &str,
        artifact_id: &str,
        kind: proto::ArtifactKind,
        format: &str,
        content: &[u8],
        sha256: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let store = ArtifactStore::open(root, "agent-1")?;
        let transfer_id = format!("transfer-{resource_id}-{artifact_id}");
        let offer = proto::ArtifactOffer {
            transfer_id: transfer_id.clone(),
            command_id: format!("command-{resource_id}"),
            operation_id: format!("operation-{resource_id}"),
            resource_id: resource_id.to_owned(),
            agent_id: "agent-1".to_owned(),
            artifact_id: artifact_id.to_owned(),
            kind: kind as i32,
            sha256: sha256.to_owned(),
            size_bytes: content.len() as u64,
            format: format.to_owned(),
            chunk_size_bytes: 4,
            chunk_count: content.len().div_ceil(4) as u32,
            expires_at_unix_ms: i64::MAX,
        };
        store.begin(&offer)?;
        store.accept_chunk(
            &offer,
            &proto::ArtifactChunk {
                transfer_id: offer.transfer_id.clone(),
                chunk_index: 0,
                offset_bytes: 0,
                data: content.to_vec(),
                chunk_sha256: sha256.to_owned(),
            },
        )?;
        store.finish(
            &offer,
            &proto::ArtifactEnd {
                transfer_id: offer.transfer_id.clone(),
                sha256: sha256.to_owned(),
                size_bytes: content.len() as u64,
            },
        )?;
        Ok(transfer_id)
    }

    /// The delete executor's config-drive reaping seam: executing the cleanup
    /// for a deleted resource removes its committed ConfigDriveIso manifest
    /// and the content-addressed final file when this manifest was its last
    /// reference, while manifests and finals of other resources and of the
    /// shared image base remain. This is the exact function the libvirt
    /// delete arm calls after the host mutation cleanup.
    #[test]
    fn config_drive_delete_cleanup_removes_owned_manifests_and_finals()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-cd-delete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let config_transfer = commit_artifact(
            &root,
            "resource-1",
            "config-1",
            proto::ArtifactKind::ConfigDriveIso,
            "iso",
            b"1111",
            "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c",
        )?;
        let image_transfer = commit_artifact(
            &root,
            "resource-1",
            "image-1",
            proto::ArtifactKind::ImageBase,
            "qcow2",
            b"2222",
            "edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9",
        )?;
        let other_transfer = commit_artifact(
            &root,
            "resource-2",
            "config-1",
            proto::ArtifactKind::ConfigDriveIso,
            "iso",
            b"3333",
            "318aee3fed8c9d040d35a7fc1fa776fb31303833aa2de885354ddf3d44d8fb69",
        )?;

        cleanup_config_drive_artifact(&root, "agent-1", "resource-1")?;

        assert!(
            !root.join(format!(".{config_transfer}.manifest")).exists(),
            "the deleted resource's config-drive manifest must be removed"
        );
        assert!(
            !root
                .join("0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c.iso")
                .exists(),
            "the config-drive final must be removed when this manifest was its \
             last reference"
        );
        assert!(
            root.join(format!(".{image_transfer}.manifest")).exists(),
            "the image-base manifest must be preserved"
        );
        assert!(
            root.join("edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9.qcow2")
                .exists(),
            "the shared image-base final must be preserved"
        );
        assert!(
            root.join(format!(".{other_transfer}.manifest")).exists(),
            "a resource that was not deleted keeps its config-drive manifest"
        );
        assert!(
            root.join("318aee3fed8c9d040d35a7fc1fa776fb31303833aa2de885354ddf3d44d8fb69.iso")
                .exists(),
            "a resource that was not deleted keeps its config-drive final"
        );
        cleanup_config_drive_artifact(&root, "agent-1", "resource-1")?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The create executor's definitive-failure path: a create that failed
    /// before libvirt could define the domain is terminal and absence-proven
    /// (the control plane completes the delete locally without dispatching an
    /// agent delete), so the resource's committed config-drive transfer state
    /// must be reaped. Manifests and finals of resources whose create did not
    /// fail stay untouched, and a replayed definitive failure is idempotent.
    /// Unknown-outcome failures never reach this builder (the framework
    /// converts `Err` executions at
    /// `crates/o3k-compute-agent/src/lib.rs` ~4104), so a retried create
    /// still finds its committed manifests.
    #[test]
    fn definitive_create_failure_reaps_owned_config_drive_manifests()
    -> Result<(), Box<dyn std::error::Error>> {
        let root =
            env::temp_dir().join(format!("o3k-compute-cd-definitive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let failed_transfer = commit_artifact(
            &root,
            "resource-1",
            "config-1",
            proto::ArtifactKind::ConfigDriveIso,
            "iso",
            b"1111",
            "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c",
        )?;
        let live_transfer = commit_artifact(
            &root,
            "resource-2",
            "config-1",
            proto::ArtifactKind::ConfigDriveIso,
            "iso",
            b"3333",
            "318aee3fed8c9d040d35a7fc1fa776fb31303833aa2de885354ddf3d44d8fb69",
        )?;

        // The d0f263ee/44e1fa48 shape: "DHCP start failed" before libvirt
        // define, reported as a definitive terminal failure.
        let result = definitive_create_failure_result(
            &root,
            "agent-1",
            "resource-1",
            "operation-1",
            AgentError::Protocol("DHCP start failed".to_owned()),
        )?;
        assert_eq!(result.state, proto::OperationState::Failed as i32);
        assert_eq!(
            result.error_category,
            proto::ErrorCategory::NotFound as i32,
            "a definitive pre-libvirt failure must stay absence-proven"
        );
        assert!(
            !root.join(format!(".{failed_transfer}.manifest")).exists(),
            "the definitively failed create's config-drive manifest must be reaped"
        );
        assert!(
            !root
                .join("0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c.iso")
                .exists(),
            "the definitively failed create's config-drive final must be reaped"
        );
        assert!(
            root.join(format!(".{live_transfer}.manifest")).exists(),
            "a create that did not fail keeps its config-drive manifest"
        );
        assert!(
            root.join("318aee3fed8c9d040d35a7fc1fa776fb31303833aa2de885354ddf3d44d8fb69.iso")
                .exists(),
            "a create that did not fail keeps its config-drive final"
        );

        // A replayed definitive failure is idempotent.
        definitive_create_failure_result(
            &root,
            "agent-1",
            "resource-1",
            "operation-1",
            AgentError::Protocol("instance image overlay could not be realized".to_owned()),
        )?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// A config-drive cleanup failure must never turn a successful delete
    /// into a failed or unknown command outcome: the delete executor calls
    /// the best-effort seam, which logs and continues. A poisoned (symlinked)
    /// manifest makes the store fail closed without deleting anything.
    #[cfg(unix)]
    #[test]
    fn config_drive_delete_cleanup_is_best_effort_when_the_store_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = env::temp_dir().join(format!("o3k-compute-cd-soft-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let transfer = commit_artifact(
            &root,
            "resource-1",
            "config-1",
            proto::ArtifactKind::ConfigDriveIso,
            "iso",
            b"1111",
            "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c",
        )?;
        let manifest = root.join(format!(".{transfer}.manifest"));
        let outside = root.join("outside");
        std::fs::write(&outside, b"foreign")?;
        std::fs::remove_file(&manifest)?;
        symlink(&outside, &manifest)?;

        reap_config_drive_artifacts(&root, "agent-1", "resource-1");
        assert!(
            manifest.is_symlink(),
            "the poisoned manifest must be preserved by the fail-closed store"
        );
        assert!(
            root.join("0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c.iso")
                .exists(),
            "nothing may be deleted while the ownership unit is unverified"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn unix_ms_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Begins an incomplete transfer and receives one chunk, leaving the
    /// store exactly as a crash mid-receipt does: a Receiving manifest plus
    /// a `.part` carrying the content. Returns the transfer id.
    #[allow(clippy::too_many_arguments)]
    fn begin_incomplete_transfer(
        root: &std::path::Path,
        resource_id: &str,
        artifact_id: &str,
        kind: proto::ArtifactKind,
        format: &str,
        content: &[u8],
        sha256: &str,
        expires_at_unix_ms: i64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let store = ArtifactStore::open(root, "agent-1")?;
        let transfer_id = format!("transfer-{resource_id}-{artifact_id}");
        let offer = proto::ArtifactOffer {
            transfer_id: transfer_id.clone(),
            command_id: format!("command-{resource_id}"),
            operation_id: format!("operation-{resource_id}"),
            resource_id: resource_id.to_owned(),
            agent_id: "agent-1".to_owned(),
            artifact_id: artifact_id.to_owned(),
            kind: kind as i32,
            sha256: sha256.to_owned(),
            size_bytes: content.len() as u64,
            format: format.to_owned(),
            chunk_size_bytes: 4,
            chunk_count: content.len().div_ceil(4) as u32,
            expires_at_unix_ms,
        };
        store.begin(&offer)?;
        store.accept_chunk(
            &offer,
            &proto::ArtifactChunk {
                transfer_id: offer.transfer_id.clone(),
                chunk_index: 0,
                offset_bytes: 0,
                data: content.to_vec(),
                chunk_sha256: sha256.to_owned(),
            },
        )?;
        Ok(transfer_id)
    }

    /// Issue #88 S5 supplementary: an agent killed mid artifact-transfer
    /// receipt leaves its `.{id}.part` behind; the control plane expires the
    /// abandoned transfer row (#571) and never resumes it, so the part is
    /// orphaned. The startup reap must remove exactly the unresumable parts:
    /// a part with no manifest (`begin` always writes the manifest before
    /// creating the part) and a part whose manifest is not committed and
    /// whose offer has expired. Parts of NON-expired incomplete transfers
    /// are kept — the control plane resumes the SAME transfer id after
    /// reconnect and `begin` continues the part — and committed manifests
    /// with their content-addressed finals are never touched.
    #[test]
    fn startup_reap_removes_only_unresumable_transfer_parts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-part-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // Committed transfer: manifest + content-addressed final, no part.
        let committed = commit_artifact(
            &root,
            "resource-c",
            "image-c",
            proto::ArtifactKind::ImageBase,
            "qcow2",
            b"1111",
            "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c",
        )?;
        // Non-expired incomplete transfer: resumable after reconnect.
        let live = begin_incomplete_transfer(
            &root,
            "resource-l",
            "image-l",
            proto::ArtifactKind::ImageBase,
            "qcow2",
            b"2222",
            "edee29f882543b956620b26d0ee0e7e950399b1c4222f5de05e06425b4c995e9",
            unix_ms_now() + 60_000,
        )?;
        // Expired incomplete transfer: never resumed, the S5 shape.
        let expired = begin_incomplete_transfer(
            &root,
            "resource-e",
            "image-e",
            proto::ArtifactKind::ImageBase,
            "qcow2",
            b"3333",
            "318aee3fed8c9d040d35a7fc1fa776fb31303833aa2de885354ddf3d44d8fb69",
            // Keep enough admission headroom for the full parallel suite;
            // the transfer must expire only after it has been created.
            unix_ms_now() + 1_000,
        )?;
        // Part with no manifest: nothing references it.
        std::fs::write(root.join(".orphan-1.part"), b"orphan")?;
        // Let the near-future offer expire before the reap runs.
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        reap_orphaned_transfer_parts(&root, "agent-1", None);

        assert!(
            !root.join(format!(".{expired}.part")).exists(),
            "the part of an expired incomplete transfer must be removed"
        );
        assert!(
            !root.join(".orphan-1.part").exists(),
            "a part with no manifest must be removed"
        );
        assert!(
            root.join(format!(".{live}.part")).exists(),
            "the part of a non-expired incomplete transfer must be kept: the \
             protocol resumes the same transfer id after reconnect"
        );
        assert!(
            root.join(format!(".{committed}.manifest")).exists(),
            "the committed manifest must be untouched"
        );
        assert!(
            root.join("0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c.qcow2")
                .exists(),
            "the committed content-addressed final must be untouched"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// The delete executor's transfer-part reaping seam: the resource-scoped
    /// reap removes exactly the deleted resource's unresumable parts and
    /// preserves every other resource's parts (live and orphaned — those
    /// belong to the restart-time global reap) and all manifests.
    #[test]
    fn delete_scoped_part_reap_removes_only_the_resources_orphans()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = env::temp_dir().join(format!("o3k-compute-part-delete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // resource-a: an expired incomplete transfer (the S5 shape, to be
        // deleted).
        let deleted = begin_incomplete_transfer(
            &root,
            "resource-a",
            "image-a",
            proto::ArtifactKind::ImageBase,
            "qcow2",
            b"4444",
            "79f06f8fde333461739f220090a23cb2a79f6d714bee100d0e4b4af249294619",
            // Keep enough admission headroom for the full parallel suite;
            // the transfer must expire only after it has been created.
            unix_ms_now() + 1_000,
        )?;
        // resource-b: a live (resumable) incomplete transfer.
        let preserved_live = begin_incomplete_transfer(
            &root,
            "resource-b",
            "image-b",
            proto::ArtifactKind::ImageBase,
            "qcow2",
            b"5555",
            "c1f330d0aff31c1c87403f1e4347bcc21aff7c179908723535f2b31723702525",
            unix_ms_now() + 60_000,
        )?;
        // resource-b: a committed transfer.
        let preserved_committed = commit_artifact(
            &root,
            "resource-b",
            "config-b",
            proto::ArtifactKind::ConfigDriveIso,
            "iso",
            b"1111",
            "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(1_100));

        reap_orphaned_transfer_parts(&root, "agent-1", Some("resource-a"));

        assert!(
            !root.join(format!(".{deleted}.part")).exists(),
            "the deleted resource's unresumable part must be removed"
        );
        assert!(
            root.join(format!(".{deleted}.manifest")).exists(),
            "manifests are never removed by the part reap"
        );
        assert!(
            root.join(format!(".{preserved_live}.part")).exists(),
            "another resource's live part must be preserved"
        );
        assert!(
            root.join(format!(".{preserved_committed}.manifest"))
                .exists(),
            "another resource's committed manifest must be preserved"
        );
        assert!(
            root.join("0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c.iso")
                .exists(),
            "another resource's committed final must be preserved"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    /// Startup restoration (issue #613 blocker A): a host reboot leaves every
    /// qemu domain defined but inactive; the restore pass must start exactly
    /// the owned domains whose last lifecycle mutation recorded a running
    /// outcome, and leave absent/stopped/deleted resources alone. A reboot
    /// also deletes the ephemeral TAP devices, so the pass must restore the
    /// recorded TAPs BEFORE the domain start and hold the start back when a
    /// TAP restoration fails closed.
    struct StartupEvents {
        log: std::sync::Mutex<Vec<String>>,
    }

    impl StartupEvents {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                log: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn push(&self, event: String) {
            let _ = self.log.lock().map(|mut log| log.push(event));
        }

        fn snapshot(&self) -> Vec<String> {
            self.log.lock().map(|log| log.clone()).unwrap_or_default()
        }
    }

    struct FakeStartupDomainRestore {
        restored: std::sync::Mutex<Vec<String>>,
        fails_before_start: std::sync::atomic::AtomicUsize,
        events: Arc<StartupEvents>,
    }

    impl FakeStartupDomainRestore {
        fn new(fails_before_start: usize) -> Self {
            Self::with_events(fails_before_start, StartupEvents::new())
        }

        fn with_events(fails_before_start: usize, events: Arc<StartupEvents>) -> Self {
            Self {
                restored: std::sync::Mutex::new(Vec::new()),
                fails_before_start: std::sync::atomic::AtomicUsize::new(fails_before_start),
                events,
            }
        }

        fn restored_ids(&self) -> Vec<String> {
            self.restored
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default()
        }
    }

    #[async_trait]
    impl StartupDomainRestore for FakeStartupDomainRestore {
        async fn restore_owned_domain(&self, resource_id: &str) -> Result<bool, AgentError> {
            self.events.push(format!("domain:{resource_id}"));
            let remaining = self
                .fails_before_start
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |value| (value > 0).then(|| value - 1),
                )
                .unwrap_or(0);
            if remaining > 0 {
                return Err(AgentError::Protocol("injected restore failure".to_owned()));
            }
            self.restored
                .lock()
                .map(|mut guard| guard.push(resource_id.to_owned()))
                .map_err(|_| AgentError::Protocol("restore lock is poisoned".to_owned()))?;
            Ok(true)
        }
    }

    struct FakeStartupTapRestore {
        failures: std::sync::Mutex<std::collections::HashMap<String, usize>>,
        events: Arc<StartupEvents>,
    }

    impl FakeStartupTapRestore {
        fn new() -> Self {
            Self::with_events(StartupEvents::new())
        }

        fn with_events(events: Arc<StartupEvents>) -> Self {
            Self {
                failures: std::sync::Mutex::new(std::collections::HashMap::new()),
                events,
            }
        }

        /// Injects `remaining` consecutive TAP restoration failures for one
        /// resource, modeling an unknown outcome or a foreign interface at
        /// the recorded name.
        fn set_failures(&self, resource_id: &str, remaining: usize) {
            let _ = self
                .failures
                .lock()
                .map(|mut failures| failures.insert(resource_id.to_owned(), remaining));
        }

        /// Wires a foreign link at the recorded TAP name for one resource:
        /// every restoration fails closed, so the instance's domain start is
        /// held back forever. The zero-mutation command behavior of the real
        /// manager is proven in the network crate's command-fake tests.
        fn set_foreign(&self, resource_id: &str) {
            self.set_failures(resource_id, usize::MAX);
        }
    }

    #[async_trait]
    impl StartupTapRestore for FakeStartupTapRestore {
        async fn restore_owned_taps(&self, resource_id: &str) -> Result<(), AgentError> {
            let failed = self
                .failures
                .lock()
                .ok()
                .map(|mut failures| match failures.get_mut(resource_id) {
                    Some(remaining) if *remaining > 0 => {
                        *remaining -= 1;
                        true
                    }
                    _ => false,
                })
                .unwrap_or(false);
            if failed {
                self.events.push(format!("tap-fail:{resource_id}"));
                return Err(AgentError::Protocol(
                    "injected TAP restoration failure".to_owned(),
                ));
            }
            self.events.push(format!("tap-ok:{resource_id}"));
            Ok(())
        }
    }

    /// Journal re-read fake for the stale-snapshot fence: every call returns
    /// the next snapshot, the last one sticking for every later call. A
    /// `None` store models an unreadable journal (the fail-closed branch).
    type JournalSnapshot = std::collections::HashMap<String, (u64, proto::ResourceState)>;

    struct FakeStartupJournalRefresh {
        snapshots: std::sync::Mutex<Option<std::collections::VecDeque<JournalSnapshot>>>,
    }

    impl FakeStartupJournalRefresh {
        fn sticky(states: JournalSnapshot) -> Self {
            Self::sequence([states])
        }

        fn sequence(snapshots: impl IntoIterator<Item = JournalSnapshot>) -> Self {
            Self {
                snapshots: std::sync::Mutex::new(Some(snapshots.into_iter().collect())),
            }
        }

        fn unreadable() -> Self {
            Self {
                snapshots: std::sync::Mutex::new(None),
            }
        }
    }

    impl StartupJournalRefresh for FakeStartupJournalRefresh {
        fn latest_lifecycle_states(&self) -> Result<JournalSnapshot, AgentError> {
            let mut snapshots = self
                .snapshots
                .lock()
                .map_err(|_| AgentError::Protocol("journal refresh lock is poisoned".to_owned()))?;
            let Some(snapshots) = snapshots.as_mut() else {
                return Err(AgentError::Protocol(
                    "injected journal re-read failure".to_owned(),
                ));
            };
            let current = snapshots.front().cloned().unwrap_or_default();
            if snapshots.len() > 1 {
                snapshots.pop_front();
            }
            Ok(current)
        }
    }

    fn lifecycle_state(
        resource_id: &str,
        state: proto::ResourceState,
    ) -> std::collections::HashMap<String, (u64, proto::ResourceState)> {
        std::collections::HashMap::from([(resource_id.to_owned(), (1, state))])
    }

    #[tokio::test]
    async fn restore_pass_starts_only_last_known_running_domains() -> Result<(), AgentError> {
        let tap = FakeStartupTapRestore::new();
        let restorer = FakeStartupDomainRestore::new(0);
        let mut states = lifecycle_state("server-running", proto::ResourceState::Running);
        states.insert(
            "server-stopped".to_owned(),
            (2, proto::ResourceState::Stopped),
        );
        states.insert(
            "server-deleted".to_owned(),
            (3, proto::ResourceState::Deleted),
        );
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        restore_expected_running_domains(&tap, &restorer, &journal, &states).await?;
        assert_eq!(
            restorer.restored_ids(),
            vec!["server-running".to_owned()],
            "only the last-known-running domain may be restored"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_with_no_running_domains_is_a_no_op() -> Result<(), AgentError> {
        let tap = FakeStartupTapRestore::new();
        let restorer = FakeStartupDomainRestore::new(0);
        let states = lifecycle_state("server-stopped", proto::ResourceState::Stopped);
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        restore_expected_running_domains(&tap, &restorer, &journal, &states).await?;
        assert!(
            restorer.restored_ids().is_empty(),
            "a stopped-only journal must not restore anything"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_retries_failed_attempts_inside_the_window() -> Result<(), AgentError> {
        let tap = FakeStartupTapRestore::new();
        let restorer = FakeStartupDomainRestore::new(2);
        let states = lifecycle_state("server-running", proto::ResourceState::Running);
        // Two failed attempts then success: the bounded retry window absorbs
        // transient startup failures (libvirtd still coming up) without
        // re-mutating an already-restored domain.
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        restore_expected_running_domains(&tap, &restorer, &journal, &states).await?;
        assert_eq!(
            restorer.restored_ids(),
            vec!["server-running".to_owned()],
            "the retry loop must converge inside the window"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_reports_unconverged_failures_without_aborting() -> Result<(), AgentError>
    {
        let tap = FakeStartupTapRestore::new();
        let restorer = FakeStartupDomainRestore::new(usize::MAX);
        let states = lifecycle_state("server-running", proto::ResourceState::Running);
        // The always-failing restorer must surface the failure after the
        // (tiny, test-scoped) window instead of hanging or silently
        // succeeding: the caller logs it and the agent stays up.
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        let result = restore_expected_running_domains_with_window(
            &tap,
            &restorer,
            &journal,
            &states,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(
            result.is_err(),
            "an unconverged restore must report its pending failure"
        );
        assert!(
            restorer.restored_ids().is_empty(),
            "a failing restorer must never record a successful start"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_recreates_recorded_taps_before_starting_domains() -> Result<(), AgentError>
    {
        // Issue #613 blocker A: the reboot deleted the TAP while the domain
        // definition survived. The restore must re-create the recorded TAP
        // FIRST and only then start the domain — the persisted domain XML
        // references the TAP with `managed="no"`, so a start without the TAP
        // fails. Pre-fix the pass never consulted the TAP restorer and the
        // domain start came first.
        let events = StartupEvents::new();
        let tap = FakeStartupTapRestore::with_events(events.clone());
        let restorer = FakeStartupDomainRestore::with_events(0, events.clone());
        let states = lifecycle_state("server-running", proto::ResourceState::Running);
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        restore_expected_running_domains(&tap, &restorer, &journal, &states).await?;
        assert_eq!(
            events.snapshot(),
            vec![
                "tap-ok:server-running".to_owned(),
                "domain:server-running".to_owned()
            ],
            "the recorded TAP must be restored before the domain start"
        );
        assert_eq!(
            restorer.restored_ids(),
            vec!["server-running".to_owned()],
            "the domain must be started exactly once after its TAP is restored"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_holds_back_domain_start_when_tap_restoration_fails_closed()
    -> Result<(), AgentError> {
        // A foreign TAP at the recorded name (or any unknown TAP outcome)
        // fails closed: the instance's domain must never be started against
        // an unverified interface, other instances still converge, and the
        // unconverged instance is reported without aborting the pass.
        let events = StartupEvents::new();
        let tap = FakeStartupTapRestore::with_events(events.clone());
        tap.set_failures("server-foreign", usize::MAX);
        let restorer = FakeStartupDomainRestore::with_events(0, events.clone());
        let mut states = lifecycle_state("server-foreign", proto::ResourceState::Running);
        states.insert("server-ok".to_owned(), (2, proto::ResourceState::Running));
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        let result = restore_expected_running_domains_with_window(
            &tap,
            &restorer,
            &journal,
            &states,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(
            result.is_err(),
            "the fail-closed instance must remain unconverged"
        );
        assert_eq!(
            restorer.restored_ids(),
            vec!["server-ok".to_owned()],
            "a foreign TAP must hold back only its own domain start"
        );
        assert!(
            events
                .snapshot()
                .iter()
                .all(|event| event != "domain:server-foreign"),
            "the fail-closed instance's domain must never be started"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_retries_tap_restoration_without_duplicate_domain_starts()
    -> Result<(), AgentError> {
        // A transient TAP restoration failure (unknown outcome) must be
        // retried inside the window; the retried restoration is idempotent
        // (a now-present TAP is verified and reused) and the domain is
        // started exactly once, on the pass whose TAP restoration succeeded.
        let events = StartupEvents::new();
        let tap = FakeStartupTapRestore::with_events(events.clone());
        tap.set_failures("server-running", 1);
        let restorer = FakeStartupDomainRestore::with_events(0, events.clone());
        let states = lifecycle_state("server-running", proto::ResourceState::Running);
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        restore_expected_running_domains(&tap, &restorer, &journal, &states).await?;
        assert_eq!(
            events.snapshot(),
            vec![
                "tap-fail:server-running".to_owned(),
                "tap-ok:server-running".to_owned(),
                "domain:server-running".to_owned(),
            ],
            "a failed TAP restoration must hold back the domain start until it succeeds"
        );
        assert_eq!(
            restorer.restored_ids(),
            vec!["server-running".to_owned()],
            "the domain must be started exactly once"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_drops_a_resource_whose_fresh_journal_state_is_stopped()
    -> Result<(), AgentError> {
        // Stale-snapshot race (issue #613 review): the seed snapshot says
        // Running, the first pass fails transiently, and by the second pass
        // the control connection has completed a user stop — the fresh
        // journal says Stopped. The second pass must NOT start the domain.
        // Fail-before: the pending set was a frozen pre-connection snapshot
        // and the second pass started it; fix-after: the per-pass re-read
        // drops the resource.
        let events = StartupEvents::new();
        let tap = FakeStartupTapRestore::with_events(events.clone());
        let restorer = FakeStartupDomainRestore::with_events(1, events.clone());
        let running = lifecycle_state("server-running", proto::ResourceState::Running);
        let stopped = lifecycle_state("server-running", proto::ResourceState::Stopped);
        let journal = FakeStartupJournalRefresh::sequence([running.clone(), stopped]);
        restore_expected_running_domains_with_window(
            &tap,
            &restorer,
            &journal,
            &running,
            Duration::from_millis(100),
            Duration::from_millis(10),
        )
        .await?;
        assert!(
            restorer.restored_ids().is_empty(),
            "the second pass must not start a domain whose fresh journal state is stopped"
        );
        assert_eq!(
            events.snapshot(),
            vec![
                "tap-ok:server-running".to_owned(),
                "domain:server-running".to_owned(),
            ],
            "the domain must be attempted exactly once, on the pass whose journal \
             state was still running"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_holds_back_mutations_when_the_journal_cannot_be_re_read()
    -> Result<(), AgentError> {
        // Fail closed: without a fresh journal snapshot the last lifecycle
        // state cannot be proven, so no pass may mutate (no TAP
        // restoration, no domain start) and the window must report the
        // unconverged outcome.
        let events = StartupEvents::new();
        let tap = FakeStartupTapRestore::with_events(events.clone());
        let restorer = FakeStartupDomainRestore::with_events(0, events.clone());
        let journal = FakeStartupJournalRefresh::unreadable();
        let states = lifecycle_state("server-running", proto::ResourceState::Running);
        let result = restore_expected_running_domains_with_window(
            &tap,
            &restorer,
            &journal,
            &states,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(
            result.is_err(),
            "an unreadable journal must report the unconverged outcome"
        );
        assert!(
            events.snapshot().is_empty(),
            "no tap or domain mutation may happen without a fresh journal snapshot"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_pass_holds_back_a_foreign_tap_domain_and_reports_other_unconverged_instances()
    -> Result<(), AgentError> {
        // A foreign link at the recorded TAP name fails closed at the
        // StartupTapRestore port (the real manager proves the zero-mutation
        // command behavior — no `tuntap add`, no `link del` — in the
        // network crate's command-fake tests): the loop must never start
        // that instance's domain, and a second instance whose domain
        // restore keeps failing must both be reported as unconverged after
        // the window without aborting the agent.
        let events = StartupEvents::new();
        let tap = FakeStartupTapRestore::with_events(events.clone());
        tap.set_foreign("server-foreign");
        let restorer = FakeStartupDomainRestore::with_events(usize::MAX, events.clone());
        let mut states = lifecycle_state("server-foreign", proto::ResourceState::Running);
        states.insert(
            "server-other".to_owned(),
            (2, proto::ResourceState::Running),
        );
        let journal = FakeStartupJournalRefresh::sticky(states.clone());
        let result = restore_expected_running_domains_with_window(
            &tap,
            &restorer,
            &journal,
            &states,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(
            result.is_err(),
            "the foreign-tap instance and the failing instance must be reported"
        );
        assert!(
            restorer.restored_ids().is_empty(),
            "no domain may record a successful start"
        );
        let events = events.snapshot();
        assert!(
            events.iter().all(|event| event != "domain:server-foreign"),
            "the foreign-tap instance's domain must never be started"
        );
        assert!(
            events.iter().any(|event| event == "domain:server-other"),
            "the other instance must be attempted inside the window"
        );
        Ok(())
    }
}
