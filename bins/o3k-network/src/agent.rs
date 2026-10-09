//! Transport boundary for the node-local network executor.

use o3k_network::{
    NetworkAgentIdentity, NetworkControllerLease, NetworkExecutionError, NetworkPlanAction,
    NetworkPlanCommand, NetworkPlanExecutor, NetworkPlanRealizer, PlanAdmission,
};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub use o3k_network_protocol::proto;

use proto::{
    CommandResult, ControlRequest, ControlResponse, ControllerLease, ControllerLeaseAck,
    ObserveCommand, ProtocolError, RegisterAck, control_request::Body as RequestBody,
    control_response::Body as ResponseBody, network_agent_server::NetworkAgent,
};

const PROTOCOL_MAJOR: u32 = 1;
const PROTOCOL_MINOR: u32 = 0;

#[derive(Debug, thiserror::Error)]
enum NetworkAgentError {
    #[error("network agent runtime is poisoned")]
    Poisoned,
    #[error("network agent command is malformed: {0}")]
    Malformed(&'static str),
    #[error("network plan payload is invalid")]
    InvalidPlan,
    #[error("network plan execution rejected: {0}")]
    Execution(&'static str),
}

struct Runtime<R> {
    realizer: R,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedLease {
    controller_id: String,
    controller_epoch: String,
    fencing_token: u64,
    lease_expiry_unix_ms: u64,
}

pub struct NetworkAgentService<R> {
    executor: Arc<NetworkPlanExecutor>,
    runtime: Arc<Mutex<Runtime<R>>>,
    authority: Arc<Mutex<Option<PersistedLease>>>,
    running: Arc<Mutex<HashSet<Uuid>>>,
    registered: Arc<std::sync::atomic::AtomicBool>,
    state_root: std::path::PathBuf,
    dynamic_lease: bool,
}

impl<R> Clone for NetworkAgentService<R> {
    fn clone(&self) -> Self {
        Self {
            executor: Arc::clone(&self.executor),
            runtime: Arc::clone(&self.runtime),
            authority: Arc::clone(&self.authority),
            running: Arc::clone(&self.running),
            registered: Arc::clone(&self.registered),
            state_root: self.state_root.clone(),
            dynamic_lease: self.dynamic_lease,
        }
    }
}

impl<R> NetworkAgentService<R>
where
    R: NetworkPlanRealizer + Send + 'static,
{
    /// Constructs the explicit legacy static-controller mode. Fabric v3
    /// production callers must use `new_dynamic` so mutation authority comes
    /// from the durable controller lease protocol.
    pub fn new_legacy(executor: NetworkPlanExecutor, realizer: R) -> Self {
        Self {
            state_root: executor.state_root().to_path_buf(),
            executor: Arc::new(executor),
            runtime: Arc::new(Mutex::new(Runtime { realizer })),
            authority: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(HashSet::new())),
            registered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dynamic_lease: false,
        }
    }

    #[cfg(test)]
    fn new(executor: NetworkPlanExecutor, realizer: R) -> Self {
        Self::new_legacy(executor, realizer)
    }

    pub fn new_dynamic(executor: NetworkPlanExecutor, realizer: R) -> Result<Self, std::io::Error> {
        Self::build(executor, realizer, true)
    }

    fn build(
        executor: NetworkPlanExecutor,
        realizer: R,
        dynamic_lease: bool,
    ) -> Result<Self, std::io::Error> {
        let state_root = executor.state_root().to_path_buf();
        let persisted = load_lease(&executor)?;
        if let Some(lease) = &persisted {
            let _ = executor.set_controller_lease(NetworkControllerLease {
                controller_id: lease.controller_id.clone(),
                controller_epoch: lease.controller_epoch.clone(),
                fencing_token: lease.fencing_token,
            });
        }
        Ok(Self {
            state_root,
            executor: Arc::new(executor),
            runtime: Arc::new(Mutex::new(Runtime { realizer })),
            authority: Arc::new(Mutex::new(persisted)),
            running: Arc::new(Mutex::new(HashSet::new())),
            registered: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dynamic_lease,
        })
    }

    pub fn reconcile_pending(
        &self,
    ) -> Result<Vec<(Uuid, o3k_network::NetworkPlanStatus)>, NetworkExecutionError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        self.executor.reconcile_pending(&mut runtime.realizer)
    }

    fn accept_lease(
        &self,
        lease: &ControllerLease,
    ) -> Result<ControllerLeaseAck, NetworkAgentError> {
        if lease.controller_id.trim().is_empty()
            || lease.controller_epoch.trim().is_empty()
            || lease.fencing_token == 0
            || lease.lease_expiry_unix_ms <= now_ms()?
        {
            return Err(NetworkAgentError::Malformed("invalid controller lease"));
        }
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let current = authority.as_ref();
        let same = current.is_some_and(|current| {
            lease.fencing_token == current.fencing_token
                && lease.controller_id == current.controller_id
                && lease.controller_epoch == current.controller_epoch
        });
        if current.is_some_and(|current| lease.fencing_token < current.fencing_token)
            || (current.is_some_and(|current| lease.fencing_token == current.fencing_token)
                && !same)
            || (same
                && current.is_some_and(|current| {
                    now_ms().unwrap_or(u64::MAX) >= current.lease_expiry_unix_ms
                }))
        {
            return Err(NetworkAgentError::Malformed("stale controller lease"));
        }
        let persisted = PersistedLease {
            controller_id: lease.controller_id.clone(),
            controller_epoch: lease.controller_epoch.clone(),
            fencing_token: lease.fencing_token,
            lease_expiry_unix_ms: lease.lease_expiry_unix_ms,
        };
        store_lease(&self.state_root, &persisted).map_err(|_| NetworkAgentError::Poisoned)?;
        *authority = Some(persisted);
        Ok(ControllerLeaseAck {
            fencing_token: lease.fencing_token,
            lease_expiry_unix_ms: lease.lease_expiry_unix_ms,
        })
    }

    fn observe(&self, request: &ObserveCommand) -> Result<CommandResult, NetworkAgentError> {
        let command_id = parse_uuid(&request.command_id, "command_id")?;
        if self
            .running
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?
            .contains(&command_id)
        {
            return Ok(CommandResult {
                command_id: request.command_id.clone(),
                status: "running".to_owned(),
                replayed: true,
                error_code: String::new(),
            });
        }
        if self.dynamic_lease {
            let authority = self
                .authority
                .lock()
                .map_err(|_| NetworkAgentError::Poisoned)?;
            if !authority
                .as_ref()
                .is_some_and(|lease| now_ms().is_ok_and(|now| now < lease.lease_expiry_unix_ms))
            {
                return Err(NetworkAgentError::Malformed("controller lease expired"));
            }
            drop(authority);
        }
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let status = match self.executor.reconcile(command_id, &mut runtime.realizer) {
            Ok(status) => status,
            Err(o3k_network::NetworkExecutionError::UnknownCommand) => {
                return Ok(CommandResult {
                    command_id: request.command_id.clone(),
                    status: "not_found".to_owned(),
                    replayed: true,
                    error_code: String::new(),
                });
            }
            Err(error) => return Err(NetworkAgentError::Execution(execution_error_code(&error))),
        };
        Ok(CommandResult {
            command_id: request.command_id.clone(),
            status: match status {
                o3k_network::NetworkPlanStatus::Succeeded => "succeeded",
                o3k_network::NetworkPlanStatus::Accepted
                | o3k_network::NetworkPlanStatus::Applying => "running",
                o3k_network::NetworkPlanStatus::Unknown => "unknown",
            }
            .to_owned(),
            replayed: true,
            error_code: String::new(),
        })
    }

    fn current_authority(
        &self,
        command: &NetworkPlanCommand,
        now: u64,
    ) -> Result<NetworkControllerLease, NetworkAgentError> {
        let authority = self
            .authority
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let accepted = authority.as_ref().ok_or(NetworkAgentError::Malformed(
            "dynamic controller lease required",
        ))?;
        if now >= accepted.lease_expiry_unix_ms {
            return Err(NetworkAgentError::Malformed("controller lease expired"));
        }
        if command.controller.controller_id != accepted.controller_id
            || command.controller.controller_epoch != accepted.controller_epoch
            || command.controller.fencing_token != accepted.fencing_token
        {
            return Err(NetworkAgentError::Execution("stale_controller_lease"));
        }
        Ok(NetworkControllerLease {
            controller_id: accepted.controller_id.clone(),
            controller_epoch: accepted.controller_epoch.clone(),
            fencing_token: accepted.fencing_token,
        })
    }

    fn register(&self, request: &proto::Register) -> Result<RegisterAck, NetworkAgentError> {
        if request.agent_id != self.executor.agent_id()
            || request.agent_epoch != self.executor.agent_epoch()
        {
            return Err(NetworkAgentError::Malformed("stale agent identity"));
        }
        self.registered
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(RegisterAck {
            agent_id: request.agent_id.clone(),
            agent_epoch: request.agent_epoch.clone(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        })
    }

    fn execute(&self, command: &proto::NetworkCommand) -> Result<CommandResult, NetworkAgentError>
    where
        R::Error: std::fmt::Display,
    {
        let command_id = parse_uuid(&command.command_id, "command_id")?;
        let operation_id = parse_uuid(&command.operation_id, "operation_id")?;
        let plan =
            serde_json::from_str(&command.plan_json).map_err(|_| NetworkAgentError::InvalidPlan)?;
        let internal = NetworkPlanCommand {
            command_id,
            operation_id,
            idempotency_key: command.idempotency_key.clone(),
            action: if command.remove {
                NetworkPlanAction::Remove
            } else {
                NetworkPlanAction::Apply
            },
            target: NetworkAgentIdentity {
                agent_id: command.agent_id.clone(),
                agent_epoch: command.agent_epoch.clone(),
            },
            controller: NetworkControllerLease {
                controller_id: command.controller_id.clone(),
                controller_epoch: command.controller_epoch.clone(),
                fencing_token: command.fencing_token,
            },
            deadline_unix_ms: command.deadline_unix_ms,
            plan,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NetworkAgentError::Malformed("system clock before epoch"))?
            .as_millis() as u64;
        // Reject stale authority before waiting behind a running mutation.
        // The authority is checked again after the lane is acquired, so a
        // command queued before takeover cannot cross admission afterward.
        if self.dynamic_lease {
            let _ = self.current_authority(&internal, now)?;
        }
        // Serialize command admission with provider execution. Waiting for this
        // lane does not hold controller authority, so lease renewals and a
        // higher-fence takeover remain responsive while an earlier provider
        // operation is running. A queued command is not admitted until it
        // owns the lane and revalidates the then-current authority.
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let authority = if self.dynamic_lease {
            Some(self.current_authority(&internal, now)?)
        } else {
            None
        };
        if !self.registered.load(std::sync::atomic::Ordering::Acquire) {
            return Err(NetworkAgentError::Malformed("register is required first"));
        }
        let admission = if let Some(authority) = authority.as_ref() {
            self.executor
                .admit_with_authority(&internal, now, authority)
        } else {
            self.executor.admit(&internal, now)
        };
        let admission = match admission {
            Ok(admission) => admission,
            Err(error) => return Err(NetworkAgentError::Execution(execution_error_code(&error))),
        };
        // Durable admission has transferred this command to the agent. No
        // authority lock is held while provider mutation runs, so takeover is
        // accepted while this serialized execution lane remains occupied.
        if admission == PlanAdmission::Accepted {
            self.running
                .lock()
                .map_err(|_| NetworkAgentError::Poisoned)?
                .insert(command_id);
        }
        let execution = match admission {
            PlanAdmission::Accepted => self
                .executor
                .execute_admitted(&internal, &mut runtime.realizer)
                .map(|_| admission),
            PlanAdmission::Replayed
            | PlanAdmission::ReplayedUnknown
            | PlanAdmission::RequiresObservation => {
                match self.executor.reconcile(command_id, &mut runtime.realizer) {
                    Ok(o3k_network::NetworkPlanStatus::Succeeded) => Ok(PlanAdmission::Replayed),
                    Ok(_) => Ok(PlanAdmission::ReplayedUnknown),
                    Err(error) => Err(error),
                }
            }
        };
        self.running
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?
            .remove(&command_id);
        let admission = match execution {
            Ok(admission) => admission,
            Err(NetworkExecutionError::MutationOutcomeUnknown(reason)) => {
                tracing::warn!(
                    command_id = %command.command_id,
                    operation_id = %command.operation_id,
                    %reason,
                    "network mutation outcome is unknown"
                );
                let code = reason
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .take(120)
                    .collect::<String>();
                return Ok(CommandResult {
                    command_id: command.command_id.clone(),
                    status: "unknown".to_owned(),
                    replayed: false,
                    error_code: code,
                });
            }
            Err(error) => {
                tracing::warn!(
                    command_id = %command.command_id,
                    operation_id = %command.operation_id,
                    error = ?error,
                    error_code = execution_error_code(&error),
                    "network plan execution failed"
                );
                return Err(NetworkAgentError::Execution(execution_error_code(&error)));
            }
        };
        let (status, replayed) = match admission {
            PlanAdmission::Accepted => ("succeeded", false),
            PlanAdmission::Replayed => ("replayed", true),
            PlanAdmission::ReplayedUnknown => ("unknown", true),
            PlanAdmission::RequiresObservation => ("unknown", true),
        };
        Ok(CommandResult {
            command_id: command.command_id.clone(),
            status: status.to_owned(),
            replayed,
            error_code: String::new(),
        })
    }
}

#[tonic::async_trait]
impl<R> NetworkAgent for NetworkAgentService<R>
where
    R: NetworkPlanRealizer + Send + 'static,
    R::Error: std::fmt::Display,
{
    type ControlStream = ReceiverStream<Result<ControlResponse, Status>>;

    async fn control(
        &self,
        request: Request<tonic::Streaming<ControlRequest>>,
    ) -> Result<Response<Self::ControlStream>, Status> {
        let mut input = request.into_inner();
        let service = (*self).clone();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let mut registered = false;
            while let Some(message) = input.next().await {
                let response = match message {
                    Ok(ControlRequest {
                        body: Some(RequestBody::Register(register)),
                    }) => match service.register(&register) {
                        Ok(ack) => {
                            registered = true;
                            ControlResponse {
                                body: Some(ResponseBody::Register(ack)),
                            }
                        }
                        Err(_) => error_response("stale_or_invalid_registration"),
                    },
                    Ok(ControlRequest {
                        body: Some(RequestBody::Command(command)),
                    }) if registered => {
                        let service = service.clone();
                        let response_tx = tx.clone();
                        tokio::spawn(async move {
                            let response = match tokio::task::spawn_blocking(move || {
                                service.execute(&command)
                            })
                            .await
                            {
                                Ok(Ok(result)) => ControlResponse {
                                    body: Some(ResponseBody::Result(result)),
                                },
                                Ok(Err(error)) => error_response(error_code(&error)),
                                Err(_) => error_response("execution_worker_failed"),
                            };
                            let _ = response_tx.send(Ok(response)).await;
                        });
                        continue;
                    }
                    Ok(ControlRequest {
                        body: Some(RequestBody::Lease(lease)),
                    }) if registered => match service.accept_lease(&lease) {
                        Ok(ack) => ControlResponse {
                            body: Some(ResponseBody::Lease(ack)),
                        },
                        Err(error) => error_response(error_code(&error)),
                    },
                    Ok(ControlRequest {
                        body: Some(RequestBody::Observe(observe)),
                    }) if registered => {
                        let service = service.clone();
                        let response_tx = tx.clone();
                        tokio::spawn(async move {
                            let response = match tokio::task::spawn_blocking(move || {
                                service.observe(&observe)
                            })
                            .await
                            {
                                Ok(Ok(result)) => ControlResponse {
                                    body: Some(ResponseBody::Result(result)),
                                },
                                Ok(Err(error)) => error_response(error_code(&error)),
                                Err(_) => error_response("observation_worker_failed"),
                            };
                            let _ = response_tx.send(Ok(response)).await;
                        });
                        continue;
                    }
                    Ok(ControlRequest {
                        body: Some(RequestBody::Command(_)),
                    }) => error_response("register_required"),
                    Ok(ControlRequest {
                        body: Some(RequestBody::Lease(_)),
                    })
                    | Ok(ControlRequest {
                        body: Some(RequestBody::Observe(_)),
                    }) => error_response("register_required"),
                    Ok(ControlRequest { body: None }) => error_response("empty_request"),
                    Err(_) => error_response("malformed_request"),
                };
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, NetworkAgentError> {
    Uuid::parse_str(value).map_err(|_| NetworkAgentError::Malformed(field))
}

fn now_ms() -> Result<u64, NetworkAgentError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NetworkAgentError::Malformed("system clock before epoch"))?
        .as_millis() as u64)
}

fn lease_path(root: &Path) -> std::path::PathBuf {
    root.join("controller-lease.json")
}

fn load_lease(executor: &NetworkPlanExecutor) -> Result<Option<PersistedLease>, std::io::Error> {
    match fs::read(lease_path(executor.state_root())) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt controller lease")
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn store_lease(root: &Path, lease: &PersistedLease) -> Result<(), std::io::Error> {
    let path = lease_path(root);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(lease)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "lease serialization"))?;
    let mut file = File::create(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, &path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn error_response(code: &str) -> ControlResponse {
    ControlResponse {
        body: Some(ResponseBody::Error(ProtocolError {
            code: code.to_owned(),
        })),
    }
}

fn error_code(error: &NetworkAgentError) -> &'static str {
    match error {
        NetworkAgentError::Poisoned => "runtime_poisoned",
        NetworkAgentError::Malformed(code) => code,
        NetworkAgentError::InvalidPlan => "invalid_plan",
        NetworkAgentError::Execution(code) => code,
    }
}

fn execution_error_code(error: &NetworkExecutionError) -> &'static str {
    match error {
        NetworkExecutionError::Io(_) => "journal_io",
        NetworkExecutionError::CorruptJournal => "corrupt_journal",
        NetworkExecutionError::InvalidCommand => "invalid_command",
        NetworkExecutionError::StaleAgentEpoch => "stale_agent_epoch",
        NetworkExecutionError::StaleControllerLease => "stale_controller_lease",
        NetworkExecutionError::DeadlineExpired => "deadline_expired",
        NetworkExecutionError::ConflictingReplay => "conflicting_replay",
        NetworkExecutionError::MutationOutcomeUnknown(_) => "mutation_outcome_unknown",
        NetworkExecutionError::UnknownCommand => "unknown_command",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use prost::Message;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct NoopRealizer;

    impl NetworkPlanRealizer for NoopRealizer {
        type Error = std::convert::Infallible;

        fn realize(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            Ok(())
        }

        fn remove(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct CountingRealizer(Arc<AtomicUsize>);

    impl NetworkPlanRealizer for CountingRealizer {
        type Error = std::convert::Infallible;

        fn realize(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn remove(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct BlockingRealizer {
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
        mutations: Arc<AtomicUsize>,
    }

    impl NetworkPlanRealizer for BlockingRealizer {
        type Error = std::convert::Infallible;

        fn realize(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.mutations.fetch_add(1, Ordering::SeqCst);
            self.entered.wait();
            self.release.wait();
            Ok(())
        }

        fn remove(&mut self, plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            self.realize(plan)
        }
    }

    struct ObservingRealizer {
        observations: Arc<AtomicUsize>,
    }

    impl NetworkPlanRealizer for ObservingRealizer {
        type Error = &'static str;

        fn realize(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            Err("recovery must not repeat host mutation")
        }

        fn remove(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<(), Self::Error> {
            Err("recovery must not repeat host mutation")
        }

        fn observe(&mut self, _plan: &o3k_network::NodeNetworkPlan) -> Result<bool, Self::Error> {
            self.observations.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    #[test]
    fn network_command_wire_round_trip_preserves_fencing_identity() {
        let request = ControlRequest {
            body: Some(RequestBody::Command(proto::NetworkCommand {
                command_id: "command".to_owned(),
                operation_id: "operation".to_owned(),
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch".to_owned(),
                fencing_token: 7,
                remove: true,
                ..Default::default()
            })),
        };
        let decoded = ControlRequest::decode(request.encode_to_vec().as_slice())
            .expect("network command must decode");
        assert!(matches!(&decoded.body, Some(RequestBody::Command(_))));
        let Some(RequestBody::Command(command)) = decoded.body else {
            return;
        };
        assert_eq!(command.controller_id, "controller");
        assert_eq!(command.controller_epoch, "epoch");
        assert_eq!(command.fencing_token, 7);
        assert!(command.remove);
    }

    #[test]
    fn registration_rejects_a_stale_agent_epoch() {
        let root = std::env::temp_dir().join(format!("o3k-network-agent-{}", Uuid::now_v7()));
        let executor = NetworkPlanExecutor::open(
            &root,
            NetworkAgentIdentity {
                agent_id: "agent-a".to_owned(),
                agent_epoch: "epoch-2".to_owned(),
            },
            NetworkControllerLease {
                controller_id: "controller".to_owned(),
                controller_epoch: "epoch-1".to_owned(),
                fencing_token: 1,
            },
        )
        .expect("executor");
        let service = NetworkAgentService::new(executor, NoopRealizer);
        let result = service.register(&proto::Register {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
        });
        assert!(matches!(
            result,
            Err(NetworkAgentError::Malformed("stale agent identity"))
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replayed_accepted_command_observes_and_recovers_without_mutation() {
        let root = std::env::temp_dir().join(format!("o3k-network-agent-{}", Uuid::now_v7()));
        let agent = NetworkAgentIdentity {
            agent_id: "agent-a".to_owned(),
            agent_epoch: "epoch-1".to_owned(),
        };
        let controller = NetworkControllerLease {
            controller_id: "controller".to_owned(),
            controller_epoch: "epoch-1".to_owned(),
            fencing_token: 1,
        };
        let operation_id = Uuid::now_v7();
        let deadline_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64
            + 60_000;
        let mut plan = o3k_network::NodeNetworkPlan {
            schema_version: 1,
            plan_id: Uuid::now_v7(),
            node_id: agent.agent_id.clone(),
            operation_id,
            deadline_unix_ms,
            resource_generations: BTreeMap::new(),
            intents: Vec::new(),
            fabric: None,
            gateway: None,
            fingerprint_sha256: String::new(),
        };
        plan.fingerprint_sha256 =
            o3k_network::canonical_plan_fingerprint(&plan).expect("fingerprint");
        let command = NetworkPlanCommand {
            command_id: Uuid::now_v7(),
            operation_id,
            idempotency_key: "network-recovery".to_owned(),
            action: NetworkPlanAction::Apply,
            target: agent.clone(),
            controller: controller.clone(),
            deadline_unix_ms,
            plan: plan.clone(),
        };
        let executor =
            NetworkPlanExecutor::open(&root, agent.clone(), controller.clone()).expect("executor");
        executor
            .admit(&command, deadline_unix_ms - 1)
            .expect("accepted journal entry");
        drop(executor);

        let observations = Arc::new(AtomicUsize::new(0));
        let service = NetworkAgentService::new(
            NetworkPlanExecutor::open(&root, agent.clone(), controller.clone()).expect("restart"),
            ObservingRealizer {
                observations: Arc::clone(&observations),
            },
        );
        assert_eq!(
            service.reconcile_pending().expect("startup reconciliation"),
            vec![(
                command.command_id,
                o3k_network::NetworkPlanStatus::Succeeded
            )]
        );
        service
            .register(&proto::Register {
                agent_id: agent.agent_id.clone(),
                agent_epoch: agent.agent_epoch.clone(),
            })
            .expect("registration");
        let result = service
            .execute(&proto::NetworkCommand {
                command_id: command.command_id.to_string(),
                operation_id: operation_id.to_string(),
                idempotency_key: command.idempotency_key,
                agent_id: agent.agent_id,
                agent_epoch: agent.agent_epoch,
                controller_id: controller.controller_id,
                controller_epoch: controller.controller_epoch,
                fencing_token: controller.fencing_token,
                deadline_unix_ms,
                plan_json: serde_json::to_string(&plan).expect("plan json"),
                remove: false,
            })
            .expect("recovery result");
        assert_eq!(result.status, "replayed");
        assert!(result.replayed);
        assert_eq!(observations.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    fn dynamic_service(root: &std::path::Path) -> NetworkAgentService<NoopRealizer> {
        NetworkAgentService::new_dynamic(
            NetworkPlanExecutor::open(
                root,
                NetworkAgentIdentity {
                    agent_id: "agent-a".into(),
                    agent_epoch: "epoch-1".into(),
                },
                NetworkControllerLease {
                    controller_id: "bootstrap".into(),
                    controller_epoch: "bootstrap".into(),
                    fencing_token: 0,
                },
            )
            .expect("executor"),
            NoopRealizer,
        )
        .expect("dynamic service")
    }

    fn lease(id: &str, epoch: &str, token: u64, expiry: u64) -> ControllerLease {
        ControllerLease {
            controller_id: id.into(),
            controller_epoch: epoch.into(),
            fencing_token: token,
            lease_expiry_unix_ms: expiry,
        }
    }

    #[test]
    fn live_takeover_rejects_stale_controller_and_preserves_higher_token() {
        let root = std::env::temp_dir().join(format!("o3k-network-lease-{}", Uuid::now_v7()));
        let mutation_count = Arc::new(AtomicUsize::new(0));
        let service = NetworkAgentService::new_dynamic(
            NetworkPlanExecutor::open(
                &root,
                NetworkAgentIdentity {
                    agent_id: "agent-a".into(),
                    agent_epoch: "epoch-1".into(),
                },
                NetworkControllerLease {
                    controller_id: "bootstrap".into(),
                    controller_epoch: "bootstrap".into(),
                    fencing_token: 0,
                },
            )
            .expect("executor"),
            CountingRealizer(Arc::clone(&mutation_count)),
        )
        .expect("dynamic service");
        let expiry = now_ms().expect("clock") + 60_000;
        service
            .accept_lease(&lease("controller-a", "epoch-a", 2, expiry))
            .expect("A lease");
        service
            .accept_lease(&lease("controller-b", "epoch-b", 3, expiry))
            .expect("B takeover");
        assert!(matches!(
            service.accept_lease(&lease("controller-a", "epoch-a", 2, expiry)),
            Err(NetworkAgentError::Malformed("stale controller lease"))
        ));
        assert_eq!(
            service
                .authority
                .lock()
                .expect("authority")
                .as_ref()
                .expect("lease")
                .fencing_token,
            3
        );

        service
            .register(&proto::Register {
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
            })
            .expect("register");
        let operation_id = Uuid::now_v7();
        let deadline_unix_ms = now_ms().expect("clock") + 60_000;
        let mut plan = o3k_network::NodeNetworkPlan {
            schema_version: 1,
            plan_id: Uuid::now_v7(),
            node_id: "agent-a".into(),
            operation_id,
            deadline_unix_ms,
            resource_generations: BTreeMap::new(),
            intents: Vec::new(),
            fabric: None,
            gateway: None,
            fingerprint_sha256: String::new(),
        };
        plan.fingerprint_sha256 =
            o3k_network::canonical_plan_fingerprint(&plan).expect("fingerprint");
        let run_command = |controller_id: &str, epoch: &str, token: u64| proto::NetworkCommand {
            command_id: Uuid::now_v7().to_string(),
            operation_id: operation_id.to_string(),
            idempotency_key: format!("controller-{token}"),
            agent_id: "agent-a".into(),
            agent_epoch: "epoch-1".into(),
            controller_id: controller_id.into(),
            controller_epoch: epoch.into(),
            fencing_token: token,
            deadline_unix_ms,
            plan_json: serde_json::to_string(&plan).expect("plan json"),
            remove: false,
        };
        assert!(matches!(
            service.execute(&run_command("controller-a", "epoch-a", 2)),
            Err(NetworkAgentError::Execution("stale_controller_lease"))
        ));
        assert_eq!(mutation_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            service
                .execute(&run_command("controller-b", "epoch-b", 3))
                .expect("current controller command")
                .status,
            "succeeded"
        );
        assert_eq!(mutation_count.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn admitted_mutation_survives_takeover_and_control_lane_stays_responsive() {
        let root =
            std::env::temp_dir().join(format!("o3k-network-agent-blocking-{}", Uuid::now_v7()));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let mutations = Arc::new(AtomicUsize::new(0));
        let service = NetworkAgentService::new_dynamic(
            NetworkPlanExecutor::open(
                &root,
                NetworkAgentIdentity {
                    agent_id: "agent-a".into(),
                    agent_epoch: "epoch-1".into(),
                },
                NetworkControllerLease {
                    controller_id: "bootstrap".into(),
                    controller_epoch: "bootstrap".into(),
                    fencing_token: 0,
                },
            )
            .expect("executor"),
            BlockingRealizer {
                entered: entered.clone(),
                release: release.clone(),
                mutations: mutations.clone(),
            },
        )
        .expect("service");
        let expiry = now_ms().expect("clock") + 60_000;
        service
            .accept_lease(&lease("controller-a", "epoch-a", 2, expiry))
            .expect("A lease");
        service
            .register(&proto::Register {
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
            })
            .expect("registration");
        let operation_id = Uuid::now_v7();
        let deadline_unix_ms = now_ms().expect("clock") + 60_000;
        let mut plan = o3k_network::NodeNetworkPlan {
            schema_version: 1,
            plan_id: Uuid::now_v7(),
            node_id: "agent-a".into(),
            operation_id,
            deadline_unix_ms,
            resource_generations: BTreeMap::new(),
            intents: Vec::new(),
            fabric: None,
            gateway: None,
            fingerprint_sha256: String::new(),
        };
        plan.fingerprint_sha256 =
            o3k_network::canonical_plan_fingerprint(&plan).expect("fingerprint");
        let command = proto::NetworkCommand {
            command_id: Uuid::now_v7().to_string(),
            operation_id: operation_id.to_string(),
            idempotency_key: "admitted-before-takeover".into(),
            agent_id: "agent-a".into(),
            agent_epoch: "epoch-1".into(),
            controller_id: "controller-a".into(),
            controller_epoch: "epoch-a".into(),
            fencing_token: 2,
            deadline_unix_ms,
            plan_json: serde_json::to_string(&plan).expect("plan"),
            remove: false,
        };
        let service_thread = service.clone();
        let command_thread = command.clone();
        let operation = std::thread::spawn(move || service_thread.execute(&command_thread));
        entered.wait();

        service
            .accept_lease(&lease(
                "controller-b",
                "epoch-b",
                3,
                now_ms().expect("clock") + 60_000,
            ))
            .expect("B takeover while provider is blocked");
        let stale = proto::NetworkCommand {
            command_id: Uuid::now_v7().to_string(),
            controller_id: "controller-a".into(),
            controller_epoch: "epoch-a".into(),
            fencing_token: 2,
            ..command.clone()
        };
        assert!(matches!(
            service.execute(&stale),
            Err(NetworkAgentError::Execution("stale_controller_lease"))
        ));
        let observation = service
            .observe(&ObserveCommand {
                command_id: command.command_id.clone(),
            })
            .expect("running observation");
        assert_eq!(observation.status, "running");

        release.wait();
        assert_eq!(
            operation
                .join()
                .expect("provider worker")
                .expect("admitted command")
                .status,
            "succeeded"
        );
        assert_eq!(mutations.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn coordination_takeover_fences_same_running_network_agent() {
        use o3k_store::{
            ControllerEpoch, ControllerId, CoordinationRepository, LeaseAcquireOutcome,
        };
        use std::time::Duration;

        let store = o3k_store::testkit::open_memory()
            .await
            .expect("memory store");
        let work_key = "network-agent:agent-a";
        let controller_a = ControllerId::new("controller-a");
        let epoch_a = ControllerEpoch::new("epoch-a");
        let lease_a = match store
            .acquire_work_lease(
                work_key,
                "network_agent_control",
                &controller_a,
                &epoch_a,
                Duration::from_millis(500),
            )
            .await
            .expect("controller A lease")
        {
            LeaseAcquireOutcome::Acquired { lease } => Some(lease),
            LeaseAcquireOutcome::Busy { .. } => None,
        }
        .expect("controller A should acquire lease");

        let root =
            std::env::temp_dir().join(format!("o3k-coordination-takeover-{}", Uuid::now_v7()));
        let mutation_count = Arc::new(AtomicUsize::new(0));
        let service = NetworkAgentService::new_dynamic(
            NetworkPlanExecutor::open(
                &root,
                NetworkAgentIdentity {
                    agent_id: "agent-a".into(),
                    agent_epoch: "epoch-1".into(),
                },
                NetworkControllerLease {
                    controller_id: "bootstrap".into(),
                    controller_epoch: "bootstrap".into(),
                    fencing_token: 0,
                },
            )
            .expect("executor"),
            CountingRealizer(Arc::clone(&mutation_count)),
        )
        .expect("dynamic service");
        service
            .register(&proto::Register {
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
            })
            .expect("register agent");

        let make_command = |controller_id: &str, epoch: &str, token: u64| {
            let operation_id = Uuid::now_v7();
            let deadline_unix_ms = now_ms().expect("clock") + 60_000;
            let mut plan = o3k_network::NodeNetworkPlan {
                schema_version: 1,
                plan_id: Uuid::now_v7(),
                node_id: "agent-a".into(),
                operation_id,
                deadline_unix_ms,
                resource_generations: BTreeMap::new(),
                intents: Vec::new(),
                fabric: None,
                gateway: None,
                fingerprint_sha256: String::new(),
            };
            plan.fingerprint_sha256 =
                o3k_network::canonical_plan_fingerprint(&plan).expect("fingerprint");
            proto::NetworkCommand {
                command_id: Uuid::now_v7().to_string(),
                operation_id: operation_id.to_string(),
                idempotency_key: Uuid::now_v7().to_string(),
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
                controller_id: controller_id.into(),
                controller_epoch: epoch.into(),
                fencing_token: token,
                deadline_unix_ms,
                plan_json: serde_json::to_string(&plan).expect("plan json"),
                remove: false,
            }
        };
        let remote_expiry = now_ms().expect("clock") + 500;
        service
            .accept_lease(&lease(
                &controller_a.to_string(),
                &epoch_a.to_string(),
                lease_a.fencing_token,
                remote_expiry,
            ))
            .expect("agent accepts A coordination lease");
        assert!(
            store
                .renew_work_lease(
                    work_key,
                    &controller_a,
                    &epoch_a,
                    lease_a.fencing_token,
                    Duration::from_millis(500),
                )
                .await
                .expect("renew coordination lease")
        );
        service
            .accept_lease(&lease(
                &controller_a.to_string(),
                &epoch_a.to_string(),
                lease_a.fencing_token,
                now_ms().expect("clock") + 500,
            ))
            .expect("renew agent-side controller lease");
        service
            .execute(&make_command(
                &controller_a.to_string(),
                &epoch_a.to_string(),
                lease_a.fencing_token,
            ))
            .expect("A mutation");
        assert_eq!(mutation_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let controller_b = ControllerId::new("controller-b");
        let epoch_b = ControllerEpoch::new("epoch-b");
        let lease_b = match store
            .acquire_work_lease(
                work_key,
                "network_agent_control",
                &controller_b,
                &epoch_b,
                Duration::from_secs(1),
            )
            .await
            .expect("controller B takeover")
        {
            LeaseAcquireOutcome::Acquired { lease } => Some(lease),
            LeaseAcquireOutcome::Busy { .. } => None,
        }
        .expect("controller B should take over expired lease");
        assert!(lease_b.fencing_token > lease_a.fencing_token);
        service
            .accept_lease(&lease(
                &controller_b.to_string(),
                &epoch_b.to_string(),
                lease_b.fencing_token,
                now_ms().expect("clock") + 60_000,
            ))
            .expect("agent accepts B takeover without restart");
        assert!(matches!(
            service.execute(&make_command(
                &controller_a.to_string(),
                &epoch_a.to_string(),
                lease_a.fencing_token,
            )),
            Err(NetworkAgentError::Execution("stale_controller_lease"))
        ));
        assert_eq!(mutation_count.load(Ordering::SeqCst), 1);
        service
            .execute(&make_command(
                &controller_b.to_string(),
                &epoch_b.to_string(),
                lease_b.fencing_token,
            ))
            .expect("B mutation");
        assert_eq!(mutation_count.load(Ordering::SeqCst), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn expired_lease_and_corrupt_state_fail_closed() {
        let root = std::env::temp_dir().join(format!("o3k-network-lease-{}", Uuid::now_v7()));
        let service = dynamic_service(&root);
        assert!(matches!(
            service.accept_lease(&lease(
                "controller",
                "epoch",
                2,
                now_ms().expect("clock") - 1
            )),
            Err(NetworkAgentError::Malformed("invalid controller lease"))
        ));
        service
            .accept_lease(&lease(
                "controller",
                "epoch",
                2,
                now_ms().expect("clock") + 80,
            ))
            .expect("short valid lease");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(matches!(
            service.accept_lease(&lease(
                "controller",
                "epoch",
                2,
                now_ms().expect("clock") + 60_000,
            )),
            Err(NetworkAgentError::Malformed("stale controller lease"))
        ));
        service
            .register(&proto::Register {
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
            })
            .expect("register");
        let operation_id = Uuid::now_v7();
        let deadline_unix_ms = now_ms().expect("clock") + 60_000;
        let mut plan = o3k_network::NodeNetworkPlan {
            schema_version: 1,
            plan_id: Uuid::now_v7(),
            node_id: "agent-a".into(),
            operation_id,
            deadline_unix_ms,
            resource_generations: BTreeMap::new(),
            intents: Vec::new(),
            fabric: None,
            gateway: None,
            fingerprint_sha256: String::new(),
        };
        plan.fingerprint_sha256 =
            o3k_network::canonical_plan_fingerprint(&plan).expect("fingerprint");
        assert!(matches!(
            service.execute(&proto::NetworkCommand {
                command_id: Uuid::now_v7().to_string(),
                operation_id: operation_id.to_string(),
                idempotency_key: "expired-authority".into(),
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
                controller_id: "controller".into(),
                controller_epoch: "epoch".into(),
                fencing_token: 2,
                deadline_unix_ms,
                plan_json: serde_json::to_string(&plan).expect("plan json"),
                remove: false,
            }),
            Err(NetworkAgentError::Malformed("controller lease expired"))
        ));
        fs::write(root.join("controller-lease.json"), b"corrupt").expect("corrupt sidecar");
        assert!(
            NetworkAgentService::new_dynamic(
                NetworkPlanExecutor::open(
                    &root,
                    NetworkAgentIdentity {
                        agent_id: "agent-a".into(),
                        agent_epoch: "epoch-1".into()
                    },
                    NetworkControllerLease {
                        controller_id: "bootstrap".into(),
                        controller_epoch: "bootstrap".into(),
                        fencing_token: 1
                    }
                )
                .expect("executor"),
                NoopRealizer
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn restart_preserves_fencing_and_observe_reports_not_found_without_mutation() {
        let root = std::env::temp_dir().join(format!("o3k-network-lease-{}", Uuid::now_v7()));
        let service = dynamic_service(&root);
        let expiry = now_ms().expect("clock") + 60_000;
        service
            .accept_lease(&lease("controller-b", "epoch-b", 9, expiry))
            .expect("lease");
        drop(service);
        let restarted = dynamic_service(&root);
        assert_eq!(
            restarted
                .authority
                .lock()
                .expect("authority")
                .as_ref()
                .expect("lease")
                .fencing_token,
            9
        );
        restarted
            .register(&proto::Register {
                agent_id: "agent-a".into(),
                agent_epoch: "epoch-1".into(),
            })
            .expect("register");
        let result = restarted
            .observe(&ObserveCommand {
                command_id: Uuid::now_v7().to_string(),
            })
            .expect("observation");
        assert_eq!(result.status, "not_found");
        let _ = fs::remove_dir_all(root);
    }
}
