//! Transport boundary for the node-local network executor.

use o3k_network::{
    NetworkAgentIdentity, NetworkControllerLease, NetworkExecutionError, NetworkPlanAction,
    NetworkPlanCommand, NetworkPlanExecutor, NetworkPlanRealizer, PlanAdmission,
};
use std::{
    fs,
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
    executor: NetworkPlanExecutor,
    realizer: R,
    registered: bool,
    lease_expiry_unix_ms: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedLease {
    controller_id: String,
    controller_epoch: String,
    fencing_token: u64,
    lease_expiry_unix_ms: u64,
}

pub struct NetworkAgentService<R> {
    runtime: Arc<Mutex<Runtime<R>>>,
}

impl<R> Clone for NetworkAgentService<R> {
    fn clone(&self) -> Self {
        Self {
            runtime: Arc::clone(&self.runtime),
        }
    }
}

impl<R> NetworkAgentService<R>
where
    R: NetworkPlanRealizer + Send + 'static,
{
    pub fn new(executor: NetworkPlanExecutor, realizer: R) -> Self {
        let persisted = load_lease(&executor).ok().flatten();
        if let Some(lease) = &persisted {
            let _ = executor.set_controller_lease(NetworkControllerLease {
                controller_id: lease.controller_id.clone(),
                controller_epoch: lease.controller_epoch.clone(),
                fencing_token: lease.fencing_token,
            });
        }
        let lease_expiry_unix_ms = persisted
            .map(|lease| lease.lease_expiry_unix_ms)
            .unwrap_or(0);
        Self {
            runtime: Arc::new(Mutex::new(Runtime {
                executor,
                realizer,
                registered: false,
                lease_expiry_unix_ms,
            })),
        }
    }

    pub fn reconcile_pending(
        &self,
    ) -> Result<Vec<(Uuid, o3k_network::NetworkPlanStatus)>, NetworkExecutionError> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkExecutionError::CorruptJournal)?;
        let Runtime {
            executor, realizer, ..
        } = &mut *runtime;
        executor.reconcile_pending(realizer)
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
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let current = runtime
            .executor
            .controller_lease()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let same = lease.fencing_token == current.fencing_token
            && lease.controller_id == current.controller_id
            && lease.controller_epoch == current.controller_epoch;
        if lease.fencing_token < current.fencing_token
            || (lease.fencing_token == current.fencing_token && !same)
        {
            return Err(NetworkAgentError::Malformed("stale controller lease"));
        }
        runtime
            .executor
            .set_controller_lease(NetworkControllerLease {
                controller_id: lease.controller_id.clone(),
                controller_epoch: lease.controller_epoch.clone(),
                fencing_token: lease.fencing_token,
            })
            .map_err(|_| NetworkAgentError::Poisoned)?;
        runtime.lease_expiry_unix_ms = lease.lease_expiry_unix_ms;
        store_lease(
            &runtime.executor,
            &PersistedLease {
                controller_id: lease.controller_id.clone(),
                controller_epoch: lease.controller_epoch.clone(),
                fencing_token: lease.fencing_token,
                lease_expiry_unix_ms: lease.lease_expiry_unix_ms,
            },
        )
        .map_err(|_| NetworkAgentError::Poisoned)?;
        Ok(ControllerLeaseAck {
            fencing_token: lease.fencing_token,
            lease_expiry_unix_ms: lease.lease_expiry_unix_ms,
        })
    }

    fn observe(&self, request: &ObserveCommand) -> Result<CommandResult, NetworkAgentError> {
        let command_id = parse_uuid(&request.command_id, "command_id")?;
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let Runtime {
            executor, realizer, ..
        } = &mut *runtime;
        let status = executor
            .reconcile(command_id, realizer)
            .map_err(|error| NetworkAgentError::Execution(execution_error_code(&error)))?;
        Ok(CommandResult {
            command_id: request.command_id.clone(),
            status: if status == o3k_network::NetworkPlanStatus::Succeeded {
                "succeeded"
            } else {
                "unknown"
            }
            .to_owned(),
            replayed: true,
            error_code: String::new(),
        })
    }

    fn register(&self, request: &proto::Register) -> Result<RegisterAck, NetworkAgentError> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        if request.agent_id != runtime.executor.agent_id()
            || request.agent_epoch != runtime.executor.agent_epoch()
        {
            return Err(NetworkAgentError::Malformed("stale agent identity"));
        }
        drop(runtime);
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        runtime.registered = true;
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
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| NetworkAgentError::Poisoned)?;
        let Runtime {
            executor,
            realizer,
            registered,
            lease_expiry_unix_ms,
        } = &mut *runtime;
        if *lease_expiry_unix_ms != 0 && now_ms()? >= *lease_expiry_unix_ms {
            return Err(NetworkAgentError::Malformed("controller lease expired"));
        }
        if !*registered {
            return Err(NetworkAgentError::Malformed("register is required first"));
        }
        let admission = match executor.execute(&internal, now, realizer) {
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
            PlanAdmission::ReplayedUnknown | PlanAdmission::RequiresObservation => {
                match executor.reconcile(command_id, realizer) {
                    Ok(o3k_network::NetworkPlanStatus::Succeeded) => ("recovered", true),
                    Ok(o3k_network::NetworkPlanStatus::Unknown) | Err(_) => ("unknown", true),
                    Ok(o3k_network::NetworkPlanStatus::Accepted)
                    | Ok(o3k_network::NetworkPlanStatus::Applying) => ("unknown", true),
                }
            }
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
                    }) if registered => match service.execute(&command) {
                        Ok(result) => ControlResponse {
                            body: Some(ResponseBody::Result(result)),
                        },
                        Err(error) => error_response(error_code(&error)),
                    },
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
                    }) if registered => match service.observe(&observe) {
                        Ok(result) => ControlResponse {
                            body: Some(ResponseBody::Result(result)),
                        },
                        Err(error) => error_response(error_code(&error)),
                    },
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

fn lease_path(executor: &NetworkPlanExecutor) -> std::path::PathBuf {
    executor.state_root().join("controller-lease.json")
}

fn load_lease(executor: &NetworkPlanExecutor) -> Result<Option<PersistedLease>, std::io::Error> {
    match fs::read(lease_path(executor)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt controller lease")
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn store_lease(
    executor: &NetworkPlanExecutor,
    lease: &PersistedLease,
) -> Result<(), std::io::Error> {
    let path = lease_path(executor);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(lease)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "lease serialization"))?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
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
}
