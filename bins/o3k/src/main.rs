use clap::{Parser, Subcommand};
use std::process::ExitCode;
use std::sync::Arc;

use o3k::upgrade::engine::{UpgradeArgs, UpgradeOutcome, run_rollback, run_upgrade};
use o3k::upgrade::output::{UpgradeJson, UpgradeStatus};
use o3k::upgrade::runner::SystemUpgradeIo;
use o3k::{Context, ReleaseVersion, SqlxDoctorDb, SystemExec, SystemHttpClient, native_cli};

#[derive(Parser)]
#[command(name = "o3k", version, about = "O3K operator and cloud-user CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run read-only installation diagnostics
    Doctor {
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Print the binary and installed release versions
    Version,
    /// Upgrade the installation
    Upgrade {
        /// Target release version (e.g. v0.4.0)
        #[arg(long)]
        to: Option<String>,
        /// Check preflight only (no mutation)
        #[arg(long)]
        check: bool,
        /// Skip confirmation prompts
        #[arg(short, long)]
        yes: bool,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Restore the previous release
    Rollback {
        /// Skip confirmation prompts
        #[arg(short, long)]
        yes: bool,
        /// Machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Native API service operations
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Native API resource-type operations
    ResourceType {
        #[command(subcommand)]
        action: ResourceTypeAction,
    },
    /// Native API generic resource operations
    Resource {
        #[command(subcommand)]
        action: ResourceAction,
    },
    /// Initialize the canonical Cloud Kernel and selected CloudProfile.
    Init {
        #[arg(long)]
        profile_id: Option<String>,
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// Enroll a prepared execution host with a single-use bootstrap grant.
    Join {
        /// Enrollment token. Prefer O3K_ENROLLMENT_TOKEN_FILE on shared hosts:
        /// a token passed on argv is visible in /proc/<pid>/cmdline.
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        agent_epoch: String,
        #[arg(long)]
        certificate: std::path::PathBuf,
        #[arg(long)]
        region: Option<String>,
        #[arg(long)]
        availability_domain: Option<String>,
        #[arg(long)]
        failure_domain_id: Option<String>,
        #[arg(long, default_value_t = 0)]
        vcpus: u64,
        #[arg(long, default_value_t = 0)]
        memory_mb: u64,
        #[arg(long, default_value_t = 0)]
        disk_gb: u64,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// List registered services
    List,
    /// Show service details
    Show { id: String },
}

#[derive(Subcommand)]
enum ResourceTypeAction {
    /// List known resource types
    List,
}

#[derive(Subcommand)]
enum ResourceAction {
    /// List resources of a type (namespace:type)
    List { resource_type: String },
    /// Show a specific resource
    Show { resource_type: String, id: String },
    /// Create a resource from a JSON file
    Create {
        resource_type: String,
        file: std::path::PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Delete a resource
    Delete {
        resource_type: String,
        id: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { json } => run_doctor(json),
        Commands::Version => run_version(),
        Commands::Upgrade {
            to,
            check,
            yes,
            json,
        } => {
            let requested = to
                .as_deref()
                .map(|v| {
                    v.parse::<ReleaseVersion>()
                        .map_err(|e| format!("invalid version '{v}': {e}"))
                })
                .transpose();
            match requested {
                Ok(r) => run_upgrade_cli(r, check, yes, json),
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::Rollback { yes: _, json } => run_rollback_cli(json),
        Commands::Service { action } => match action {
            ServiceAction::List => handle_result(native_cli::list_services()),
            ServiceAction::Show { id } => handle_result(native_cli::show_service(&id)),
        },
        Commands::ResourceType { action } => match action {
            ResourceTypeAction::List => handle_result(native_cli::list_resource_types()),
        },
        Commands::Resource { action } => match action {
            ResourceAction::List { resource_type } => {
                handle_result(native_cli::list_resources(&resource_type))
            }
            ResourceAction::Show { resource_type, id } => {
                handle_result(native_cli::show_resource(&resource_type, &id))
            }
            ResourceAction::Create {
                resource_type,
                file,
                idempotency_key,
            } => handle_result(native_cli::create_resource(
                &resource_type,
                &file,
                idempotency_key.as_deref(),
            )),
            ResourceAction::Delete {
                resource_type,
                id,
                idempotency_key,
            } => handle_result(native_cli::delete_resource(
                &resource_type,
                &id,
                idempotency_key.as_deref(),
            )),
        },
        Commands::Init {
            profile_id,
            agent_id,
        } => handle_result(native_cli::init(profile_id.as_deref(), agent_id.as_deref())),
        Commands::Join {
            token,
            agent_id,
            agent_epoch,
            certificate,
            region,
            availability_domain,
            failure_domain_id,
            vcpus,
            memory_mb,
            disk_gb,
        } => handle_result(native_cli::join(
            token.as_deref(),
            &agent_id,
            &agent_epoch,
            &certificate,
            region.as_deref(),
            availability_domain.as_deref(),
            failure_domain_id.as_deref(),
            vcpus,
            memory_mb,
            disk_gb,
        )),
    }
}

fn handle_result(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn build_runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            eprintln!("o3k: failed to build the async runtime: {error}");
            ExitCode::from(2)
        })
}

fn run_version() -> ExitCode {
    println!("o3k {}", env!("CARGO_PKG_VERSION"));
    let installed = installed_version();
    println!("installed {installed}");
    ExitCode::SUCCESS
}

fn installed_version() -> String {
    let prefix = std::env::var("O3K_UPGRADE_PREFIX")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local"));
    let candidates = [prefix, std::path::PathBuf::from("/usr")];
    for candidate in &candidates {
        let manifest = candidate.join("share/o3k/release-manifest.json");
        let Ok(contents) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
            continue;
        };
        if let Some(version) = value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .filter(|version| !version.is_empty())
        {
            return version.to_owned();
        }
    }
    "unknown".to_owned()
}

fn run_doctor(json: bool) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    let is_root = o3k::context::current_euid() == 0;
    let context = Context::load(
        Arc::new(SystemExec::new(is_root)),
        Arc::new(SystemHttpClient),
        Arc::new(SqlxDoctorDb),
    );
    let report = runtime.block_on(o3k::run_all(&context));
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("o3k: failed to serialize the report: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!("{}", report.render_human());
    }
    if report.overall_status == o3k::OverallStatus::Healthy {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_upgrade_cli(
    requested: Option<ReleaseVersion>,
    check_only: bool,
    assume_yes: bool,
    json: bool,
) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    let io = SystemUpgradeIo::from_env();
    let args = UpgradeArgs {
        requested,
        check_only,
        assume_yes,
        doctor_retry_attempts: std::env::var("O3K_UPGRADE_DOCTOR_RETRY_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5),
        doctor_retry_delay_ms: std::env::var("O3K_UPGRADE_DOCTOR_RETRY_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15_000),
    };
    let outcome = runtime.block_on(run_upgrade(&io, &args));
    render_upgrade_outcome("upgrade", outcome, json)
}

fn run_rollback_cli(json: bool) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    let io = SystemUpgradeIo::from_env();
    let outcome = runtime.block_on(run_rollback(&io));
    render_upgrade_outcome("rollback", outcome, json)
}

fn render_upgrade_outcome(command: &str, outcome: UpgradeOutcome, json: bool) -> ExitCode {
    if json {
        let serialized = UpgradeJson::new(
            outcome.source_version.as_ref().map(ToString::to_string),
            outcome.target_version.as_ref().map(ToString::to_string),
            Some(outcome.phase),
            outcome.backup_id.clone(),
            outcome.status,
            outcome.rollback_performed,
            outcome.doctor_status.clone(),
        );
        match serde_json::to_string_pretty(&serialized) {
            Ok(serialized) => println!("{serialized}"),
            Err(error) => {
                eprintln!("o3k {command}: failed to serialize the result: {error}");
                return ExitCode::from(2);
            }
        }
        if let Some(error) = &outcome.error {
            eprintln!("o3k {command}: {error}");
        }
    } else {
        render_upgrade_human(command, &outcome);
    }
    match outcome.status {
        UpgradeStatus::Committed | UpgradeStatus::RolledBack | UpgradeStatus::CheckPassed => {
            ExitCode::SUCCESS
        }
        UpgradeStatus::Failed | UpgradeStatus::CheckBlocked => ExitCode::from(1),
    }
}

fn render_upgrade_human(command: &str, outcome: &UpgradeOutcome) {
    let versions = match (&outcome.source_version, &outcome.target_version) {
        (Some(source), Some(target)) => format!("{source} -> {target}"),
        _ => "unknown".to_owned(),
    };
    match outcome.status {
        UpgradeStatus::Committed => {
            println!("o3k {command}: upgrade committed: {versions}");
            if let Some(doctor) = &outcome.doctor_status {
                println!("o3k {command}: doctor overall: {doctor}");
            }
        }
        UpgradeStatus::RolledBack => {
            println!("o3k {command}: rollback completed: {versions}");
        }
        UpgradeStatus::CheckPassed => {
            println!("o3k {command}: check passed: {versions}");
        }
        UpgradeStatus::CheckBlocked => {
            if let Some(error) = &outcome.error {
                eprintln!("o3k {command}: check blocked: {error}");
            } else {
                eprintln!("o3k {command}: check blocked");
            }
        }
        UpgradeStatus::Failed => {
            if let Some(error) = &outcome.error {
                eprintln!("o3k {command}: {error}");
            } else {
                eprintln!("o3k {command}: failed");
            }
        }
    }
}
