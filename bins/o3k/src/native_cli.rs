//! Native API CLI commands.
//!
//! These commands talk to a running O3K native API endpoint (typically
//! served by `o3kd` at the configured endpoint).
//!
//! Architecture:
//! - `o3k service list` / `o3k service show` — discover registered services
//! - `o3k resource-type list` — discover registered resource types
//! - `o3k resource list <ns:type>` — list resources of a given type
//! - `o3k resource show <ns:type> <id>` — show a specific resource
//!
//! The underlying protocol is O3K native HTTP API (ADR-0173/SPEC-0030).

use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::HttpClient;
use crate::context::HttpResponse;
use crate::sys::{RequestError, SystemHttpClient, request_with_key};
use o3k_compute_agent::types::EnrollmentIdentity;
use o3k_provider_contract::compute_proto::{
    EnrollRequest, ProtocolVersion, compute_enrollment_client::ComputeEnrollmentClient,
};
use openssl::{pkey::PKey, x509::X509Req};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

/// Default native API base URL.
const DEFAULT_API_BASE: &str = "http://127.0.0.1:18080/o3k/v1";

/// Maximum number of `bootstrap/init` attempts after a transport failure.
const INIT_MAX_ATTEMPTS: usize = 3;
/// Fixed backoff between `bootstrap/init` attempts.
const INIT_RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// Total deadline across all `bootstrap/init` attempts and backoffs.
const INIT_TOTAL_DEADLINE: Duration = Duration::from_secs(12);

/// Returns the effective API base URL from environment or default.
fn api_base() -> String {
    std::env::var("O3K_API_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE.to_owned())
}

/// Small runtime reused for each API call (cheap: current-thread, no spawn).
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))
}

/// Reads a secret from the environment, or — when the variable is unset or
/// empty — from the file whose path is named by `<ENV>_FILE`. File contents
/// are trimmed of surrounding whitespace. File-based intake exists so shared
/// hosts never carry secrets through `/proc/<pid>/cmdline` argv.
fn secret_from_env_or_file(env_var: &str) -> Result<String, String> {
    secret_from(
        std::env::var(env_var).ok(),
        std::env::var(format!("{env_var}_FILE")).ok(),
    )
    .map_err(|detail| format!("{env_var} (or {env_var}_FILE) is required: {detail}"))
}

/// Testable core of [`secret_from_env_or_file`]: resolve from an explicit env
/// value first, then an explicit file path.
fn secret_from(env_value: Option<String>, file_path: Option<String>) -> Result<String, String> {
    if let Some(value) = env_value
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    let path = file_path.ok_or("no file path provided")?;
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read secret file at {path}: {e}"))?;
    let value = content.trim().to_owned();
    if value.is_empty() {
        return Err(format!("secret file at {path} is empty"));
    }
    Ok(value)
}

/// Enrolls a new compute host through the loopback TLS endpoint exposed by the
/// controller. Operators reach this endpoint through an authenticated SSH
/// tunnel; the token and private key never cross that tunnel. The key remains
/// on the joining host and the returned certificate is installed atomically.
pub fn enroll_host(
    token: Option<&str>,
    agent_id: &str,
    agent_epoch: &str,
    endpoint: &str,
    ca_certificate: &Path,
    private_key: &Path,
    certificate: &Path,
) -> Result<(), String> {
    let token = match token.map(str::trim) {
        Some(v) if !v.is_empty() => v.to_owned(),
        _ => secret_from_env_or_file("O3K_ENROLLMENT_TOKEN")?,
    };
    let csr_path = private_key.with_extension("csr.pem");
    let csr = if private_key.exists() || csr_path.exists() {
        if !private_key.exists() || !csr_path.exists() {
            return Err("enrollment identity is partially present; refusing repair".to_owned());
        }
        validate_identity_file(private_key)?;
        validate_identity_file(&csr_path)?;
        let key = std::fs::read(private_key)
            .map_err(|_| "cannot read existing enrollment key".to_owned())?;
        let csr = std::fs::read(&csr_path)
            .map_err(|_| "cannot read existing enrollment CSR".to_owned())?;
        validate_persisted_identity(&key, &csr, agent_id, agent_epoch)?;
        csr
    } else {
        let identity = EnrollmentIdentity::generate(agent_id, agent_epoch)
            .map_err(|e| format!("cannot generate enrollment identity: {e}"))?;
        identity
            .write_private_key(private_key)
            .map_err(|e| format!("cannot persist private key: {e}"))?;
        write_secret_file(&csr_path, identity.csr_pem())?;
        identity.csr_pem().to_vec()
    };
    let ca =
        std::fs::read(ca_certificate).map_err(|e| format!("cannot read enrollment CA: {e}"))?;
    let endpoint = endpoint.to_owned();
    let response = runtime()?.block_on(async move {
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .domain_name(
                std::env::var("O3K_ENROLLMENT_TLS_SERVER_NAME")
                    .unwrap_or_else(|_| "o3k-controller".to_owned()),
            );
        let channel = Endpoint::from_shared(endpoint)
            .map_err(|e| format!("invalid enrollment endpoint: {e}"))?
            .tls_config(tls)
            .map_err(|e| format!("invalid enrollment TLS configuration: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("enrollment tunnel unavailable: {e}"))?;
        let mut client = ComputeEnrollmentClient::new(channel);
        client
            .enroll(tonic::Request::new(EnrollRequest {
                bootstrap_token: token,
                certificate_signing_request_pem: csr,
                requested_host_label: agent_id.to_owned(),
                supported_versions: vec![ProtocolVersion {
                    major: 1,
                    minor: 0,
                    wire_revision: 1,
                }],
            }))
            .await
            .map(|r| r.into_inner())
            .map_err(|e| format!("enrollment rejected: {e}"))
    })?;
    if response.agent_id != agent_id || response.client_certificate_chain_pem.is_empty() {
        return Err("enrollment response identity or certificate is invalid".to_owned());
    }
    let parent = certificate
        .parent()
        .ok_or("certificate path has no parent")?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create certificate directory: {e}"))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        certificate
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("agent.pem"),
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&tmp, &response.client_certificate_chain_pem)
        .map_err(|e| format!("cannot write issued certificate: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect issued certificate: {e}"))?;
    }
    std::fs::rename(&tmp, certificate)
        .map_err(|e| format!("cannot install issued certificate: {e}"))?;
    Ok(())
}

fn validate_identity_file(path: &Path) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "identity file unavailable".to_owned())?;
    if !metadata.file_type().is_file() {
        return Err("identity file is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err("identity file mode is unsafe".to_owned());
        }
    }
    Ok(())
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err("identity file already exists".to_owned());
    }
    let parent = path.parent().ok_or("identity path has no parent")?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create identity directory: {e}"))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("identity"),
        uuid::Uuid::new_v4()
    ));
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    {
        use std::io::Write;
        let mut file = options
            .open(&tmp)
            .map_err(|e| format!("cannot write identity: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("cannot write identity: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync identity: {e}"))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot protect identity: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot install identity: {e}"))
}

fn validate_persisted_identity(
    key: &[u8],
    csr: &[u8],
    agent_id: &str,
    agent_epoch: &str,
) -> Result<(), String> {
    let private = PKey::private_key_from_pem(key)
        .map_err(|_| "stored enrollment key is malformed".to_owned())?;
    let request =
        X509Req::from_pem(csr).map_err(|_| "stored enrollment CSR is malformed".to_owned())?;
    let subject = request
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok().map(|v| v.to_string()));
    let agent_uri = format!("urn:o3k:compute:agent:{agent_id}");
    let epoch_uri = format!("urn:o3k:compute:epoch:{agent_epoch}");
    if subject.as_deref() != Some(agent_id)
        || !csr
            .windows(agent_uri.len())
            .any(|w| w == agent_uri.as_bytes())
        || !csr
            .windows(epoch_uri.len())
            .any(|w| w == epoch_uri.as_bytes())
    {
        return Err("stored enrollment CSR identity does not match requested host".to_owned());
    }
    let request_key = request
        .public_key()
        .map_err(|_| "stored enrollment CSR key unavailable".to_owned())?;
    let a = private
        .public_key_to_pem()
        .map_err(|_| "stored enrollment key unavailable".to_owned())?;
    let b = request_key
        .public_key_to_pem()
        .map_err(|_| "stored enrollment CSR key unavailable".to_owned())?;
    if a != b {
        return Err("stored enrollment key does not match CSR".to_owned());
    }
    Ok(())
}

/// One recorded `bootstrap/init` attempt outcome for stderr diagnostics.
#[derive(Debug)]
struct InitAttemptRecord {
    attempt: usize,
    class: &'static str,
    detail: String,
    elapsed_ms: u128,
}

/// Testable core of `o3k init`: performs the bounded, classified retry of the
/// bootstrap-init exchange and returns the response body plus a record of
/// failed attempts (printed to stderr by the caller). Only transport
/// failures — cases where no HTTP status was received — are retried; the
/// bootstrap-init handler is intentionally replay-safe, while any received
/// HTTP status (including errors) or a malformed response is final. The
/// identical JSON body is sent on every attempt so logical request identity
/// is preserved. The bootstrap secret is never included in any record.
fn init_inner(
    base: &str,
    secret: &str,
    profile_id: Option<&str>,
    agent_id: Option<&str>,
) -> Result<(String, Vec<InitAttemptRecord>), (String, Vec<InitAttemptRecord>)> {
    let body = serde_json::json!({ "profile_id": profile_id, "agent_id": agent_id }).to_string();
    let url = format!("{base}/bootstrap/init");
    let started = Instant::now();
    let mut records = Vec::new();
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        match request_with_key(
            &url,
            "POST",
            Some(&body),
            None,
            Some(("X-O3K-Bootstrap-Secret", secret)),
        ) {
            Ok(response) => {
                if response.status != 200 {
                    let detail = format!("API returned status {}", response.status);
                    records.push(InitAttemptRecord {
                        attempt,
                        class: "http-status",
                        detail: detail.clone(),
                        elapsed_ms: started.elapsed().as_millis(),
                    });
                    return Err((detail, records));
                }
                return Ok((response.body, records));
            }
            Err(RequestError::Malformed(message)) => {
                records.push(InitAttemptRecord {
                    attempt,
                    class: "malformed",
                    detail: message.clone(),
                    elapsed_ms: started.elapsed().as_millis(),
                });
                return Err((message, records));
            }
            Err(RequestError::Transport(message)) => {
                records.push(InitAttemptRecord {
                    attempt,
                    class: "transport",
                    detail: message.clone(),
                    elapsed_ms: started.elapsed().as_millis(),
                });
                if attempt >= INIT_MAX_ATTEMPTS || started.elapsed() >= INIT_TOTAL_DEADLINE {
                    return Err((message, records));
                }
                std::thread::sleep(INIT_RETRY_BACKOFF);
                if started.elapsed() >= INIT_TOTAL_DEADLINE {
                    return Err((message, records));
                }
            }
        }
    }
}

/// Initializes canonical Cloud Kernel bootstrap state. The bootstrap secret is
/// sent only as a request header and is never printed.
pub fn init(profile_id: Option<&str>, agent_id: Option<&str>) -> Result<(), String> {
    let secret = secret_from_env_or_file("O3K_BOOTSTRAP_SECRET")?;
    if secret.contains(['\r', '\n']) {
        return Err("bootstrap secret contains a newline".to_owned());
    }
    match init_inner(&api_base(), &secret, profile_id, agent_id) {
        Ok((body, records)) => {
            print_init_records(&records);
            println!("{body}");
            Ok(())
        }
        Err((error, records)) => {
            print_init_records(&records);
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "bootstrap-init-failed",
                    "attempts": records.len(),
                    "detail": error,
                })
            );
            Err(error)
        }
    }
}

/// Emits one sanitized stderr line per failed `bootstrap/init` attempt. Never
/// includes the secret, the request body, or a full URL; stdout stays pure
/// JSON for callers that parse the enrollment token.
fn print_init_records(records: &[InitAttemptRecord]) {
    for record in records {
        eprintln!(
            "{}",
            serde_json::json!({
                "event": "bootstrap-init-retry",
                "attempt": record.attempt,
                "max_attempts": INIT_MAX_ATTEMPTS,
                "elapsed_ms": record.elapsed_ms,
                "class": record.class,
                "detail": record.detail,
            })
        );
    }
}

/// Enrolls a prepared host. Certificate material is read locally and only the
/// bounded certificate text is sent; private keys are never accepted or
/// emitted by this command. The enrollment token is taken from `--token`,
/// `O3K_ENROLLMENT_TOKEN`, or `O3K_ENROLLMENT_TOKEN_FILE` (preferred on shared
/// hosts: argv is visible in `/proc/<pid>/cmdline`).
#[allow(clippy::too_many_arguments)]
pub fn join(
    token: Option<&str>,
    agent_id: &str,
    agent_epoch: &str,
    certificate: &Path,
    region: Option<&str>,
    availability_domain: Option<&str>,
    failure_domain_id: Option<&str>,
    vcpus: u64,
    memory_mb: u64,
    disk_gb: u64,
) -> Result<(), String> {
    let token = match token.map(str::trim) {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => secret_from_env_or_file("O3K_ENROLLMENT_TOKEN")?,
    };
    if agent_id.trim().is_empty() || agent_epoch.trim().is_empty() {
        return Err("agent id and agent epoch are required".to_owned());
    }
    let cert = std::fs::read_to_string(certificate)
        .map_err(|e| format!("cannot read certificate: {e}"))?;
    if cert.len() > 1024 * 1024 || cert.contains("PRIVATE KEY") {
        return Err("certificate input is invalid".to_owned());
    }
    let mut inventories = serde_json::Map::new();
    if vcpus > 0 {
        inventories.insert("VCPU".into(), serde_json::json!(vcpus));
    }
    if memory_mb > 0 {
        inventories.insert("MEMORY_MB".into(), serde_json::json!(memory_mb));
    }
    if disk_gb > 0 {
        inventories.insert("DISK_GB".into(), serde_json::json!(disk_gb));
    }
    let body = serde_json::json!({ "enrollment_token": token, "agent_id": agent_id, "agent_epoch": agent_epoch, "certificate": cert, "region": region, "availability_domain": availability_domain, "failure_domain_id": failure_domain_id, "capabilities": { "architecture": "unknown", "provider_name": "o3k-cli", "provider_version": env!("CARGO_PKG_VERSION") }, "inventories": inventories });
    let client = SystemHttpClient;
    let rt = runtime()?;
    let response = rt
        .block_on(client.post_json(&format!("{}/bootstrap/join", api_base()), &body.to_string()))?;
    if response.status != 200 {
        return Err(format!("API returned status {}", response.status));
    }
    println!("{}", response.body);
    Ok(())
}

/// Performs a GET request against the native API and returns parsed JSON.
fn api_get(path: &str) -> Result<Value, String> {
    let base = api_base();
    let url = format!("{base}{path}");
    let client = SystemHttpClient;
    let rt = runtime()?;

    let HttpResponse { status, body, .. } = rt.block_on(client.get(&url))?;

    if status != 200 {
        return Err(format!("API returned status {status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("API response parse error: {e}"))
}

fn resolve_resource(ns_type: &str) -> Result<(String, String), String> {
    let (namespace, name) = ns_type
        .split_once(':')
        .ok_or("resource type must be namespace:type")?;
    let json = api_get("/resource-types")?;
    json["resource_types"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["namespace"] == namespace && item["name"] == name)
        })
        .and_then(|item| item["collection"].as_str())
        .map(|collection| (namespace.to_owned(), collection.to_owned()))
        .ok_or_else(|| format!("unknown resource type '{ns_type}'"))
}

/// Lists all registered services.
pub fn list_services() -> Result<(), String> {
    let json = api_get("/services")?;
    let services = json["services"]
        .as_array()
        .ok_or_else(|| "unexpected response format: missing services array".to_owned())?;

    println!("{:<20} {:<16} {:<12}", "ID", "NAMESPACE", "OWNERSHIP");
    println!("{}", "-".repeat(50));
    for svc in services {
        let id = svc["id"].as_str().unwrap_or("?");
        let ns = svc["namespace"].as_str().unwrap_or("?");
        let ownership = svc["ownership"].as_str().unwrap_or("?");
        println!("{id:<20} {ns:<16} {ownership:<12}");
    }
    println!("\nTotal: {} service(s)", services.len());
    Ok(())
}

/// Shows details for a specific service.
pub fn show_service(name: &str) -> Result<(), String> {
    let json = api_get("/services")?;
    let services = json["services"]
        .as_array()
        .ok_or_else(|| "unexpected response format: missing services array".to_owned())?;

    let svc = services
        .iter()
        .find(|s| s["id"].as_str() == Some(name) || s["namespace"].as_str() == Some(name))
        .ok_or_else(|| format!("service '{name}' not found"))?;

    println!("Service:      {}", svc["id"].as_str().unwrap_or("?"));
    println!("Namespace:    {}", svc["namespace"].as_str().unwrap_or("?"));
    println!("Ownership:    {}", svc["ownership"].as_str().unwrap_or("?"));
    println!(
        "Version:      {}",
        svc["service_version"].as_str().unwrap_or("?")
    );
    Ok(())
}

/// Lists all registered resource types.
pub fn list_resource_types() -> Result<(), String> {
    let json = api_get("/resource-types")?;
    let rts = json["resource_types"]
        .as_array()
        .ok_or_else(|| "unexpected response format: missing resource_types array".to_owned())?;

    println!("{:<24} {:<16}", "RESOURCE TYPE", "SERVICE");
    println!("{}", "-".repeat(42));
    for rt in rts {
        let ns = rt["namespace"].as_str().unwrap_or("?");
        let name = rt["name"].as_str().unwrap_or("?");
        let svc = rt["service"].as_str().unwrap_or("?");
        println!("{ns:<8}:{name:<14} {svc:<16}");
    }
    println!("\nTotal: {} resource type(s)", rts.len());
    Ok(())
}

/// Lists resources of a given namespace:type.
pub fn list_resources(ns_type: &str) -> Result<(), String> {
    let (ns, collection) = resolve_resource(ns_type)?;
    let mut cursor = None;
    let mut items = Vec::new();
    loop {
        let path = cursor.as_deref().map_or_else(
            || format!("/{ns}/{collection}"),
            |cursor| format!("/{ns}/{collection}?cursor={cursor}"),
        );
        let json = api_get(&path)?;
        items.extend(json["items"].as_array().cloned().unwrap_or_default());
        cursor = json["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }

    println!("{:<36} {:<20} {:<12}", "ID", "OWNER", "GENERATION");
    println!("{}", "-".repeat(70));
    for item in &items {
        let id = item["metadata"]["id"].as_str().unwrap_or("?");
        let owner = item["metadata"]["owner_scope"].as_str().unwrap_or("?");
        let generation = item["metadata"]["generation"].as_i64().unwrap_or(0);
        println!("{id:<36} {owner:<20} {generation:<12}");
    }
    println!("\nTotal: {} resource(s)", items.len());
    Ok(())
}

/// Shows a specific resource by namespace:type and id.
pub fn show_resource(ns_type: &str, id: &str) -> Result<(), String> {
    let (ns, collection) = resolve_resource(ns_type)?;
    let path = format!("/{ns}/{collection}/{id}");
    let json = api_get(&path)?;

    let pretty =
        serde_json::to_string_pretty(&json).map_err(|e| format!("serialization error: {e}"))?;
    println!("{pretty}");
    Ok(())
}

pub fn create_resource(ns_type: &str, file: &Path, key: Option<&str>) -> Result<(), String> {
    let (ns, collection) = resolve_resource(ns_type)?;
    let body =
        std::fs::read_to_string(file).map_err(|e| format!("cannot read create file: {e}"))?;
    if body.len() > 1024 * 1024 {
        return Err("create file exceeds 1 MiB limit".to_owned());
    }
    let _: Value = serde_json::from_str(&body).map_err(|e| format!("invalid JSON: {e}"))?;
    let client = SystemHttpClient;
    let rt = runtime()?;
    let response = rt.block_on(client.post_json_with_idempotency(
        &format!("{}/{ns}/{collection}", api_base()),
        &body,
        key,
    ))?;
    if response.status != 201 && response.status != 202 {
        return Err(format!(
            "API returned status {}: {}",
            response.status, response.body
        ));
    }
    println!("{}", response.body);
    Ok(())
}

pub fn delete_resource(ns_type: &str, id: &str, key: Option<&str>) -> Result<(), String> {
    let (ns, collection) = resolve_resource(ns_type)?;
    let client = SystemHttpClient;
    let rt = runtime()?;
    let response = rt.block_on(
        client.delete_with_idempotency(&format!("{}/{ns}/{collection}/{id}", api_base()), key),
    )?;
    if response.status != 202 && response.status != 204 {
        return Err(format!(
            "API returned status {}: {}",
            response.status, response.body
        ));
    }
    if !response.body.is_empty() {
        println!("{}", response.body);
    }
    Ok(())
}

/// Prints the help text for native commands.
pub fn print_help() {
    println!("o3k native API commands:");
    println!("  o3k service list                         list registered services");
    println!("  o3k service show <service>                show service details");
    println!("  o3k resource-type list                    list known resource types");
    println!("  o3k resource list <ns:type>               list resources of a type");
    println!("  o3k resource show <ns:type> <id>          show a specific resource");
    println!();
    println!("Environment:");
    println!("  O3K_API_URL   native API base URL (default: {DEFAULT_API_BASE})");
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{secret_from, validate_persisted_identity};
    use o3k_compute_agent::types::EnrollmentIdentity;
    use std::io::Write;
    use std::path::PathBuf;

    fn fixture_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "o3k-native-cli-test-{}-{}",
            name,
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).expect("fixture create");
        file.write_all(contents.as_bytes()).expect("fixture write");
        path
    }

    #[test]
    fn env_value_wins_over_file() {
        let path = fixture_file("envwins", "file-value");
        let value = secret_from(
            Some("  env-value  ".to_owned()),
            Some(path.to_string_lossy().into_owned()),
        )
        .expect("env secret");
        assert_eq!(value, "  env-value  ");
        std::fs::remove_file(&path).expect("fixture cleanup");
    }

    #[test]
    fn secret_file_is_trimmed() {
        let path = fixture_file(
            "trim",
            "  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        );
        let value =
            secret_from(None, Some(path.to_string_lossy().into_owned())).expect("file secret");
        assert_eq!(value.len(), 64);
        std::fs::remove_file(&path).expect("fixture cleanup");
    }

    #[test]
    fn missing_everything_errors() {
        let error = secret_from(None, None).expect_err("must fail");
        assert!(error.contains("no file path"), "{error}");
    }

    #[test]
    fn empty_secret_file_errors() {
        let path = fixture_file("empty", "\n");
        let error =
            secret_from(None, Some(path.to_string_lossy().into_owned())).expect_err("must fail");
        assert!(error.contains("is empty"), "{error}");
        std::fs::remove_file(&path).expect("fixture cleanup");
    }

    #[test]
    fn persisted_identity_reuses_exact_csr_and_rejects_mismatch() {
        let identity = EnrollmentIdentity::generate("host-a", "epoch-1").expect("identity");
        let key_path = std::env::temp_dir().join(format!("o3k-key-{}", uuid::Uuid::new_v4()));
        identity.write_private_key(&key_path).expect("key");
        let key = std::fs::read(&key_path).expect("read key");
        let csr = identity.csr_pem().to_vec();
        validate_persisted_identity(&key, &csr, "host-a", "epoch-1").expect("valid identity");
        assert!(validate_persisted_identity(&key, &csr, "host-b", "epoch-1").is_err());
        std::fs::remove_file(key_path).expect("cleanup");
    }

    use super::init_inner;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Reads one full HTTP request (headers plus the declared Content-Length
    /// body) from a stub-server connection.
    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).expect("stub read");
            assert!(read > 0, "stub connection closed mid-headers");
            buffer.extend_from_slice(&chunk[..read]);
        }
        let head_end = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let content_length = String::from_utf8_lossy(&buffer[..head_end])
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.eq_ignore_ascii_case("content-length"))
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while buffer.len() < head_end + content_length {
            let read = stream.read(&mut chunk).expect("stub read");
            assert!(read > 0, "stub connection closed mid-body");
            buffer.extend_from_slice(&chunk[..read]);
        }
        buffer
    }

    fn request_body(request: &[u8]) -> &[u8] {
        let head_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        &request[head_end..]
    }

    #[test]
    fn init_retries_after_lost_response_with_identical_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local_addr");
        let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&received);
        let server = std::thread::spawn(move || {
            // First connection: read the full request (the server "commits"),
            // then never answer so the client's read times out (transport).
            let (mut stream, _) = listener.accept().expect("accept 1");
            let first = read_http_request(&mut stream);
            seen.lock().expect("lock").push(first);
            std::thread::sleep(std::time::Duration::from_secs(3));
            drop(stream);
            // Second connection: answer normally.
            let (mut stream, _) = listener.accept().expect("accept 2");
            let second = read_http_request(&mut stream);
            seen.lock().expect("lock").push(second);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\n\r\n{\"enrollment_token\":\"tok-123\"}",
                )
                .expect("stub write");
        });
        let (body, records) = init_inner(
            &format!("http://{address}/o3k/v1"),
            "test-secret",
            None,
            Some("agent-1"),
        )
        .expect("init must succeed on the retried attempt");
        let received = received.lock().expect("lock");
        assert_eq!(received.len(), 2, "expected exactly two requests");
        assert_eq!(
            request_body(&received[0]),
            request_body(&received[1]),
            "retry must send a byte-identical body"
        );
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("response JSON");
        assert_eq!(parsed["enrollment_token"], "tok-123");
        assert!(
            records.iter().any(|record| record.class == "transport"),
            "expected a recorded transport failure, got {records:?}"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn init_does_not_retry_http_status_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local_addr");
        let received: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&received);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _request = read_http_request(&mut stream);
            *seen.lock().expect("lock") += 1;
            stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .expect("stub write");
        });
        let error = init_inner(
            &format!("http://{address}/o3k/v1"),
            "test-secret",
            None,
            None,
        )
        .expect_err("401 must fail");
        assert_eq!(error.0, "API returned status 401");
        assert_eq!(
            *received.lock().expect("lock"),
            1,
            "401 must not be retried"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn init_does_not_retry_malformed_responses() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local_addr");
        let received: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&received);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _request = read_http_request(&mut stream);
            *seen.lock().expect("lock") += 1;
            stream
                .write_all(b"GARBAGE BYTES\r\n\r\n")
                .expect("stub write");
        });
        let error = init_inner(
            &format!("http://{address}/o3k/v1"),
            "test-secret",
            None,
            None,
        )
        .expect_err("garbage response must fail");
        assert!(
            error.0.contains("unknown protocol"),
            "error must mention the malformed response, got: {}",
            error.0
        );
        assert_eq!(
            *received.lock().expect("lock"),
            1,
            "malformed response must not be retried"
        );
        server.join().expect("server thread");
    }

    /// Stub handler that reads the full request, then stalls forever without
    /// answering (the protected-gate failure shape: the request commits, the
    /// response is lost).
    fn never_respond(mut stream: TcpStream, received: Arc<Mutex<usize>>) {
        let _request = read_http_request(&mut stream);
        *received.lock().expect("lock") += 1;
        std::thread::sleep(Duration::from_secs(10));
    }

    /// Stub handler that starts a valid response, then stalls mid-response
    /// past the client's 2s read timeout before sending the remainder.
    fn stall_mid_response(mut stream: TcpStream, received: Arc<Mutex<usize>>) {
        let _request = read_http_request(&mut stream);
        *received.lock().expect("lock") += 1;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 31\r\n\r\n{")
            .expect("partial write");
        std::thread::sleep(Duration::from_secs(3));
        // The client timed out and moved on long ago; the remainder write
        // may hit a closed socket, which must not fail the test.
        let _ = stream.write_all(b"\"enrollment_token\":\"tok-123\"}");
    }

    fn assert_deadline_bounded(received: Arc<Mutex<usize>>, elapsed: Duration) {
        // Nominal: 3 attempts x 2s in-flight read timeout + 2 x 250ms
        // backoff = 6.5s; the 12s total deadline must bound the sum.
        assert!(
            elapsed <= Duration::from_secs(11),
            "init_inner exceeded the total deadline: {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(5),
            "init_inner gave up suspiciously early: {elapsed:?}"
        );
        assert_eq!(
            *received.lock().expect("lock"),
            3,
            "init_inner must make exactly 3 attempts against a silent stub"
        );
        eprintln!("init_inner bounded-run elapsed: {elapsed:?}");
    }

    #[test]
    fn init_total_deadline_bounds_silent_stub() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local_addr");
        let received: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let server = {
            let received = Arc::clone(&received);
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let (stream, _) = listener.accept().expect("accept");
                    let received = Arc::clone(&received);
                    std::thread::spawn(move || never_respond(stream, received));
                }
            })
        };
        let started = Instant::now();
        let error = init_inner(
            &format!("http://{address}/o3k/v1"),
            "test-secret",
            None,
            None,
        )
        .expect_err("a silent stub must exhaust attempts and fail");
        let elapsed = started.elapsed();
        assert_deadline_bounded(received, elapsed);
        let records = error.1;
        assert_eq!(records.len(), 3, "one diagnostic record per attempt");
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record.attempt, index + 1);
            assert_eq!(record.class, "transport");
            assert!(
                record.detail.starts_with("response read failed:"),
                "unexpected detail: {}",
                record.detail
            );
        }
        assert!(
            records[1].elapsed_ms > records[0].elapsed_ms,
            "per-attempt elapsed must increase"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn init_total_deadline_bounds_repeated_mid_response_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("local_addr");
        let received: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let server = {
            let received = Arc::clone(&received);
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let (stream, _) = listener.accept().expect("accept");
                    let received = Arc::clone(&received);
                    std::thread::spawn(move || stall_mid_response(stream, received));
                }
            })
        };
        let started = Instant::now();
        let error = init_inner(
            &format!("http://{address}/o3k/v1"),
            "test-secret",
            None,
            None,
        )
        .expect_err("mid-response stalls must exhaust attempts and fail");
        let elapsed = started.elapsed();
        assert_deadline_bounded(received, elapsed);
        for record in &error.1 {
            assert_eq!(record.class, "transport");
            assert!(
                record.detail.starts_with("response read failed:"),
                "unexpected detail: {}",
                record.detail
            );
        }
        server.join().expect("server thread");
    }
}
