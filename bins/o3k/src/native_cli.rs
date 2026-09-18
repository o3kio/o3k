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

use crate::HttpClient;
use crate::context::HttpResponse;
use crate::sys::SystemHttpClient;

/// Default native API base URL.
const DEFAULT_API_BASE: &str = "http://127.0.0.1:18080/o3k/v1";

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

/// Initializes canonical Cloud Kernel bootstrap state. The bootstrap secret is
/// sent only as a request header and is never printed.
pub fn init(profile_id: Option<&str>, agent_id: Option<&str>) -> Result<(), String> {
    let secret = secret_from_env_or_file("O3K_BOOTSTRAP_SECRET")?;
    if secret.contains(['\r', '\n']) {
        return Err("bootstrap secret contains a newline".to_owned());
    }
    let body = serde_json::json!({ "profile_id": profile_id, "agent_id": agent_id });
    let client = SystemHttpClient;
    let rt = runtime()?;
    let response = rt.block_on(client.post_json_with_header(
        &format!("{}/bootstrap/init", api_base()),
        &body.to_string(),
        Some(("X-O3K-Bootstrap-Secret", secret.as_str())),
    ))?;
    if response.status != 200 {
        return Err(format!("API returned status {}", response.status));
    }
    println!("{}", response.body);
    Ok(())
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
#[allow(clippy::expect_used)]
mod tests {
    use super::secret_from;
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
}
