//! Real system implementations of the three seams: process execution,
//! hand-rolled HTTP/1.1, and read-only SQLite (the database implementation
//! lives in [`crate::db`]).
//!
//! Everything here is bounded: commands carry a 10-second timeout, HTTP
//! connects/reads/writes carry 2-second timeouts, and file reads are small
//! config or `/proc` artifacts. Nothing in this module mutates host state.

use crate::context::{Exec, HttpClient, HttpResponse, UnitState};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bound on any single host command.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on HTTP connect/read/write operations.
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
/// Upper bound on a response body doctor will accept. Local health and
/// token endpoints answer in kilobytes; a larger response is truncated so a
/// misbehaving local service can never exhaust doctor's memory.
const MAX_HTTP_RESPONSE_BYTES: usize = 1024 * 1024;

/// Outcome of a bounded synchronous host command.
pub(crate) struct CommandOutcome {
    pub(crate) output: std::process::Output,
    /// False when the command was killed after exceeding the bound.
    pub(crate) completed: bool,
}

/// Reads a byte stream to its end, ignoring read errors (the exit status and
/// partial output are what the caller judges).
fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = reader.read_to_end(&mut buffer);
    buffer
}

/// Runs a host command with a bounded wait. On timeout the child is killed
/// and the outcome is marked incomplete. A missing binary reports an
/// [`std::io::ErrorKind::NotFound`] spawn error to the caller.
pub(crate) fn run_bounded(command: &mut Command) -> std::io::Result<CommandOutcome> {
    run_bounded_with_timeout(command, COMMAND_TIMEOUT)
}

/// [`run_bounded`] with an explicit bound (the upgrade runner needs longer
/// bounds for downloads and service stop/start).
pub(crate) fn run_bounded_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<CommandOutcome> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                let stdout = child.stdout.take().map(read_all);
                let stderr = child.stderr.take().map(read_all);
                return Ok(CommandOutcome {
                    output: std::process::Output {
                        status,
                        stdout: stdout.unwrap_or_default(),
                        stderr: stderr.unwrap_or_default(),
                    },
                    completed: true,
                });
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(CommandOutcome {
                    output: std::process::Output {
                        status: std::process::ExitStatus::default(),
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    },
                    completed: false,
                });
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Reduces a completed command outcome to a trimmed stderr message.
pub(crate) fn stderr_message(output: &std::process::Output) -> String {
    let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if message.is_empty() {
        "command failed without a message".to_owned()
    } else {
        crate::context::sanitize_error(&message)
    }
}

/// Real [`Exec`] implementation backed by `systemctl`, `virsh`, `ip`, `df`,
/// `/proc`, and the local filesystem.
pub struct SystemExec {
    pub is_root: bool,
}

impl SystemExec {
    /// Creates the real exec seam.
    #[must_use]
    pub const fn new(is_root: bool) -> Self {
        Self { is_root }
    }

    /// Bounded `systemctl is-active` runner.
    async fn systemctl_is_active_inner(&self, unit: &str) -> UnitState {
        let mut command = Command::new("systemctl");
        command.args(["is-active", unit]);
        match run_bounded(&mut command) {
            Ok(outcome) if !outcome.completed => UnitState::Unknown,
            Ok(outcome) if outcome.output.status.success() => UnitState::Active,
            Ok(outcome) => match outcome.output.status.code() {
                Some(3) => UnitState::Inactive,
                // systemctl reports exit 4 for a unit that does not exist.
                Some(4) => UnitState::NotFound,
                Some(_) => UnitState::Failed,
                None => UnitState::Unknown,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => UnitState::NotFound,
            Err(_) => UnitState::Unknown,
        }
    }

    /// argv for the compute-identity `runuser` virsh probe. util-linux does
    /// not split `-G` values on commas (`getgrnam` receives the whole optarg),
    /// so each supplementary group needs its own `-G` flag. Kept as an
    /// associated function so the exact argv is covered by a unit test.
    fn compute_probe_argv() -> Vec<String> {
        [
            "-u",
            "o3k-compute",
            "-g",
            "o3k-compute",
            "-G",
            "libvirt",
            "-G",
            "kvm",
            "--",
            "virsh",
            "-c",
            "qemu:///system",
            "uri",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    /// Bounded `virsh -c qemu:///system uri`, optionally under `sudo` when
    /// running as root. For the compute identity `runuser` (util-linux) sets
    /// the supplementary groups mirroring the compute unit's
    /// `SupplementaryGroups=libvirt kvm` so the probe reproduces the real
    /// agent's socket access (plain `sudo -u` drops them; Ubuntu's sudo
    /// build lacks `-G`); the control-identity probe keeps no extra groups
    /// so a granted connection still means a boundary breach.
    async fn virsh_uri_inner(&self, user: Option<&str>) -> Result<String, String> {
        let mut command = if self.is_root {
            let Some(user) = user else {
                return self.virsh_uri_inner_unprivileged().await;
            };
            if user == "o3k-compute" {
                // runuser (util-linux) sets supplementary groups, which sudo
                // on both target distros cannot (`-G` is unavailable in
                // Ubuntu's sudo build). util-linux does not split `-G` values
                // on commas (getgrnam on the whole optarg), so each group
                // needs its own `-G`. The groups mirror the compute unit's
                // SupplementaryGroups=libvirt kvm so the probe reproduces the
                // real agent's socket access.
                let mut run = Command::new("runuser");
                run.args(Self::compute_probe_argv());
                run
            } else {
                let mut run = Command::new("sudo");
                run.args(["-u", user, "--", "virsh", "-c", "qemu:///system", "uri"]);
                run
            }
        } else {
            return self.virsh_uri_inner_unprivileged().await;
        };
        match run_bounded(&mut command) {
            Ok(outcome) if !outcome.completed => Err("virsh timed out".to_owned()),
            Ok(outcome) if outcome.output.status.success() => {
                Ok(String::from_utf8_lossy(&outcome.output.stdout)
                    .trim()
                    .to_owned())
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("virsh is not installed".to_owned())
            }
            Err(error) => Err(format!("virsh failed to start: {error}")),
        }
    }

    /// `virsh -c qemu:///system uri` as the current user.
    async fn virsh_uri_inner_unprivileged(&self) -> Result<String, String> {
        let mut command = Command::new("virsh");
        command.args(["-c", "qemu:///system", "uri"]);
        match run_bounded(&mut command) {
            Ok(outcome) if !outcome.completed => Err("virsh timed out".to_owned()),
            Ok(outcome) if outcome.output.status.success() => {
                Ok(String::from_utf8_lossy(&outcome.output.stdout)
                    .trim()
                    .to_owned())
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("virsh is not installed".to_owned())
            }
            Err(error) => Err(format!("virsh failed to start: {error}")),
        }
    }

    /// Bounded `virsh -c qemu:///system list --all --name`.
    async fn virsh_list_names_inner(&self) -> Result<Vec<String>, String> {
        let mut command = Command::new("virsh");
        command.args(["-c", "qemu:///system", "list", "--all", "--name"]);
        match run_bounded(&mut command) {
            Ok(outcome) if !outcome.completed => Err("virsh timed out".to_owned()),
            Ok(outcome) if outcome.output.status.success() => {
                let text = String::from_utf8_lossy(&outcome.output.stdout);
                Ok(text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect())
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("virsh is not installed".to_owned())
            }
            Err(error) => Err(format!("virsh failed to start: {error}")),
        }
    }

    /// Bounded `ip -o link show`.
    async fn ip_link_names_inner(&self) -> Result<Vec<String>, String> {
        let mut command = Command::new("ip");
        command.args(["-o", "link", "show"]);
        match run_bounded(&mut command) {
            Ok(outcome) if !outcome.completed => Err("ip command timed out".to_owned()),
            Ok(outcome) if outcome.output.status.success() => {
                let text = String::from_utf8_lossy(&outcome.output.stdout);
                let mut names = Vec::new();
                for line in text.lines() {
                    // Format: `1: lo: <LOOPBACK,UP,LOWER_UP> ...`
                    let mut fields = line.split_whitespace();
                    let _index = fields.next();
                    let Some(name) = fields.next() else {
                        continue;
                    };
                    let name = name.strip_suffix(':').unwrap_or(name);
                    if !name.is_empty() {
                        names.push(name.to_owned());
                    }
                }
                Ok(names)
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("ip is not installed".to_owned())
            }
            Err(error) => Err(format!("ip failed to start: {error}")),
        }
    }

    /// Bounded `df -Pk <path>`; returns available KiB.
    async fn df_avail_kib_inner(&self, path: &Path) -> Result<u64, String> {
        let mut command = Command::new("df");
        command.args(["-Pk", &path.display().to_string()]);
        match run_bounded(&mut command) {
            Ok(outcome) if !outcome.completed => Err("df command timed out".to_owned()),
            Ok(outcome) if outcome.output.status.success() => {
                let text = String::from_utf8_lossy(&outcome.output.stdout);
                let mut rows = text.lines().skip(1);
                let Some(row) = rows.next() else {
                    return Err("df output is missing the filesystem row".to_owned());
                };
                let available = row.split_whitespace().nth(3).unwrap_or("");
                available
                    .parse::<u64>()
                    .map_err(|_| "df output is not a number".to_owned())
            }
            Ok(outcome) => Err(stderr_message(&outcome.output)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("df is not installed".to_owned())
            }
            Err(error) => Err(format!("df failed to start: {error}")),
        }
    }
}

#[async_trait]
impl Exec for SystemExec {
    async fn systemctl_is_active(&self, unit: &str) -> UnitState {
        self.systemctl_is_active_inner(unit).await
    }

    async fn virsh_uri(&self, user: Option<&str>) -> Result<String, String> {
        self.virsh_uri_inner(user).await
    }

    async fn virsh_list_names(&self) -> Result<Vec<String>, String> {
        self.virsh_list_names_inner().await
    }

    async fn ip_link_names(&self) -> Result<Vec<String>, String> {
        self.ip_link_names_inner().await
    }

    async fn df_avail_kib(&self, path: &Path) -> Result<u64, String> {
        self.df_avail_kib_inner(path).await
    }

    fn proc_alive(&self, pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        // A zombie has already terminated; mirror `bins/o3k-compute`'s
        // `pid_is_alive` so a reaped dnsmasq never counts as live.
        stat.split_whitespace().nth(2) != Some("Z")
    }

    fn proc_cmdline(&self, pid: u32) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        Some(String::from_utf8_lossy(&raw).into_owned())
    }

    fn proc_start_time_ticks(&self, pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The comm field may contain spaces; everything after the last ')'
        // is the whitespace-separated field list, with starttime at index 19
        // (mirrors `o3k-dhcp::process_starttime`).
        let after_comm = stat.get(stat.rfind(')')? + 1..)?.trim_start();
        let ticks = after_comm.split_whitespace().nth(19)?.parse::<u64>().ok()?;
        Some(ticks.to_string())
    }

    fn read_file(&self, path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path)
            .map_err(|error| crate::context::sanitize_error(&error.to_string()))
    }

    fn read_dir_names(&self, path: &Path) -> Result<Vec<String>, String> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(crate::context::sanitize_error(&error.to_string()));
            }
        };
        let mut names = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    fn is_regular_file(&self, path: &Path) -> bool {
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_file(),
            Err(_) => false,
        }
    }

    #[cfg(unix)]
    fn is_char_device(&self, path: &Path) -> bool {
        use std::os::unix::fs::FileTypeExt;
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.file_type().is_char_device(),
            Err(_) => false,
        }
    }

    #[cfg(not(unix))]
    fn is_char_device(&self, path: &Path) -> bool {
        let _ = path;
        false
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    #[cfg(unix)]
    fn file_mode(&self, path: &Path) -> Result<u32, String> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|error| crate::context::sanitize_error(&error.to_string()))?;
        Ok(metadata.permissions().mode() & 0o7777)
    }

    #[cfg(not(unix))]
    fn file_mode(&self, path: &Path) -> Result<u32, String> {
        let _ = path;
        Err("file permissions are unavailable on this platform".to_owned())
    }

    fn sha256_file(&self, path: &Path) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        const MAX_HASH_FILE_BYTES: u64 = 128 * 1024 * 1024;
        let size = std::fs::metadata(path)
            .map_err(|error| crate::context::sanitize_error(&error.to_string()))?
            .len();
        if size > MAX_HASH_FILE_BYTES {
            return Err("file is too large to hash".to_owned());
        }
        let bytes = std::fs::read(path)
            .map_err(|error| crate::context::sanitize_error(&error.to_string()))?;
        let digest = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Ok(hex)
    }
}

/// Real [`HttpClient`] implementation: hand-rolled HTTP/1.1 over
/// `std::net::TcpStream` with 2-second connect/read/write bounds. Supports
/// exactly the plain `http://` URLs doctor uses; no TLS, no redirects.
#[derive(Debug, Clone, Copy)]
pub struct SystemHttpClient;

/// Parses `http://host[:port]/path` into (host, port, path).
fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Err("only plain http:// URLs are supported".to_owned());
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() {
        return Err("URL host is empty".to_owned());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let Some((host, tail)) = rest.split_once(']') else {
            return Err("URL host is malformed".to_owned());
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => port
                .parse::<u16>()
                .map_err(|_| "URL port is invalid".to_owned())?,
            None => 80,
        };
        (host.to_owned(), port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (
                host.to_owned(),
                port.parse::<u16>()
                    .map_err(|_| "URL port is invalid".to_owned())?,
            ),
            None => (authority.to_owned(), 80),
        }
    };
    if host.is_empty() {
        return Err("URL host is empty".to_owned());
    }
    Ok((host, port, path))
}

/// Host header value including a non-default port and IPv6 brackets.
fn authority_header(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// One bounded HTTP exchange.
fn request_with_key(
    url: &str,
    method: &str,
    body: Option<&str>,
    key: Option<&str>,
    header: Option<(&str, &str)>,
) -> Result<HttpResponse, String> {
    let (host, port, path) = parse_http_url(url)?;
    let address = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &address
            .parse()
            .map_err(|_| "URL address is invalid".to_owned())?,
        HTTP_TIMEOUT,
    )
    .map_err(|error| format!("connection to {address} failed: {error}"))?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .map_err(|error| format!("read timeout setup failed: {error}"))?;
    stream
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .map_err(|error| format!("write timeout setup failed: {error}"))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        authority_header(&host, port)
    );
    if let Some(body) = body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if let Some(key) = key {
        head.push_str(&format!("Idempotency-Key: {key}\r\n"));
    }
    if let Some((name, value)) = header {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut payload = head.into_bytes();
    if let Some(body) = body {
        payload.extend_from_slice(body.as_bytes());
    }
    stream
        .write_all(&payload)
        .map_err(|error| format!("request write failed: {error}"))?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("response read failed: {error}"))?;
        if read == 0 {
            break;
        }
        if response.len() + read > MAX_HTTP_RESPONSE_BYTES {
            response.extend_from_slice(&chunk[..MAX_HTTP_RESPONSE_BYTES - response.len()]);
            // The connection is closed by the server (Connection: close);
            // dropping the stream discards the oversized remainder.
            break;
        }
        response.extend_from_slice(&chunk[..read]);
    }
    let response = String::from_utf8_lossy(&response);
    let (head, body) = match response.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => return Err("response is not HTTP/1.1".to_owned()),
    };
    let mut lines = head.lines();
    let Some(status_line) = lines.next() else {
        return Err("response has no status line".to_owned());
    };
    let mut status_parts = status_line.split_whitespace();
    match status_parts.next() {
        Some("HTTP/1.1") | Some("HTTP/1.0") => {}
        _ => return Err("response has an unknown protocol".to_owned()),
    }
    let Some(code) = status_parts.next() else {
        return Err("response has no status code".to_owned());
    };
    let status: u16 = code
        .parse()
        .map_err(|_| "response status is not a number".to_owned())?;
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_owned(),
    })
}
fn request(url: &str, method: &str, body: Option<&str>) -> Result<HttpResponse, String> {
    request_with_key(url, method, body, None, None)
}

#[async_trait]
impl HttpClient for SystemHttpClient {
    async fn get(&self, url: &str) -> Result<HttpResponse, String> {
        request(url, "GET", None)
    }

    async fn post_json(&self, url: &str, body: &str) -> Result<HttpResponse, String> {
        request(url, "POST", Some(body))
    }
    async fn post_json_with_header(
        &self,
        url: &str,
        body: &str,
        header: Option<(&str, &str)>,
    ) -> Result<HttpResponse, String> {
        request_with_key(url, "POST", Some(body), None, header)
    }
    async fn delete(&self, url: &str) -> Result<HttpResponse, String> {
        request(url, "DELETE", None)
    }
    async fn post_json_with_idempotency(
        &self,
        url: &str,
        body: &str,
        key: Option<&str>,
    ) -> Result<HttpResponse, String> {
        request_with_key(url, "POST", Some(body), key, None)
    }
    async fn delete_with_idempotency(
        &self,
        url: &str,
        key: Option<&str>,
    ) -> Result<HttpResponse, String> {
        request_with_key(url, "DELETE", None, key, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_probe_argv_uses_repeated_supp_group_flags() {
        let argv = SystemExec::compute_probe_argv();
        assert_eq!(
            argv,
            [
                "-u",
                "o3k-compute",
                "-g",
                "o3k-compute",
                "-G",
                "libvirt",
                "-G",
                "kvm",
                "--",
                "virsh",
                "-c",
                "qemu:///system",
                "uri",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
        );
        // No single -G may carry a comma-separated list: util-linux runuser
        // passes the whole optarg to getgrnam without splitting.
        assert!(argv.windows(2).all(|w| w[1] != "-G" || !w[0].contains(',')));
    }
}
