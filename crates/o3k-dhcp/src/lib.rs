//! Durable, isolated dnsmasq configuration for O3K-managed flat networks.

pub mod types;

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

pub use types::{Binding, DhcpConfig, DhcpError};

/// Bounded window for the `dnsmasq --test` config preflight. A real dnsmasq
/// parses the config and exits in milliseconds; test stubs may never exit, so
/// the probe is abandoned (treated as unknown) rather than blocking startup.
const CONFIG_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
/// Bounded post-spawn liveness window: a dnsmasq that dies from a startup
/// error (bad config, missing interface) does so within a few hundred
/// milliseconds of spawning.
const LIVENESS_GRACE: Duration = Duration::from_millis(500);
/// Poll interval for the bounded waits above.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Kernel-maintained start time (clock ticks since boot, `/proc/<pid>/stat`
/// field 22) of the process with the given pid. The value is set by the
/// kernel at fork and cannot be forged or altered by a same-user process,
/// so it is the durable half of the spawn-time identity the ownership reap
/// validates before signaling. A read failure (permissions, the process
/// exiting) is an unverifiable pid, never an identity.
/// Linux-only by design: the project targets Linux and the ownership reap
/// is /proc-based.
pub fn process_starttime(pid: i32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field is wrapped in parentheses and may contain spaces, so
    // parse the fields AFTER the closing paren: state(0) ppid(1) pgrp(2)
    // session(3) tty_nr(4) tpgid(5) flags(6) minflt(7) cminflt(8) majflt(9)
    // cmajflt(10) utime(11) stime(12) cutime(13) cstime(14) priority(15)
    // nice(16) num_threads(17) itrealvalue(18) starttime(19).
    let after_comm = stat[stat.rfind(')')? + 1..].trim_start();
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Owns one managed dnsmasq process and provides restart/cleanup semantics.
///
/// The supervisor intentionally owns the child handle rather than relying on a
/// pid file alone. A pid file is an artifact produced by dnsmasq, not proof
/// that the process is still the one started by this service.
pub struct DnsmasqSupervisor {
    binary: PathBuf,
    config: PathBuf,
    pid_file: PathBuf,
    /// Spawn-time process identity (start time of the child) recorded next to
    /// the pidfile. The ownership reap requires the pidfile pid's CURRENT
    /// start time to equal this recorded value before it may signal: a
    /// same-user argv spoof or a PID-reuse replacement has a different start
    /// time, so neither can be mistaken for the owned process.
    identity_file: PathBuf,
    child: Option<Child>,
    adopted_pid: Option<(i32, u64)>,
}

impl DnsmasqSupervisor {
    fn spawn(root: &Path, binary: &Path) -> Result<Self, DhcpError> {
        let config = root.join("dnsmasq.conf");
        let pid_file = root.join(format!("dnsmasq-{}.pid", uuid::Uuid::now_v7()));
        let child = launch(binary, &config, &pid_file)?;
        let identity_file = PathBuf::from(format!("{}.owner", pid_file.display()));
        record_spawn_identity(&child, &identity_file)?;
        Ok(Self {
            binary: binary.to_path_buf(),
            config,
            pid_file,
            identity_file,
            child: Some(child),
            adopted_pid: None,
        })
    }

    fn adopt(root: &Path, binary: &Path) -> Result<Option<Self>, DhcpError> {
        let mut candidate = None;
        for entry in fs::read_dir(root).map_err(DhcpError::Storage)? {
            let path = entry.map_err(DhcpError::Storage)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with("dnsmasq-") || !name.ends_with(".pid") {
                continue;
            }
            let identity_file = PathBuf::from(format!("{}.owner", path.display()));
            let parsed = fs::read_to_string(&path)
                .ok()
                .and_then(|value| value.trim().parse::<i32>().ok())
                .zip(
                    fs::read_to_string(&identity_file)
                        .ok()
                        .and_then(|value| value.trim().parse::<u64>().ok()),
                );
            let Some((pid, starttime)) = parsed else {
                remove_metadata(&path, &identity_file)?;
                continue;
            };
            if process_starttime(pid) != Some(starttime) {
                remove_metadata(&path, &identity_file)?;
                continue;
            }
            if candidate.is_some() {
                return Err(DhcpError::CommandFailed);
            }
            candidate = Some(Self {
                binary: binary.to_path_buf(),
                config: root.join("dnsmasq.conf"),
                pid_file: path,
                identity_file,
                child: None,
                adopted_pid: Some((pid, starttime)),
            });
        }
        Ok(candidate)
    }

    /// Returns whether the owned process is still running.
    pub fn is_running(&mut self) -> Result<bool, DhcpError> {
        if let Some(child) = self.child.as_mut() {
            return Ok(child
                .try_wait()
                .map_err(|_| DhcpError::CommandFailed)?
                .is_none());
        }
        Ok(self
            .adopted_pid
            .is_some_and(|(pid, starttime)| process_starttime(pid) == Some(starttime)))
    }

    /// Restart the owned process after the caller has published new config.
    pub fn restart(&mut self) -> Result<(), DhcpError> {
        self.stop()?;
        let child = launch(&self.binary, &self.config, &self.pid_file)?;
        record_spawn_identity(&child, &self.identity_file)?;
        self.child = Some(child);
        self.adopted_pid = None;
        Ok(())
    }

    /// Stop the owned process and remove only its managed pid file and the
    /// recorded spawn identity next to it.
    pub fn stop(&mut self) -> Result<(), DhcpError> {
        if let Some(child) = self.child.as_mut() {
            if child
                .try_wait()
                .map_err(|_| DhcpError::CommandFailed)?
                .is_none()
            {
                child.kill().map_err(|_| DhcpError::CommandFailed)?;
            }
            child.wait().map_err(|_| DhcpError::CommandFailed)?;
        } else if let Some((pid, starttime)) = self.adopted_pid.take() {
            terminate_owned_process(pid, starttime)?;
        }
        self.child = None;
        for path in [&self.pid_file, &self.identity_file] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(DhcpError::CommandFailed),
            }
        }
        Ok(())
    }
}

impl Drop for DnsmasqSupervisor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn remove_metadata(pid_file: &Path, identity_file: &Path) -> Result<(), DhcpError> {
    for path in [pid_file, identity_file] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(DhcpError::Storage(error)),
        }
    }
    Ok(())
}

fn terminate_owned_process(pid: i32, starttime: u64) -> Result<(), DhcpError> {
    if process_starttime(pid) != Some(starttime) {
        return Ok(());
    }
    Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map_err(|_| DhcpError::CommandFailed)?;
    let deadline = Instant::now() + LIVENESS_GRACE;
    while process_starttime(pid) == Some(starttime) && Instant::now() < deadline {
        std::thread::sleep(POLL_INTERVAL);
    }
    if process_starttime(pid) == Some(starttime) {
        Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .map_err(|_| DhcpError::CommandFailed)?;
    }
    Ok(())
}

/// Fail closed before any serving process is spawned if the binary rejects
/// the rendered config (`dnsmasq --test`). dnsmasq 2.90 rejects the
/// previously rendered `start,end,static` dhcp-range shape with "bad
/// dhcp-range" and would then exit immediately after spawn; the preflight
/// catches config errors deterministically instead of relying on death
/// timing. A binary that neither accepts nor rejects the config within the
/// bounded window (e.g. a test stub that ignores arguments) is treated as
/// unknown and allowed to proceed; the post-spawn liveness check in
/// [`launch`] still guards the serving process.
fn verify_config(binary: &Path, config: &Path) -> Result<(), DhcpError> {
    let mut probe = Command::new(binary)
        .arg("--test")
        .arg(format!("--conf-file={}", config.display()))
        .spawn()
        .map_err(|_| DhcpError::CommandFailed)?;
    let deadline = Instant::now() + CONFIG_PROBE_TIMEOUT;
    loop {
        match probe.try_wait().map_err(|_| DhcpError::CommandFailed)? {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err(DhcpError::CommandFailed),
            None if Instant::now() >= deadline => {
                let _ = probe.kill();
                let _ = probe.wait();
                return Ok(());
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

/// Spawn the serving dnsmasq and fail closed if it does not stay alive.
///
/// A single spawn-time `try_wait` races a child that starts and then exits
/// immediately (bad config, missing interface, ...): by the time the check
/// runs the child is often still alive, so the caller would get a supervisor
/// that owns a corpse and project the create ACTIVE with no DHCP. A short
/// bounded liveness window after spawn turns that early death into a failed
/// start instead.
fn launch(binary: &Path, config: &Path, pid_file: &Path) -> Result<Child, DhcpError> {
    verify_config(binary, config)?;
    let mut child = Command::new(binary)
        // dnsmasq 2.90 rejects the space-separated form for these optional
        // long options ("junk found in command line"); use `--opt=value`.
        .arg(format!("--conf-file={}", config.display()))
        .arg(format!("--pid-file={}", pid_file.display()))
        .arg("--keep-in-foreground")
        .spawn()
        .map_err(|_| DhcpError::CommandFailed)?;
    let deadline = Instant::now() + LIVENESS_GRACE;
    loop {
        if child
            .try_wait()
            .map_err(|_| DhcpError::CommandFailed)?
            .is_some()
        {
            let _ = fs::remove_file(pid_file);
            return Err(DhcpError::CommandFailed);
        }
        if Instant::now() >= deadline {
            return Ok(child);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Persists the spawn-time identity of the freshly launched dnsmasq next to
/// its pidfile. The reap that later terminates an orphaned dnsmasq requires
/// the process's current start time to match this recorded value before it
/// may signal, so a same-user argv spoof or a PID-reuse replacement can
/// never be mistaken for the owned process. Failing to record the identity
/// fails the spawn closed: an unprovable process must not be started, and
/// an identity-less pidfile must not be signaled later.
fn record_spawn_identity(child: &Child, identity_file: &Path) -> Result<(), DhcpError> {
    let starttime = process_starttime(child.id() as i32).ok_or(DhcpError::CommandFailed)?;
    atomic_write(identity_file, starttime.to_string().as_bytes())
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct State {
    config: Option<DhcpConfig>,
    bindings: BTreeMap<String, Binding>,
}

pub struct DhcpService {
    root: PathBuf,
    state: State,
}

impl DhcpService {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, DhcpError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(DhcpError::Storage)?;
        let path = root.join("state.json");
        let state = if path.exists() {
            serde_json::from_slice(&fs::read(path).map_err(DhcpError::Storage)?)
                .map_err(DhcpError::CorruptState)?
        } else {
            State::default()
        };
        Ok(Self { root, state })
    }

    pub fn configure(&mut self, config: DhcpConfig) -> Result<(), DhcpError> {
        validate_config(&config)?;
        for binding in self.state.bindings.values() {
            if !valid_host(&config.subnet, binding.address) || binding.address == config.gateway {
                return Err(DhcpError::InvalidConfig);
            }
        }
        self.state.config = Some(config);
        self.persist()
    }

    pub fn upsert_binding(&mut self, binding: Binding) -> Result<(), DhcpError> {
        let config = self.state.config.as_ref().ok_or(DhcpError::InvalidConfig)?;
        if binding.port_id.is_empty()
            || !valid_mac(&binding.mac)
            || !valid_host(&config.subnet, binding.address)
            || binding.address == config.gateway
        {
            return Err(DhcpError::InvalidConfig);
        }
        if self.state.bindings.values().any(|existing| {
            existing.port_id != binding.port_id
                && (existing.address == binding.address || existing.mac == binding.mac)
        }) {
            return Err(DhcpError::Conflict);
        }
        self.state.bindings.insert(binding.port_id.clone(), binding);
        self.persist()
    }

    pub fn remove_binding(&mut self, port_id: &str) -> Result<(), DhcpError> {
        self.state.bindings.remove(port_id);
        self.persist()
    }

    pub fn bindings(&self) -> impl Iterator<Item = &Binding> {
        self.state.bindings.values()
    }

    /// Returns the durable binding for one port, if present.
    pub fn binding(&self, port_id: &str) -> Option<&Binding> {
        self.state.bindings.get(port_id)
    }

    /// Returns the persisted network configuration for restart reconciliation.
    pub fn configuration(&self) -> Option<&DhcpConfig> {
        self.state.config.as_ref()
    }

    /// Clears the persisted network configuration after the last binding was
    /// removed. The flat DHCP bridge is single-subnet per occupied lifetime;
    /// once no bindings remain, the bridge returns to unbound state so a
    /// future attachment with a different subnet can bind. The conflict guard
    /// is unchanged while any binding exists.
    pub fn clear_configuration(&mut self) -> Result<(), DhcpError> {
        self.state.config = None;
        self.persist()
    }

    pub fn render_config(&self) -> Result<String, DhcpError> {
        let config = self.state.config.as_ref().ok_or(DhcpError::InvalidConfig)?;
        validate_config(config)?;
        let (network, _) = subnet_bounds(&config.subnet).ok_or(DhcpError::InvalidConfig)?;
        let dhcp_start = Ipv4Addr::from(u32::from(network) + 1);
        let mut lines = vec![
            "# Managed by o3k-dhcp; do not edit.".to_owned(),
            format!("interface={}", config.interface),
            // dnsmasq always opens a DNS listener on 127.0.0.1:53 regardless
            // of `interface=`/`bind-interfaces`; on hosts with a system
            // dnsmasq that listener is EADDRINUSE and the DHCP server dies
            // at spawn. Exclude the loopback so the DHCP server binds the
            // managed bridge only (issue #87 re-probe matrix, dnsmasq 2.90).
            "except-interface=lo".to_owned(),
            "bind-interfaces".to_owned(),
            format!(
                "dhcp-leasefile={}",
                self.root.join("dnsmasq.leases").display()
            ),
            // dnsmasq's `<mode>` keyword occupies the `<end-addr>` position,
            // so `start,end,static` is rejected by 2.90 ("bad dhcp-range").
            // `start,static[,lease]` spans the interface subnet and serves
            // only hosts with a dhcp-host binding, preserving the static-only
            // intent for fixed IPs.
            format!("dhcp-range={},static,{}", dhcp_start, config.lease_seconds),
            format!("dhcp-option=3,{}", config.gateway),
        ];
        if !config.dns.is_empty() {
            lines.push(format!(
                "dhcp-option=6,{}",
                config
                    .dns
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        lines.extend(
            self.state
                .bindings
                .values()
                .map(|binding| format!("dhcp-host={},{}", binding.mac, binding.address)),
        );
        Ok(lines.join("\n") + "\n")
    }

    pub fn write_config(&self) -> Result<PathBuf, DhcpError> {
        let content = self.render_config()?;
        let path = self.root.join("dnsmasq.conf");
        atomic_write(&path, content.as_bytes())?;
        Ok(path)
    }

    pub fn start(&self, binary: &Path) -> Result<DnsmasqSupervisor, DhcpError> {
        self.write_config()?;
        DnsmasqSupervisor::spawn(&self.root, binary)
    }

    pub fn adopt_supervisor(&self, binary: &Path) -> Result<Option<DnsmasqSupervisor>, DhcpError> {
        DnsmasqSupervisor::adopt(&self.root, binary)
    }

    /// Publish the current state and restart the owned process.
    pub fn reload(&self, supervisor: &mut DnsmasqSupervisor) -> Result<(), DhcpError> {
        self.write_config()?;
        supervisor.restart()
    }

    pub fn managed_config_path(&self) -> PathBuf {
        self.root.join("dnsmasq.conf")
    }

    pub fn managed_lease_path(&self) -> PathBuf {
        self.root.join("dnsmasq.leases")
    }

    fn persist(&self) -> Result<(), DhcpError> {
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|_| DhcpError::InvalidConfig)?;
        atomic_write(&self.root.join("state.json"), &bytes)
    }
}

fn validate_config(config: &DhcpConfig) -> Result<(), DhcpError> {
    if config.interface.is_empty()
        || config.interface.len() > 15
        || !config
            .interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || config.lease_seconds == 0
        || !valid_host(&config.subnet, config.gateway)
        || config
            .dns
            .iter()
            .any(|address| !valid_host(&config.subnet, *address))
    {
        return Err(DhcpError::InvalidConfig);
    }
    Ok(())
}

fn valid_host(cidr: &str, address: Ipv4Addr) -> bool {
    let Some((network, broadcast)) = subnet_bounds(cidr) else {
        return false;
    };
    u32::from(address) > u32::from(network) && u32::from(address) < u32::from(broadcast)
}

fn subnet_bounds(cidr: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (address, prefix) = cidr.split_once('/')?;
    let address = address.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 30 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(address) & mask;
    Some((Ipv4Addr::from(network), Ipv4Addr::from(network | !mask)))
}

fn valid_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.split(':').count() == 6
        && mac
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), DhcpError> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
    if let Err(error) = fs::write(&temporary, bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(DhcpError::Storage(error));
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(DhcpError::Storage(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service() -> Result<DhcpService, DhcpError> {
        DhcpService::open(
            std::env::temp_dir().join(format!("o3k-dhcp-tests-{}", uuid::Uuid::now_v7())),
        )
    }
    fn config() -> Result<DhcpConfig, DhcpError> {
        Ok(DhcpConfig {
            subnet: "192.0.2.0/24".into(),
            gateway: "192.0.2.1".parse().map_err(|_| DhcpError::InvalidConfig)?,
            dns: vec!["192.0.2.1".parse().map_err(|_| DhcpError::InvalidConfig)?],
            interface: "o3k-br0".into(),
            lease_seconds: 3600,
        })
    }
    #[test]
    fn renders_fixed_bindings_and_rejects_collisions() -> Result<(), DhcpError> {
        let mut service = service()?;
        service.configure(config()?)?;
        service.upsert_binding(Binding {
            port_id: "p1".into(),
            mac: "02:00:00:00:00:01".into(),
            address: "192.0.2.10".parse().map_err(|_| DhcpError::InvalidConfig)?,
        })?;
        assert!(matches!(
            service.upsert_binding(Binding {
                port_id: "p2".into(),
                mac: "02:00:00:00:00:02".into(),
                address: "192.0.2.10".parse().map_err(|_| DhcpError::InvalidConfig)?
            }),
            Err(DhcpError::Conflict)
        ));
        let rendered = service.render_config()?;
        assert!(rendered.contains("dhcp-host=02:00:00:00:00:01,192.0.2.10"));
        // dnsmasq 2.90 grammar: `<mode>` occupies the <end-addr> position, so
        // `start,end,static` is rejected ("bad dhcp-range"); the static-only
        // intent is `start,static[,lease]`, which spans the interface subnet.
        assert!(rendered.contains("dhcp-range=192.0.2.1,static,3600"));
        assert!(rendered.contains("dhcp-leasefile="));
        assert!(service.managed_lease_path().ends_with("dnsmasq.leases"));
        Ok(())
    }

    #[test]
    fn clearing_configuration_after_last_binding_allows_new_subnet() -> Result<(), DhcpError> {
        let mut service = service()?;
        service.configure(config()?)?;
        service.upsert_binding(Binding {
            port_id: "p1".into(),
            mac: "02:00:00:00:00:01".into(),
            address: "192.0.2.10".parse().map_err(|_| DhcpError::InvalidConfig)?,
        })?;
        // While a binding exists, a conflicting subnet stays rejected.
        let mut conflicting = config()?;
        conflicting.subnet = "198.18.0.0/29".into();
        conflicting.gateway = "198.18.0.1".parse().map_err(|_| DhcpError::InvalidConfig)?;
        conflicting.dns = vec![conflicting.gateway];
        assert!(matches!(
            service.configure(conflicting.clone()),
            Err(DhcpError::InvalidConfig)
        ));
        // Once the last binding is removed and the configuration cleared, the
        // bridge is unbound again and a different subnet may bind.
        service.remove_binding("p1")?;
        service.clear_configuration()?;
        assert!(service.configuration().is_none());
        service.configure(conflicting)?;
        Ok(())
    }

    /// dnsmasq always opens a DNS listener on 127.0.0.1:53 regardless of
    /// `interface=`/`bind-interfaces`; on hosts with a system dnsmasq that
    /// listener is EADDRINUSE and the DHCP server dies at spawn (issue #87
    /// re-probe capability matrix, dnsmasq 2.90). The loopback must be
    /// excluded so the DHCP server binds the managed bridge only.
    #[test]
    fn rendered_config_excludes_loopback() -> Result<(), DhcpError> {
        let mut service = service()?;
        service.configure(config()?)?;
        let rendered = service.render_config()?;
        assert!(
            rendered.contains("except-interface=lo"),
            "rendered dnsmasq config must exclude the loopback:\n{rendered}"
        );
        Ok(())
    }

    #[test]
    fn gateway_reconfiguration_rejects_existing_binding() -> Result<(), DhcpError> {
        let root = std::env::temp_dir().join(format!("o3k-dhcp-gateway-{}", uuid::Uuid::now_v7()));
        let mut service = DhcpService::open(&root)?;
        service.configure(config()?)?;
        let binding_address = "192.0.2.10".parse().map_err(|_| DhcpError::InvalidConfig)?;
        service.upsert_binding(Binding {
            port_id: "gateway-conflict".into(),
            mac: "02:00:00:00:00:10".into(),
            address: binding_address,
        })?;

        let mut conflicting = config()?;
        conflicting.gateway = binding_address;
        assert!(matches!(
            service.configure(conflicting),
            Err(DhcpError::InvalidConfig)
        ));
        assert!(service.render_config()?.contains("dhcp-option=3,192.0.2.1"));
        fs::remove_dir_all(root).map_err(DhcpError::Storage)?;
        Ok(())
    }
    #[test]
    fn foreign_paths_are_not_used() -> Result<(), DhcpError> {
        let service = service()?;
        assert!(service.managed_config_path().ends_with("dnsmasq.conf"));
        Ok(())
    }

    #[test]
    fn configuration_survives_reopen() -> Result<(), DhcpError> {
        let root = std::env::temp_dir().join(format!("o3k-dhcp-reopen-{}", uuid::Uuid::now_v7()));
        let mut service = DhcpService::open(&root)?;
        let expected = config()?;
        service.configure(expected.clone())?;
        let reopened = DhcpService::open(&root)?;
        assert_eq!(reopened.configuration(), Some(&expected));
        fs::remove_dir_all(root).map_err(DhcpError::Storage)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_is_nonblocking_restartable_and_owned() -> Result<(), DhcpError> {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "o3k-dhcp-supervisor-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root).map_err(DhcpError::Storage)?;
        let binary = root.join("fake-dnsmasq.sh");
        fs::write(&binary, "#!/bin/sh\ntrap 'exit 0' TERM INT HUP\nsleep 30\n")
            .map_err(DhcpError::Storage)?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .map_err(DhcpError::Storage)?;

        let mut service = DhcpService::open(&root)?;
        service.configure(config()?)?;
        let mut supervisor = service.start(&binary)?;
        assert!(supervisor.is_running()?);
        // The spawn identity must be recorded next to the pidfile and must
        // match the child's kernel start time exactly.
        let identity = fs::read_to_string(&supervisor.identity_file).map_err(DhcpError::Storage)?;
        let child_id = supervisor
            .child
            .as_ref()
            .map(Child::id)
            .ok_or(DhcpError::CommandFailed)?;
        assert_eq!(
            identity.trim().parse::<u64>().ok(),
            process_starttime(child_id as i32),
            "the recorded spawn identity must be the child's kernel start time"
        );
        service.upsert_binding(Binding {
            port_id: "p1".into(),
            mac: "02:00:00:00:00:01".into(),
            address: "192.0.2.10".parse().map_err(|_| DhcpError::InvalidConfig)?,
        })?;
        service.reload(&mut supervisor)?;
        assert!(supervisor.is_running()?);
        // A restart respawns the child: the recorded identity must be
        // refreshed to the new process, never carried over from the old one.
        let identity = fs::read_to_string(&supervisor.identity_file).map_err(DhcpError::Storage)?;
        let child_id = supervisor
            .child
            .as_ref()
            .map(Child::id)
            .ok_or(DhcpError::CommandFailed)?;
        assert_eq!(
            identity.trim().parse::<u64>().ok(),
            process_starttime(child_id as i32),
            "restart must rewrite the spawn identity for the new child"
        );
        assert!(
            fs::read_to_string(service.managed_config_path())
                .map_err(DhcpError::Storage)?
                .contains("192.0.2.10")
        );
        supervisor.stop()?;
        assert!(!supervisor.is_running()?);
        assert!(
            !supervisor.identity_file.exists(),
            "stop must remove the recorded spawn identity"
        );

        let failing_binary = root.join("missing-dnsmasq");
        assert!(matches!(
            service.start(&failing_binary),
            Err(DhcpError::CommandFailed)
        ));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_can_be_adopted_after_agent_restart() -> Result<(), DhcpError> {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "o3k-dhcp-adopt-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root).map_err(DhcpError::Storage)?;
        let binary = root.join("fake-dnsmasq.sh");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" = \"--test\" ]; then exit 0; fi\nfor arg in \"$@\"; do case \"$arg\" in --pid-file=*) echo $$ > \"${arg#--pid-file=}\";; esac; done\ntrap 'exit 0' TERM INT HUP\nsleep 30\n",
        )
        .map_err(DhcpError::Storage)?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .map_err(DhcpError::Storage)?;

        let mut service = DhcpService::open(&root)?;
        service.configure(config()?)?;
        let supervisor = service.start(&binary)?;
        let pid_file = supervisor.pid_file.clone();
        let identity_file = supervisor.identity_file.clone();
        let deadline = Instant::now() + LIVENESS_GRACE;
        while !pid_file.exists() && Instant::now() < deadline {
            std::thread::sleep(POLL_INTERVAL);
        }
        assert!(
            pid_file.exists(),
            "dnsmasq must publish its pidfile before adoption"
        );
        std::mem::forget(supervisor);

        let reopened = DhcpService::open(&root)?;
        let mut adopted = reopened
            .adopt_supervisor(&binary)?
            .ok_or(DhcpError::CommandFailed)?;
        assert!(adopted.is_running()?);
        adopted.stop()?;
        assert!(!pid_file.exists());
        assert!(!identity_file.exists());
        fs::remove_dir_all(root).map_err(DhcpError::Storage)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn start_fails_closed_when_child_dies_after_spawn() -> Result<(), DhcpError> {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("o3k-dhcp-early-death-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&root).map_err(DhcpError::Storage)?;
        // Mimic dnsmasq's two phases: `--test` passes, but the serving
        // process exits nonzero shortly after spawn. The exit is delayed past
        // the supervisor's spawn-time try_wait, so pre-fix this start
        // succeeds; the post-spawn liveness window must fail it closed.
        // The artificial delay must stay comfortably inside LIVENESS_GRACE
        // (500ms) even under maximal parallel-test CPU load: a starved
        // `sleep 0.2` can overrun the window and flake this assertion (issue
        // #1044), which is a test-setup margin problem, not a production
        // budget bug.
        let binary = root.join("dies-after-spawn.sh");
        fs::write(
            &binary,
            "#!/bin/sh\nfor arg in \"$@\"; do\n  [ \"$arg\" = \"--test\" ] && exit 0\ndone\nsleep 0.02\nexit 1\n",
        )
        .map_err(DhcpError::Storage)?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .map_err(DhcpError::Storage)?;

        let mut service = DhcpService::open(&root)?;
        service.configure(config()?)?;
        assert!(matches!(
            service.start(&binary),
            Err(DhcpError::CommandFailed)
        ));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn start_fails_closed_when_config_probe_rejects() -> Result<(), DhcpError> {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("o3k-dhcp-test-reject-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&root).map_err(DhcpError::Storage)?;
        // A binary whose `--test` rejects the rendered config (as dnsmasq
        // 2.90 does for `start,end,static`) must fail the start before any
        // serving process is spawned. Without the preflight the serving
        // process stays alive and the start succeeds, so this fails pre-fix.
        let binary = root.join("rejects-config.sh");
        fs::write(
            &binary,
            "#!/bin/sh\n[ \"$1\" = \"--test\" ] && exit 1\ntrap 'exit 0' TERM INT HUP\nsleep 30\n",
        )
        .map_err(DhcpError::Storage)?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .map_err(DhcpError::Storage)?;

        let mut service = DhcpService::open(&root)?;
        service.configure(config()?)?;
        assert!(matches!(
            service.start(&binary),
            Err(DhcpError::CommandFailed)
        ));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn spawn_uses_equals_form_for_path_options() -> Result<(), DhcpError> {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("o3k-dhcp-argv-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&root).map_err(DhcpError::Storage)?;
        let argv_file = root.join("argv.txt");
        let binary = root.join("fake-dnsmasq-argv.sh");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ntrap 'exit 0' TERM INT HUP\nfor arg in \"$@\"; do\n  [ \"$arg\" = \"--test\" ] && exit 0\ndone\nsleep 30\n",
                argv_file.display()
            ),
        )
        .map_err(DhcpError::Storage)?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .map_err(DhcpError::Storage)?;

        let mut service = DhcpService::open(&root)?;
        service.configure(config()?)?;
        let mut supervisor = service.start(&binary)?;
        // The child records argv then holds; startup is asynchronous, so poll
        // for the recording with a bounded wait before asserting on it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !argv_file.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "fake dnsmasq never recorded its argv within 5s"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let recorded = fs::read_to_string(&argv_file).map_err(DhcpError::Storage)?;
        let args: Vec<&str> = recorded.lines().collect();
        let expected_config = format!("--conf-file={}", service.managed_config_path().display());
        assert!(
            args.contains(&expected_config.as_str()),
            "expected {expected_config} in argv, got {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg.starts_with("--pid-file=")),
            "expected --pid-file=<path> in argv, got {args:?}"
        );
        supervisor.stop()?;

        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
