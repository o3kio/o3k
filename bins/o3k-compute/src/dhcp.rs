use super::{AgentError, process, proto};
use rustix::process::{Signal, pidfd_send_signal};
use std::{net::Ipv4Addr, path::PathBuf};

pub(crate) struct DhcpRuntime {
    pub(crate) service: o3k_dhcp::DhcpService,
    pub(crate) supervisor: Option<o3k_dhcp::DnsmasqSupervisor>,
    pub(crate) binary: PathBuf,
    pub(crate) interface: String,
    pub(crate) root: PathBuf,
}

impl DhcpRuntime {
    pub(super) fn open(
        root: impl Into<PathBuf>,
        binary: impl Into<PathBuf>,
        interface: String,
    ) -> Result<Self, o3k_dhcp::DhcpError> {
        let root = root.into();
        Ok(Self {
            service: o3k_dhcp::DhcpService::open(root.clone())?,
            supervisor: None,
            binary: binary.into(),
            interface,
            root,
        })
    }

    pub(super) fn validate(
        &self,
        attachments: &[proto::NetworkAttachment],
    ) -> Result<(), AgentError> {
        let Some(first) = attachments.first() else {
            return Err(AgentError::Protocol(
                "DHCP requires a network attachment".to_owned(),
            ));
        };
        if attachments.iter().any(|attachment| {
            attachment.subnet_cidr != first.subnet_cidr
                || attachment.gateway_ipv4 != first.gateway_ipv4
        }) {
            return Err(AgentError::Protocol(
                "multiple network subnets are not supported by the flat DHCP profile".to_owned(),
            ));
        }
        let gateway = first
            .gateway_ipv4
            .parse()
            .map_err(|_| AgentError::Protocol("DHCP gateway address is invalid".to_owned()))?;
        let expected = o3k_dhcp::DhcpConfig {
            subnet: first.subnet_cidr.clone(),
            gateway,
            dns: vec![gateway],
            interface: self.interface.clone(),
            lease_seconds: 3600,
        };
        if let Some(existing) = self.service.configuration()
            && existing != &expected
        {
            return Err(AgentError::Protocol(
                "the managed bridge already has a different DHCP subnet".to_owned(),
            ));
        }
        for attachment in attachments {
            let address: Ipv4Addr = attachment
                .fixed_ipv4
                .parse()
                .map_err(|_| AgentError::Protocol("DHCP fixed address is invalid".to_owned()))?;
            if let Some(existing) = self.service.binding(&attachment.port_id)
                && (existing.mac != attachment.mac || existing.address != address)
            {
                return Err(AgentError::Protocol(
                    "DHCP port binding conflicts with durable state".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Applies only new bindings and returns those identities for precise rollback.
    pub(super) fn apply(
        &mut self,
        attachments: &[proto::NetworkAttachment],
    ) -> Result<Vec<String>, AgentError> {
        self.validate(attachments)?;
        let first = attachments
            .first()
            .ok_or_else(|| AgentError::Protocol("DHCP requires a network attachment".to_owned()))?;
        let gateway = first
            .gateway_ipv4
            .parse()
            .map_err(|_| AgentError::Protocol("DHCP gateway address is invalid".to_owned()))?;
        if self.service.configuration().is_none() {
            self.service
                .configure(o3k_dhcp::DhcpConfig {
                    subnet: first.subnet_cidr.clone(),
                    gateway,
                    dns: vec![gateway],
                    interface: self.interface.clone(),
                    lease_seconds: 3600,
                })
                .map_err(|_| AgentError::Protocol("DHCP configuration is invalid".to_owned()))?;
        }
        let mut added = Vec::new();
        for attachment in attachments {
            if self.service.binding(&attachment.port_id).is_some() {
                continue;
            }
            let address = attachment
                .fixed_ipv4
                .parse()
                .map_err(|_| AgentError::Protocol("DHCP fixed address is invalid".to_owned()))?;
            if let Err(error) = self.service.upsert_binding(o3k_dhcp::Binding {
                port_id: attachment.port_id.clone(),
                mac: attachment.mac.clone(),
                address,
            }) {
                let _ = self.remove_ports(&added);
                return Err(AgentError::Protocol(format!(
                    "DHCP binding failed: {error}"
                )));
            }
            added.push(attachment.port_id.clone());
        }
        if let Some(supervisor) = self.supervisor.as_mut() {
            self.service.reload(supervisor).map_err(|_| {
                // Issue #88 C6a (DEV-1): a failed reload/start must roll
                // back the durable bindings of the ports added by this
                // apply, or a later restart re-serves them for a
                // never-created instance (bridge + owned dnsmasq leak).
                let _ = self.remove_ports(&added);
                AgentError::Protocol("DHCP reload failed".to_owned())
            })?;
        } else {
            self.supervisor = Some(self.service.start(&self.binary).map_err(|_| {
                let _ = self.remove_ports(&added);
                AgentError::Protocol("DHCP start failed".to_owned())
            })?);
        }
        Ok(added)
    }

    pub(super) fn remove_ports(&mut self, ports: &[String]) -> Result<(), AgentError> {
        for port in ports {
            self.service
                .remove_binding(port)
                .map_err(|_| AgentError::Protocol("DHCP binding cleanup failed".to_owned()))?;
        }
        if self.service.configuration().is_none() {
            // A create that crashed before DHCP configuration never wrote a
            // dnsmasq.conf, so there is nothing to render, reload, or stop
            // (the supervisor cannot exist without a configuration). Never-
            // configured state is absent state, not an aborting error (issue
            // #608): the delete/reap must continue into TAP and bridge
            // cleanup. Bindings cannot be added without a configuration, but
            // clear any that may remain so nothing stale can be re-served.
            for port_id in self
                .service
                .bindings()
                .map(|binding| binding.port_id.clone())
                .collect::<Vec<_>>()
            {
                let _ = self.service.remove_binding(&port_id);
            }
            return Ok(());
        }
        self.service
            .write_config()
            .map_err(|_| AgentError::Protocol("DHCP configuration cleanup failed".to_owned()))?;
        if self.service.bindings().next().is_none() {
            if let Some(mut supervisor) = self.supervisor.take() {
                supervisor
                    .stop()
                    .map_err(|_| AgentError::Protocol("DHCP stop failed".to_owned()))?;
            }
            // The flat bridge is single-subnet per occupied lifetime. With no
            // bindings left, return it to unbound state so a later attachment
            // with a different subnet (for example the P15.7 journey network
            // after an earlier lifecycle server was deleted) can bind. While
            // any binding exists, validate() still rejects conflicting
            // subnets — the guard is unchanged for occupied bridges.
            self.service.clear_configuration().map_err(|_| {
                AgentError::Protocol("DHCP configuration cleanup failed".to_owned())
            })?;
        } else if let Some(supervisor) = self.supervisor.as_mut() {
            self.service
                .reload(supervisor)
                .map_err(|_| AgentError::Protocol("DHCP reload failed".to_owned()))?;
        }
        Ok(())
    }

    pub(super) fn start_after_restart(
        &mut self,
        network: &o3k_network::HostNetworkManager,
    ) -> Result<(), AgentError> {
        if self.service.bindings().next().is_none() || self.supervisor.is_some() {
            return Ok(());
        }
        let config = self.service.configuration().cloned().ok_or_else(|| {
            AgentError::Protocol("DHCP bindings exist without configuration".to_owned())
        })?;
        let prefix_len = config
            .subnet
            .split_once('/')
            .and_then(|(_, prefix)| prefix.parse().ok())
            .ok_or_else(|| AgentError::Protocol("DHCP subnet prefix is invalid".to_owned()))?;
        network
            .ensure_gateway(o3k_network::GatewaySpec {
                address: config.gateway,
                prefix_len,
            })
            .map_err(|_| AgentError::Protocol("managed DHCP gateway is unavailable".to_owned()))?;
        self.supervisor = Some(
            self.service
                .start(&self.binary)
                .map_err(|_| AgentError::Protocol("DHCP restart failed".to_owned()))?,
        );
        Ok(())
    }

    /// Reaps every owned dnsmasq left behind by a previous agent process
    /// (issue #88 S3/S4): a crashed agent's dnsmasq was reparented to init
    /// and keeps running unsupervized. Invariant: at startup the supervisor
    /// is ALWAYS `None` (`DhcpRuntime::open` sets it; `start_after_restart`
    /// creates it later), so ANY owned dnsmasq found at startup is a
    /// leftover of a previous process — regardless of durable bindings. Live
    /// bindings are re-served by `start_after_restart` AFTER this residue
    /// cleanup (the caller's ordering), and the earlier stale-network reap
    /// already removed stale bindings first. Each `dnsmasq-*.pid` pidfile is
    /// verified by its recorded spawn identity (`<pidfile>.owner`, written at
    /// spawn with the process's kernel start time) and its process cmdline
    /// (it must contain the O3K dhcp root) before a pidfd is opened: SIGTERM,
    /// a bounded wait, SIGKILL only if still alive, then the pidfile and the
    /// identity file are removed. A pidfile whose process is already gone is
    /// just removed together with its identity file. A pidfile without a
    /// recorded identity, with a mismatched identity (argv spoof, PID reuse),
    /// or pointing at a foreign process is skipped with a warning and left
    /// for the inventory — an unprovable process must never be signaled.
    pub(super) fn reap_owned_dnsmasq(&self) -> Result<(), AgentError> {
        let entries = std::fs::read_dir(&self.root)
            .map_err(|_| AgentError::Protocol("dhcp root is unreadable".to_owned()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with("dnsmasq-") || !name.ends_with(".pid") {
                continue;
            }
            self.reap_owned_dnsmasq_pidfile(&path);
        }
        Ok(())
    }

    fn reap_owned_dnsmasq_pidfile(&self, pidfile: &std::path::Path) {
        let Ok(raw) = std::fs::read_to_string(pidfile) else {
            tracing::warn!(
                pidfile = %pidfile.display(),
                "owned dnsmasq pidfile is unreadable; left for the inventory"
            );
            return;
        };
        let Ok(pid) = raw.trim().parse::<i32>() else {
            tracing::warn!(
                pidfile = %pidfile.display(),
                "owned dnsmasq pidfile does not carry a pid; left for the inventory"
            );
            return;
        };
        if !process::pid_is_alive(pid) {
            // The process is already gone; only the stale pidfile (and its
            // recorded identity) remain.
            let identity_file = std::path::PathBuf::from(format!("{}.owner", pidfile.display()));
            for path in [pidfile, &identity_file] {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!(
                        pidfile = %pidfile.display(),
                        error = %error,
                        "stale dnsmasq pidfile/identity removal failed"
                    );
                }
            }
            return;
        }
        let identity_file = std::path::PathBuf::from(format!("{}.owner", pidfile.display()));
        let expected_starttime = match std::fs::read_to_string(&identity_file) {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(starttime) => starttime,
                Err(_) => {
                    tracing::warn!(
                        pidfile = %pidfile.display(),
                        "dnsmasq pidfile identity is malformed; left for the inventory"
                    );
                    return;
                }
            },
            Err(_) => {
                tracing::warn!(
                    pidfile = %pidfile.display(),
                    "dnsmasq pidfile has no recorded spawn identity; left for the inventory"
                );
                return;
            }
        };
        let pidfd = match process::open_owned_pidfd(pid, &self.root, expected_starttime) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                tracing::warn!(
                    pid,
                    pidfile = %pidfile.display(),
                    error = %error,
                    "dnsmasq pidfile process is foreign or lacks pidfd support; left for the inventory"
                );
                return;
            }
        };
        let _ = pidfd_send_signal(&pidfd, Signal::Term);
        // Bounded wait for SIGTERM to take effect; SIGKILL only if the
        // process is still alive after the window.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2000);
        while process::pid_is_alive(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if process::pid_is_alive(pid) {
            let _ = pidfd_send_signal(&pidfd, Signal::Kill);
            let kill_deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            while process::pid_is_alive(pid) && std::time::Instant::now() < kill_deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        for path in [pidfile, &identity_file] {
            if let Err(error) = std::fs::remove_file(path) {
                tracing::warn!(
                    pidfile = %pidfile.display(),
                    error = %error,
                    "owned dnsmasq pidfile/identity removal failed"
                );
            }
        }
    }
}
