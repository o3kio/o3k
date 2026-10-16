use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

pub mod types;
pub use types::*;

impl Config {
    /// Loads defaults, then a TOML file, environment variables, and CLI flags.
    /// Later sources override earlier sources.
    pub fn from_sources<I, E>(args: I, environment: E) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = String>,
        E: IntoIterator<Item = (String, String)>,
    {
        let args: Vec<String> = args.into_iter().collect();
        let cli = PartialConfig::from_cli(&args)?;
        let environment: Vec<(String, String)> = environment.into_iter().collect();
        let config_path = cli
            .config_path
            .clone()
            .or_else(|| value_from_env(&environment, "O3K_CONFIG").map(PathBuf::from));

        let mut values = PartialConfig::default();
        if let Some(path) = &config_path {
            let contents = fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
                path: path.clone(),
                source,
            })?;
            let file: FileConfig = toml::from_str(&contents)
                .map_err(|_| ConfigError::ParseFile { path: path.clone() })?;
            values.merge(file.into());
        }
        values.merge(PartialConfig::from_environment(&environment));
        values.merge(cli);
        values.into_config(config_path)
    }

    #[must_use]
    pub fn bootstrap_secret(&self) -> Option<&Secret> {
        self.bootstrap_secret.as_ref()
    }

    #[must_use]
    pub fn bootstrap_password(&self) -> Option<&Secret> {
        self.bootstrap_password.as_ref()
    }

    pub fn cinder_password(&self) -> Option<&Secret> {
        self.cinder_password.as_ref()
    }

    #[must_use]
    pub fn token_signing_key(&self) -> Option<&Secret> {
        self.token_signing_key.as_ref()
    }

    #[must_use]
    pub fn database_url(&self) -> Option<&Secret> {
        self.database_url.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unknown command-line option `{0}`")]
    UnknownOption(String),
    /// A bare argument that is not an option. Its value is not kept: it can be
    /// the tail of an unquoted secret split by the shell.
    #[error("unexpected positional argument (value withheld)")]
    UnexpectedArgument,
    #[error("missing value for command-line option `{0}`")]
    MissingValue(String),
    #[error("cannot read configuration file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse configuration file {path}")]
    ParseFile { path: PathBuf },
    #[error("listen address is invalid")]
    InvalidListenAddress,
    #[error("compute control address is invalid")]
    InvalidComputeControlAddress,
    #[error("compute TLS requires server certificate, private key, and client CA together")]
    IncompleteComputeTls,
    #[error("compute TLS requires at least one authorized agent fingerprint")]
    MissingComputeAuthorization,
    #[error("data directory must be non-empty and must not be the filesystem root")]
    InvalidDataDirectory,
    #[error("log filter must be non-empty")]
    EmptyLogFilter,
    #[error("log format must be `json` or `pretty`")]
    InvalidLogFormat,
    #[error("provider must be `fake`, `cellhv`, `agent`, or `libvirt`")]
    InvalidProvider,
    #[error(
        "the `libvirt` provider is unavailable in o3kd: no agent-backed provider path exists; use `fake` for local tests or `cellhv` with its configured endpoint, and do not start the real-libvirt profile until compute-agent wiring is available"
    )]
    DirectLibvirtProviderUnavailable,
    #[error("CellHV provider requires endpoint and expected version")]
    MissingCellHvConfiguration,
    #[error("agent provider requires complete compute TLS configuration")]
    MissingAgentConfiguration,
    #[error("bootstrap secret must not contain a newline")]
    InvalidSecret,
    #[error("bootstrap password must not contain a newline")]
    InvalidBootstrapPassword,
    #[error("token signing key must be at least 32 bytes")]
    WeakTokenSigningKey,
    #[error("database backend must be `sqlite` or `postgres`")]
    InvalidDatabaseBackend,
    #[error("PostgreSQL database backend requires O3K_DATABASE_URL / database_url")]
    MissingDatabaseUrl,
    #[error("deployment profile must be `standalone` or `kubernetes`")]
    InvalidDeploymentProfile,
    #[error("network gateway realization must be `enabled` or `disabled`")]
    InvalidNetworkGatewayRealization,
    #[error(
        "PostgreSQL database backend is strictly required for the Kubernetes deployment profile; SQLite is rejected"
    )]
    KubernetesRequiresPostgres,
}

#[derive(Debug, Default, Clone)]
struct PartialConfig {
    config_path: Option<PathBuf>,
    listen_addr: Option<String>,
    data_dir: Option<String>,
    database_backend: Option<String>,
    database_url: Option<String>,
    deployment_profile: Option<String>,
    network_gateway_realization: Option<String>,
    log_format: Option<String>,
    log_filter: Option<String>,
    provider: Option<String>,
    cellhv_endpoint: Option<String>,
    cellhv_expected_version: Option<String>,
    cellhv_ca_certificate: Option<String>,
    cellhv_client_certificate: Option<String>,
    cellhv_client_key: Option<String>,
    bootstrap_secret: Option<String>,
    bootstrap_password: Option<String>,
    cinder_password: Option<String>,
    token_signing_key: Option<String>,
    compute_control_addr: Option<String>,
    compute_server_certificate: Option<String>,
    compute_server_private_key: Option<String>,
    compute_client_ca: Option<String>,
    compute_authorized_agents: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen_addr: Option<String>,
    data_dir: Option<String>,
    database_backend: Option<String>,
    database_url: Option<String>,
    deployment_profile: Option<String>,
    log_format: Option<String>,
    log_filter: Option<String>,
    provider: Option<String>,
    cellhv_endpoint: Option<String>,
    cellhv_expected_version: Option<String>,
    cellhv_ca_certificate: Option<String>,
    cellhv_client_certificate: Option<String>,
    cellhv_client_key: Option<String>,
    bootstrap_secret: Option<String>,
    bootstrap_password: Option<String>,
    cinder_password: Option<String>,
    token_signing_key: Option<String>,
    compute_control_addr: Option<String>,
    compute_server_certificate: Option<String>,
    compute_server_private_key: Option<String>,
    compute_client_ca: Option<String>,
    compute_authorized_agents: Option<String>,
}

impl From<FileConfig> for PartialConfig {
    fn from(file: FileConfig) -> Self {
        Self {
            listen_addr: file.listen_addr,
            data_dir: file.data_dir,
            database_backend: file.database_backend,
            database_url: file.database_url,
            deployment_profile: file.deployment_profile,
            log_format: file.log_format,
            log_filter: file.log_filter,
            provider: file.provider,
            cellhv_endpoint: file.cellhv_endpoint,
            cellhv_expected_version: file.cellhv_expected_version,
            cellhv_ca_certificate: file.cellhv_ca_certificate,
            cellhv_client_certificate: file.cellhv_client_certificate,
            cellhv_client_key: file.cellhv_client_key,
            bootstrap_secret: file.bootstrap_secret,
            bootstrap_password: file.bootstrap_password,
            cinder_password: file.cinder_password,
            token_signing_key: file.token_signing_key,
            compute_control_addr: file.compute_control_addr,
            compute_server_certificate: file.compute_server_certificate,
            compute_server_private_key: file.compute_server_private_key,
            compute_client_ca: file.compute_client_ca,
            compute_authorized_agents: file.compute_authorized_agents,
            ..Self::default()
        }
    }
}

impl PartialConfig {
    fn merge(&mut self, other: Self) {
        if other.config_path.is_some() {
            self.config_path = other.config_path;
        }
        if other.listen_addr.is_some() {
            self.listen_addr = other.listen_addr;
        }
        if other.data_dir.is_some() {
            self.data_dir = other.data_dir;
        }
        if other.database_backend.is_some() {
            self.database_backend = other.database_backend;
        }
        if other.database_url.is_some() {
            self.database_url = other.database_url;
        }
        if other.deployment_profile.is_some() {
            self.deployment_profile = other.deployment_profile;
        }
        if other.network_gateway_realization.is_some() {
            self.network_gateway_realization = other.network_gateway_realization;
        }
        if other.log_format.is_some() {
            self.log_format = other.log_format;
        }
        if other.log_filter.is_some() {
            self.log_filter = other.log_filter;
        }
        if other.provider.is_some() {
            self.provider = other.provider;
        }
        if other.cellhv_endpoint.is_some() {
            self.cellhv_endpoint = other.cellhv_endpoint;
        }
        if other.cellhv_expected_version.is_some() {
            self.cellhv_expected_version = other.cellhv_expected_version;
        }
        if other.cellhv_ca_certificate.is_some() {
            self.cellhv_ca_certificate = other.cellhv_ca_certificate;
        }
        if other.cellhv_client_certificate.is_some() {
            self.cellhv_client_certificate = other.cellhv_client_certificate;
        }
        if other.cellhv_client_key.is_some() {
            self.cellhv_client_key = other.cellhv_client_key;
        }
        if other.bootstrap_secret.is_some() {
            self.bootstrap_secret = other.bootstrap_secret;
        }
        if other.bootstrap_password.is_some() {
            self.bootstrap_password = other.bootstrap_password;
        }
        if other.cinder_password.is_some() {
            self.cinder_password = other.cinder_password;
        }
        if other.token_signing_key.is_some() {
            self.token_signing_key = other.token_signing_key;
        }
        if other.compute_control_addr.is_some() {
            self.compute_control_addr = other.compute_control_addr;
        }
        if other.compute_server_certificate.is_some() {
            self.compute_server_certificate = other.compute_server_certificate;
        }
        if other.compute_server_private_key.is_some() {
            self.compute_server_private_key = other.compute_server_private_key;
        }
        if other.compute_client_ca.is_some() {
            self.compute_client_ca = other.compute_client_ca;
        }
        if other.compute_authorized_agents.is_some() {
            self.compute_authorized_agents = other.compute_authorized_agents;
        }
    }

    fn from_environment(environment: &[(String, String)]) -> Self {
        Self {
            listen_addr: value_from_env(environment, "O3K_LISTEN_ADDR"),
            data_dir: value_from_env(environment, "O3K_DATA_DIR"),
            database_backend: value_from_env(environment, "O3K_DATABASE_BACKEND"),
            database_url: value_from_env(environment, "O3K_DATABASE_URL"),
            deployment_profile: value_from_env(environment, "O3K_DEPLOYMENT_PROFILE")
                .or_else(|| value_from_env(environment, "O3K_DEPLOYMENT_MODE")),
            network_gateway_realization: value_from_env(
                environment,
                "O3K_NETWORK_GATEWAY_REALIZATION",
            ),
            log_format: value_from_env(environment, "O3K_LOG_FORMAT"),
            log_filter: value_from_env(environment, "O3K_LOG_FILTER"),
            provider: value_from_env(environment, "O3K_PROVIDER"),
            cellhv_endpoint: value_from_env(environment, "O3K_CELLHV_ENDPOINT"),
            cellhv_expected_version: value_from_env(environment, "O3K_CELLHV_EXPECTED_VERSION"),
            cellhv_ca_certificate: value_from_env(environment, "O3K_CELLHV_CA_CERTIFICATE"),
            cellhv_client_certificate: value_from_env(environment, "O3K_CELLHV_CLIENT_CERTIFICATE"),
            cellhv_client_key: value_from_env(environment, "O3K_CELLHV_CLIENT_KEY"),
            bootstrap_secret: value_from_env(environment, "O3K_BOOTSTRAP_SECRET"),
            bootstrap_password: value_from_env(environment, "O3K_BOOTSTRAP_PASSWORD"),
            cinder_password: value_from_env(environment, "O3K_CINDER_PASSWORD"),
            token_signing_key: value_from_env(environment, "O3K_TOKEN_SIGNING_KEY"),
            compute_control_addr: value_from_env(environment, "O3K_COMPUTE_CONTROL_ADDR"),
            compute_server_certificate: value_from_env(
                environment,
                "O3K_COMPUTE_SERVER_CERTIFICATE",
            ),
            compute_server_private_key: value_from_env(
                environment,
                "O3K_COMPUTE_SERVER_PRIVATE_KEY",
            ),
            compute_client_ca: value_from_env(environment, "O3K_COMPUTE_CLIENT_CA"),
            compute_authorized_agents: value_from_env(environment, "O3K_COMPUTE_AUTHORIZED_AGENTS"),
            ..Self::default()
        }
    }

    fn from_cli(args: &[String]) -> Result<Self, ConfigError> {
        fn is_option_name(option: &str) -> bool {
            option.strip_prefix("--").is_some_and(|name| {
                name.len() <= 64
                    && name.starts_with(|c: char| c.is_ascii_lowercase())
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
        }
        let mut result = Self::default();
        let mut args = args.iter().skip(1);
        while let Some(argument) = args.next() {
            let (option, inline_value) = argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(option, value)| {
                    (option, Some(value))
                });
            let mut value = |name: &str| {
                inline_value
                    .map(str::to_owned)
                    .or_else(|| args.next().cloned())
                    .ok_or_else(|| ConfigError::MissingValue(name.to_owned()))
            };
            match option {
                "--config" => result.config_path = Some(PathBuf::from(value("--config")?)),
                "--listen-addr" => result.listen_addr = Some(value("--listen-addr")?),
                "--data-dir" => result.data_dir = Some(value("--data-dir")?),
                "--database-backend" => {
                    result.database_backend = Some(value("--database-backend")?)
                }
                "--database-url" => result.database_url = Some(value("--database-url")?),
                "--deployment-profile" | "--deployment-mode" => {
                    result.deployment_profile = Some(value(option)?)
                }
                "--log-format" => result.log_format = Some(value("--log-format")?),
                "--log-filter" => result.log_filter = Some(value("--log-filter")?),
                "--provider" => result.provider = Some(value("--provider")?),
                "--cellhv-endpoint" => result.cellhv_endpoint = Some(value("--cellhv-endpoint")?),
                "--cellhv-expected-version" => {
                    result.cellhv_expected_version = Some(value("--cellhv-expected-version")?)
                }
                "--cellhv-ca-certificate" => {
                    result.cellhv_ca_certificate = Some(value("--cellhv-ca-certificate")?)
                }
                "--cellhv-client-certificate" => {
                    result.cellhv_client_certificate = Some(value("--cellhv-client-certificate")?)
                }
                "--cellhv-client-key" => {
                    result.cellhv_client_key = Some(value("--cellhv-client-key")?)
                }
                "--bootstrap-secret" => {
                    result.bootstrap_secret = Some(value("--bootstrap-secret")?)
                }
                "--bootstrap-password" => {
                    result.bootstrap_password = Some(value("--bootstrap-password")?)
                }
                "--cinder-password" => result.cinder_password = Some(value("--cinder-password")?),
                "--token-signing-key" => {
                    result.token_signing_key = Some(value("--token-signing-key")?)
                }
                "--compute-control-addr" => {
                    result.compute_control_addr = Some(value("--compute-control-addr")?)
                }
                "--compute-server-certificate" => {
                    result.compute_server_certificate = Some(value("--compute-server-certificate")?)
                }
                "--compute-server-private-key" => {
                    result.compute_server_private_key = Some(value("--compute-server-private-key")?)
                }
                "--compute-client-ca" => {
                    result.compute_client_ca = Some(value("--compute-client-ca")?)
                }
                "--compute-authorized-agents" => {
                    result.compute_authorized_agents = Some(value("--compute-authorized-agents")?)
                }
                option if option == "--help" || option == "-h" => {
                    return Err(ConfigError::UnknownOption(option.to_owned()));
                }
                // Echo only something shaped like an option name. Any other
                // dash-prefixed argument may be the tail of a secret split by
                // the shell, so its value is withheld.
                option if is_option_name(option) => {
                    return Err(ConfigError::UnknownOption(option.to_owned()));
                }
                _ => return Err(ConfigError::UnexpectedArgument),
            }
        }
        Ok(result)
    }

    fn into_config(self, config_path: Option<PathBuf>) -> Result<Config, ConfigError> {
        let listen_addr = self
            .listen_addr
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidListenAddress)?;
        let compute_control_addr = self
            .compute_control_addr
            .unwrap_or_else(|| DEFAULT_COMPUTE_CONTROL_ADDR.to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidComputeControlAddress)?;
        let data_dir = PathBuf::from(self.data_dir.unwrap_or_else(|| DEFAULT_DATA_DIR.to_owned()));
        if data_dir.as_os_str().is_empty() || data_dir == Path::new("/") {
            return Err(ConfigError::InvalidDataDirectory);
        }
        let log_filter = self
            .log_filter
            .unwrap_or_else(|| DEFAULT_LOG_FILTER.to_owned());
        if log_filter.trim().is_empty() {
            return Err(ConfigError::EmptyLogFilter);
        }
        let log_format = match self
            .log_format
            .as_deref()
            .unwrap_or("json")
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            _ => return Err(ConfigError::InvalidLogFormat),
        };
        let provider = match self
            .provider
            .as_deref()
            .unwrap_or("fake")
            .to_ascii_lowercase()
            .as_str()
        {
            "fake" => Provider::Fake,
            "cellhv" => Provider::CellHv,
            "agent" => Provider::Agent,
            "libvirt" => Provider::Libvirt,
            _ => return Err(ConfigError::InvalidProvider),
        };
        if provider == Provider::CellHv
            && (self
                .cellhv_endpoint
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
                || self
                    .cellhv_expected_version
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty()))
        {
            return Err(ConfigError::MissingCellHvConfiguration);
        }
        if provider == Provider::Agent
            && (self.compute_server_certificate.is_none()
                || self.compute_server_private_key.is_none()
                || self.compute_client_ca.is_none()
                || self
                    .compute_authorized_agents
                    .as_deref()
                    .is_none_or(|agents| agents.trim().is_empty()))
        {
            return Err(ConfigError::MissingAgentConfiguration);
        }
        if provider == Provider::Libvirt {
            return Err(ConfigError::DirectLibvirtProviderUnavailable);
        }
        if self
            .bootstrap_secret
            .as_deref()
            .is_some_and(|secret| secret.contains(['\n', '\r']))
        {
            return Err(ConfigError::InvalidSecret);
        }
        if self
            .bootstrap_password
            .as_deref()
            .is_some_and(|password| password.contains(['\n', '\r']))
        {
            return Err(ConfigError::InvalidBootstrapPassword);
        }
        if self
            .cinder_password
            .as_deref()
            .is_some_and(|password| password.contains(['\n', '\r']))
        {
            return Err(ConfigError::InvalidBootstrapPassword);
        }
        if self.bootstrap_password.is_some()
            && self
                .token_signing_key
                .as_ref()
                .is_none_or(|key| key.len() < 32)
        {
            return Err(ConfigError::WeakTokenSigningKey);
        }
        let compute_tls_paths = [
            self.compute_server_certificate.as_ref(),
            self.compute_server_private_key.as_ref(),
            self.compute_client_ca.as_ref(),
        ];
        if compute_tls_paths
            .iter()
            .filter(|path| path.is_some())
            .count()
            != 0
            && compute_tls_paths.iter().any(Option::is_none)
        {
            return Err(ConfigError::IncompleteComputeTls);
        }
        if compute_tls_paths.iter().any(Option::is_some)
            && self
                .compute_authorized_agents
                .as_deref()
                .is_none_or(|agents| agents.trim().is_empty())
        {
            return Err(ConfigError::MissingComputeAuthorization);
        }
        if compute_tls_paths.iter().all(Option::is_none) && self.compute_authorized_agents.is_some()
        {
            return Err(ConfigError::IncompleteComputeTls);
        }

        let deployment_profile = match self
            .deployment_profile
            .as_deref()
            .unwrap_or("standalone")
            .to_ascii_lowercase()
            .as_str()
        {
            "standalone" | "systemd" | "local" | "" => DeploymentProfile::Standalone,
            "kubernetes" | "k8s" => DeploymentProfile::Kubernetes,
            _ => return Err(ConfigError::InvalidDeploymentProfile),
        };

        let network_gateway_realization = match self
            .network_gateway_realization
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "enabled" => true,
            "disabled" => false,
            _ => return Err(ConfigError::InvalidNetworkGatewayRealization),
        };

        let database_backend = match self
            .database_backend
            .as_deref()
            .unwrap_or("sqlite")
            .to_ascii_lowercase()
            .as_str()
        {
            "sqlite" => DatabaseBackend::Sqlite,
            "postgres" | "postgresql" => DatabaseBackend::Postgres,
            _ => return Err(ConfigError::InvalidDatabaseBackend),
        };
        if database_backend == DatabaseBackend::Postgres
            && self
                .database_url
                .as_deref()
                .is_none_or(|url| url.trim().is_empty())
        {
            return Err(ConfigError::MissingDatabaseUrl);
        }

        if deployment_profile == DeploymentProfile::Kubernetes
            && database_backend != DatabaseBackend::Postgres
        {
            return Err(ConfigError::KubernetesRequiresPostgres);
        }

        Ok(Config {
            config_path,
            listen_addr,
            data_dir,
            database_backend,
            deployment_profile,
            network_gateway_realization,
            database_url: self.database_url.map(Secret),
            log_format,
            log_filter,
            provider,
            cellhv_endpoint: self.cellhv_endpoint,
            cellhv_expected_version: self.cellhv_expected_version,
            cellhv_ca_certificate: self.cellhv_ca_certificate.map(PathBuf::from),
            cellhv_client_certificate: self.cellhv_client_certificate.map(PathBuf::from),
            cellhv_client_key: self.cellhv_client_key.map(PathBuf::from),
            compute_control_addr,
            compute_server_certificate: self.compute_server_certificate.map(PathBuf::from),
            compute_server_private_key: self.compute_server_private_key.map(PathBuf::from),
            compute_client_ca: self.compute_client_ca.map(PathBuf::from),
            compute_authorized_agents: self.compute_authorized_agents,
            bootstrap_secret: self.bootstrap_secret.map(Secret),
            bootstrap_password: self.bootstrap_password.map(Secret),
            cinder_password: self.cinder_password.map(Secret),
            token_signing_key: self.token_signing_key.map(Secret),
        })
    }
}

fn value_from_env(environment: &[(String, String)], name: &str) -> Option<String> {
    environment
        .iter()
        .find_map(|(key, value)| (key == name).then(|| value.clone()))
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigError, DatabaseBackend, DeploymentProfile, LogFormat, Provider};
    use std::{fs, path::PathBuf};

    fn env(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn precedence_is_defaults_then_file_then_environment_then_cli()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from(format!(
            "/tmp/o3k-config-test-{}-{}.toml",
            std::process::id(),
            1
        ));
        fs::write(
            &path,
            "listen_addr = '127.0.0.1:9000'\ndata_dir = '/var/lib/o3k'\nprovider = 'cellhv'\ncellhv_endpoint = 'http://127.0.0.1:50052'\ncellhv_expected_version = 'v1'\n",
        )?;
        let args = vec![
            "o3kd".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
            "--listen-addr=127.0.0.1:9100".to_owned(),
        ];
        let config = Config::from_sources(
            args,
            env(&[("O3K_CONFIG", "ignored.toml"), ("O3K_DATA_DIR", "/tmp/o3k")]),
        )?;

        assert_eq!(config.listen_addr.to_string(), "127.0.0.1:9100");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/o3k"));
        assert_eq!(config.provider, Provider::CellHv);
        assert_eq!(
            config.cellhv_endpoint.as_deref(),
            Some("http://127.0.0.1:50052")
        );
        assert_eq!(config.log_format, LogFormat::Json);
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn cellhv_requires_endpoint_and_version() {
        let result = Config::from_sources(
            ["o3kd".to_owned(), "--provider=cellhv".to_owned()],
            Vec::new(),
        );
        assert!(matches!(
            result,
            Err(ConfigError::MissingCellHvConfiguration)
        ));
    }

    #[test]
    fn libvirt_mode_rejects_unsafe_direct_provider_path() {
        let result = Config::from_sources(
            ["o3kd".to_owned(), "--provider=libvirt".to_owned()],
            Vec::new(),
        );

        assert!(matches!(
            &result,
            Err(ConfigError::DirectLibvirtProviderUnavailable)
        ));
        if let Err(error) = result {
            assert!(error.to_string().contains("agent-backed provider path"));
            assert!(error.to_string().contains("use `fake`"));
        }
    }

    #[test]
    fn secret_is_redacted_from_debug_and_displayed_errors() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--bootstrap-secret".to_owned(),
                "top-secret".to_owned(),
            ],
            Vec::new(),
        )?;
        let secret = config
            .bootstrap_secret()
            .ok_or_else(|| std::io::Error::other("secret missing"))?;
        assert_eq!(secret.expose(), "top-secret");
        assert!(!format!("{config:?}").contains("top-secret"));
        assert_eq!(secret.to_string(), "<redacted>");
        Ok(())
    }

    #[test]
    fn positional_argument_is_rejected_without_keeping_its_value() {
        let result = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--bootstrap-password=part1".to_owned(),
                "part2-secret".to_owned(),
            ],
            Vec::new(),
        );
        assert!(matches!(result, Err(ConfigError::UnexpectedArgument)));
        let rendered = format!("{:?} {}", result, ConfigError::UnexpectedArgument);
        assert!(!rendered.contains("part2-secret"));
    }

    #[test]
    fn dash_prefixed_argument_is_rejected_without_keeping_its_value() {
        for secret_tail in ["-Xsecret", "--Secret!", "--a=b"] {
            let result = Config::from_sources(
                [
                    "o3kd".to_owned(),
                    "--bootstrap-password=part1".to_owned(),
                    secret_tail.to_owned(),
                ],
                Vec::new(),
            );
            let rendered = format!("{result:?}");
            assert!(!rendered.contains("secret"), "{rendered}");
            assert!(!rendered.contains("Secret"), "{rendered}");
        }
        let mistyped = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--databse-url=postgres://o3k:secret@db/o3k".to_owned(),
            ],
            Vec::new(),
        );
        assert!(matches!(
            mistyped,
            Err(ConfigError::UnknownOption(ref option)) if option == "--databse-url"
        ));
        assert!(!format!("{mistyped:?}").contains("secret"));
    }

    #[test]
    fn invalid_configuration_fails_before_runtime_use() {
        let result = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--listen-addr".to_owned(),
                "not-an-address".to_owned(),
            ],
            Vec::new(),
        );
        assert!(matches!(result, Err(ConfigError::InvalidListenAddress)));
    }

    #[test]
    fn bootstrap_password_requires_a_strong_separate_signing_key() {
        let result = Config::from_sources(
            ["o3kd".to_owned()],
            env(&[
                ("O3K_BOOTSTRAP_PASSWORD", "password"),
                ("O3K_TOKEN_SIGNING_KEY", "short"),
            ]),
        );
        assert!(matches!(result, Err(ConfigError::WeakTokenSigningKey)));
    }

    #[test]
    fn compute_tls_configuration_cannot_be_partial() {
        let result = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--compute-server-certificate".to_owned(),
                "server.pem".to_owned(),
            ],
            Vec::new(),
        );
        assert!(matches!(result, Err(ConfigError::IncompleteComputeTls)));
    }

    #[test]
    fn agent_provider_requires_authorized_compute_tls() {
        let result = Config::from_sources(
            ["o3kd".to_owned(), "--provider=agent".to_owned()],
            Vec::new(),
        );
        assert!(matches!(
            result,
            Err(ConfigError::MissingAgentConfiguration)
        ));
    }

    #[test]
    fn default_database_backend_is_sqlite() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(["o3kd".to_owned()], Vec::new())?;
        assert_eq!(config.database_backend, DatabaseBackend::Sqlite);
        assert!(config.database_url().is_none());
        Ok(())
    }

    #[test]
    fn postgres_database_backend_requires_url() {
        let result = Config::from_sources(
            ["o3kd".to_owned(), "--database-backend=postgres".to_owned()],
            Vec::new(),
        );
        assert!(matches!(result, Err(ConfigError::MissingDatabaseUrl)));
    }

    #[test]
    fn postgres_database_backend_configured_from_env() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(
            ["o3kd".to_owned()],
            env(&[
                ("O3K_DATABASE_BACKEND", "postgres"),
                (
                    "O3K_DATABASE_URL",
                    "postgres://o3k:secret-password@127.0.0.1/o3k",
                ),
            ]),
        )?;
        assert_eq!(config.database_backend, DatabaseBackend::Postgres);
        let url = config
            .database_url()
            .ok_or_else(|| std::io::Error::other("url missing"))?;
        assert_eq!(url.expose(), "postgres://o3k:secret-password@127.0.0.1/o3k");
        assert_eq!(url.to_string(), "<redacted>");
        assert!(!format!("{config:?}").contains("secret-password"));
        Ok(())
    }

    #[test]
    fn kubernetes_deployment_profile_rejects_sqlite() {
        let result = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--deployment-profile=kubernetes".to_owned(),
            ],
            Vec::new(),
        );
        assert!(matches!(
            result,
            Err(ConfigError::KubernetesRequiresPostgres)
        ));
    }

    #[test]
    fn kubernetes_deployment_profile_accepts_postgres() -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(
            [
                "o3kd".to_owned(),
                "--deployment-profile=kubernetes".to_owned(),
                "--database-backend=postgres".to_owned(),
                "--database-url=postgres://o3k:pass@127.0.0.1/o3k".to_owned(),
            ],
            Vec::new(),
        )?;
        assert_eq!(config.deployment_profile, DeploymentProfile::Kubernetes);
        assert_eq!(config.database_backend, DatabaseBackend::Postgres);
        Ok(())
    }

    #[test]
    fn unset_network_gateway_realization_defaults_to_enabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(["o3kd".to_owned()], Vec::new())?;
        assert!(config.network_gateway_realization);
        Ok(())
    }

    #[test]
    fn network_gateway_realization_enabled_value_activates_realization()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(
            ["o3kd".to_owned()],
            env(&[("O3K_NETWORK_GATEWAY_REALIZATION", "enabled")]),
        )?;
        assert!(config.network_gateway_realization);
        Ok(())
    }

    #[test]
    fn network_gateway_realization_empty_value_means_enabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(
            ["o3kd".to_owned()],
            env(&[("O3K_NETWORK_GATEWAY_REALIZATION", "")]),
        )?;
        assert!(config.network_gateway_realization);
        Ok(())
    }

    #[test]
    fn network_gateway_realization_disabled_value_deactivates_realization()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::from_sources(
            ["o3kd".to_owned()],
            env(&[("O3K_NETWORK_GATEWAY_REALIZATION", "disabled")]),
        )?;
        assert!(!config.network_gateway_realization);
        Ok(())
    }

    #[test]
    fn network_gateway_realization_rejects_unknown_values() {
        let result = Config::from_sources(
            ["o3kd".to_owned()],
            env(&[("O3K_NETWORK_GATEWAY_REALIZATION", "yes")]),
        );
        assert!(matches!(
            result,
            Err(ConfigError::InvalidNetworkGatewayRealization)
        ));
    }
}
