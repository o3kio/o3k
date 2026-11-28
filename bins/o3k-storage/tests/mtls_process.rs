#![allow(clippy::expect_used, clippy::unwrap_used)]

use o3k_controller_protocol::storage::{
    StorageCommand, storage_executor_client::StorageExecutorClient,
};
use std::{fs, net::TcpListener, path::Path, process::Command, time::Duration};
use tempfile::TempDir;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

fn run(root: &Path, args: &[&str]) {
    let status = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .status()
        .expect("openssl");
    assert!(status.success(), "openssl command failed: {args:?}");
}

fn certs() -> (TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    run(root.path(), &["genrsa", "-out", "ca-key.pem", "2048"]);
    run(
        root.path(),
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "ca-key.pem",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=o3k-test-ca",
        ],
    );
    run(root.path(), &["genrsa", "-out", "server-key.pem", "2048"]);
    run(
        root.path(),
        &[
            "req",
            "-new",
            "-key",
            "server-key.pem",
            "-out",
            "server.csr",
            "-subj",
            "/CN=localhost",
        ],
    );
    fs::write(
        root.path().join("server.ext"),
        "subjectAltName=DNS:localhost\n",
    )
    .unwrap();
    run(
        root.path(),
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-CAcreateserial",
            "-out",
            "server.pem",
            "-days",
            "1",
            "-extfile",
            "server.ext",
        ],
    );
    run(root.path(), &["genrsa", "-out", "client-key.pem", "2048"]);
    run(
        root.path(),
        &[
            "req",
            "-new",
            "-key",
            "client-key.pem",
            "-out",
            "client.csr",
            "-subj",
            "/CN=controller",
        ],
    );
    fs::write(
        root.path().join("client.ext"),
        "subjectAltName=URI:spiffe://o3k/controller\n",
    )
    .unwrap();
    run(
        root.path(),
        &[
            "x509",
            "-req",
            "-in",
            "client.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-CAcreateserial",
            "-out",
            "client.pem",
            "-days",
            "1",
            "-extfile",
            "client.ext",
        ],
    );
    run(root.path(), &["genrsa", "-out", "foreign-key.pem", "2048"]);
    run(
        root.path(),
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "foreign-key.pem",
            "-out",
            "foreign-ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=foreign-ca",
        ],
    );
    run(
        root.path(),
        &[
            "req",
            "-new",
            "-key",
            "foreign-key.pem",
            "-out",
            "foreign.csr",
            "-subj",
            "/CN=controller",
        ],
    );
    run(
        root.path(),
        &[
            "x509",
            "-req",
            "-in",
            "foreign.csr",
            "-CA",
            "foreign-ca.pem",
            "-CAkey",
            "foreign-key.pem",
            "-CAcreateserial",
            "-out",
            "foreign.pem",
            "-days",
            "1",
            "-extfile",
            "client.ext",
        ],
    );
    (root, "spiffe://o3k/controller".into())
}

fn tls(root: &Path, with_client: bool, foreign: bool) -> ClientTlsConfig {
    let cert = if foreign { "foreign.pem" } else { "client.pem" };
    let key = if foreign {
        "foreign-key.pem"
    } else {
        "client-key.pem"
    };
    let mut config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(
            fs::read(root.join("ca.pem")).unwrap(),
        ))
        .domain_name("localhost");
    if with_client {
        config = config.identity(Identity::from_pem(
            fs::read(root.join(cert)).unwrap(),
            fs::read(root.join(key)).unwrap(),
        ));
    }
    config
}

async fn connect(
    port: u16,
    config: ClientTlsConfig,
) -> Result<StorageExecutorClient<Channel>, tonic::transport::Error> {
    Endpoint::from_shared(format!("https://localhost:{port}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(1))
        .tls_config(config)
        .unwrap()
        .connect()
        .await
        .map(StorageExecutorClient::new)
}

#[tokio::test]
async fn process_executor_enforces_ca_signed_client_certificates() {
    let (root, _) = certs();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let binary = env!("CARGO_BIN_EXE_o3k-storage-bin");
    let journal = root.path().join("journal.json");
    let mut child = Command::new(binary)
        .env("O3K_STORAGE_LISTEN", format!("127.0.0.1:{port}"))
        .env("O3K_STORAGE_JOURNAL", &journal)
        .env("O3K_STORAGE_AGENT_ID", "agent-a")
        .env("O3K_STORAGE_AGENT_EPOCH", "epoch-a")
        .env("O3K_STORAGE_VOLUME_GROUP", "test-vg")
        .env("O3K_STORAGE_THIN_POOL", "test-pool")
        .env("O3K_STORAGE_CONTROLLER_IDENTITY", "spiffe://o3k/controller")
        .env("O3K_STORAGE_TLS_CERT", root.path().join("server.pem"))
        .env("O3K_STORAGE_TLS_KEY", root.path().join("server-key.pem"))
        .env("O3K_STORAGE_TLS_CLIENT_CA", root.path().join("ca.pem"))
        .spawn()
        .unwrap();
    for _ in 0..20 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let mut no_cert = connect(port, tls(root.path(), false, false))
        .await
        .expect("TLS connection may complete before RPC peer-cert validation");
    assert!(
        no_cert
            .execute(StorageCommand {
                envelope_json: vec![],
                payload_json: vec![],
            })
            .await
            .is_err()
    );
    let mut foreign = connect(port, tls(root.path(), true, true))
        .await
        .expect("TLS connection may complete before identity validation");
    assert!(
        foreign
            .execute(StorageCommand {
                envelope_json: vec![],
                payload_json: vec![],
            })
            .await
            .is_err()
    );
    let mut client = connect(port, tls(root.path(), true, false))
        .await
        .expect("CA-signed client accepted");
    let result = client
        .execute(StorageCommand {
            envelope_json: vec![],
            payload_json: vec![],
        })
        .await;
    assert!(
        result.is_err(),
        "malformed command must be rejected after TLS authentication"
    );
    child.kill().unwrap();
    let _ = child.wait();
}
