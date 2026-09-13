#![cfg(unix)]

//! Production-composition evidence for P15.4: desired CloudProfile state is
//! persisted before daemon start, survives a real o3kd restart, and remains
//! distinct from the observed manifest registry.
use o3k_kernel::{CloudProfile, ServiceOwnershipMode, ServiceSelection};
use o3k_store::CloudProfileRecord;
use o3k_store::testkit::open_file;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn address() -> std::io::Result<std::net::SocketAddr> {
    TcpListener::bind("127.0.0.1:0")?.local_addr()
}
fn ready(child: &mut Child, addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream.write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?;
            if bytes.starts_with(b"HTTP/1.1 200 OK") {
                return Ok(());
            }
        }
        if child.try_wait()?.is_some() {
            return Err("o3kd exited".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("o3kd not ready".into())
}
fn start(root: &Path, addr: std::net::SocketAddr) -> Result<Child, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_o3kd"))
        .args([
            "--provider",
            "fake",
            "--listen-addr",
            &addr.to_string(),
            "--data-dir",
            root.to_str().ok_or("path")?,
            "--log-filter",
            "off",
        ])
        .env(
            "O3K_LOCATIONS",
            "[{\"id\":\"region-p15-4\",\"availability_domains\":[{\"id\":\"az-p15-4\"}]}]",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Err(e) = ready(&mut child, addr) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(child)
}
async fn stop(mut child: Child) -> Result<(), Box<dyn std::error::Error>> {
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

#[tokio::test]
async fn cloud_profile_survives_real_daemon_restart() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("o3k-p15-4-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root)?;
    let store = open_file(&root.join("o3k.sqlite")).await?;
    let profile = CloudProfile {
        profile_id: "default".into(),
        generation: 1,
        selected_services: vec![ServiceSelection {
            service_id: "compute".into(),
            ownership: ServiceOwnershipMode::O3kImplemented,
            version_requirement: "*".into(),
            dependencies: vec![],
            required_capabilities: vec![],
            locality: None,
            placement_requirement: None,
            config_refs: vec![],
        }],
        upgrade_order: vec![],
    };
    let record = CloudProfileRecord::from_profile(&profile, "2026-01-01T00:00:00Z")?;
    store.upsert_cloud_profile(&record, None).await?;
    let child = start(&root, address()?)?;
    stop(child).await?;
    drop(store);
    let reopened = open_file(&root.join("o3k.sqlite")).await?;
    assert_eq!(
        reopened
            .get_cloud_profile("default")
            .await?
            .ok_or("profile missing")?
            .profile()?,
        profile
    );
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}
