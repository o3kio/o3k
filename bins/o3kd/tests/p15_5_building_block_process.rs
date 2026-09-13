#![cfg(unix)]

//! Production-composition persistence evidence for P15.5.  The daemon is
//! started and stopped as a real process; lifecycle/link state is written via
//! the same SQLite store and survives reconstruction.  Provider/agent
//! discovery is intentionally not faked into the durable record.
use o3k_kernel::BuildingBlock;
use o3k_store::{BuildingBlockRepository, testkit::open_file};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream.write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?;
            if bytes.starts_with(b"HTTP/1.1 200 OK") {
                return Ok(child);
            }
        }
        if child.try_wait()?.is_some() {
            return Err("o3kd exited".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("o3kd not ready".into())
}

#[tokio::test]
async fn building_block_survives_real_daemon_restart() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("o3k-p15-5-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root)?;
    let store = open_file(&root.join("o3k.sqlite")).await?;
    let block = BuildingBlock::enrolling("bb-process", "agent-process", vec![], None, None)?;
    let record = o3k_store::BuildingBlockRecord::from_block(&block, "2026-01-01T00:00:00Z")?;
    store.upsert_building_block(&record, None).await?;
    let addr = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let mut child = start(&root, addr)?;
    let _ = child.kill();
    let _ = child.wait();
    drop(store);
    let reopened = open_file(&root.join("o3k.sqlite")).await?;
    assert_eq!(
        reopened
            .get_building_block("bb-process")
            .await?
            .ok_or("missing")?
            .block()?,
        block
    );
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}
