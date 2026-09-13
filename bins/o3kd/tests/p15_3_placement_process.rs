#![cfg(unix)]

//! P15.3 production-composition evidence: a real `o3kd` owns the SQLite
//! database while Placement state is published through the same durable path,
//! then the daemon is restarted and all canonical state is reconstructed.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use o3k_kernel::TopologyStore;
use o3k_placement::{CandidateRequest, Inventory, PlacementLedger, VCPU};
use o3k_store::testkit::open_file;
use o3k_store::{DurableStore, ResourceRecord};
use uuid::Uuid;

fn wait_ready(
    child: &mut Child,
    address: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(address) {
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.write_all(
                b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            if response.starts_with(b"HTTP/1.1 200 OK") {
                return Ok(());
            }
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("o3kd exited during startup: {status}").into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("o3kd did not become ready".into())
}

fn start_o3kd(
    data_dir: &Path,
    address: std::net::SocketAddr,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_o3kd"))
        .args([
            "--provider",
            "fake",
            "--listen-addr",
            &address.to_string(),
            "--data-dir",
            data_dir.to_str().ok_or("non-utf8 data path")?,
            "--log-filter",
            "off",
        ])
        .env(
            "O3K_LOCATIONS",
            r#"[{"id":"region-p15","availability_domains":[{"id":"az-p15"}]}]"#,
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Err(error) = wait_ready(&mut child, address) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(child)
}

fn free_address() -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

fn inventory() -> BTreeMap<String, Inventory> {
    BTreeMap::from([(
        VCPU.to_owned(),
        Inventory {
            total: 8,
            reserved: 0,
            allocation_ratio: 1.0,
            used: 0,
        },
    )])
}

async fn stop(mut child: Child) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()?;
    if !status.success() {
        child.kill()?;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(format!("o3kd shutdown failed: {status}").into());
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.kill()?;
    let _ = child.wait();
    Err("o3kd did not shut down".into())
}

#[tokio::test]
async fn real_o3kd_placement_hierarchy_survives_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let root = std::env::temp_dir().join(format!("o3k-p15-3-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root)?;
    let store = open_file(&root.join("o3k.sqlite")).await?;
    let consumer_id = Uuid::now_v7();
    store
        .insert_resource(&ResourceRecord {
            id: consumer_id,
            kind: "compute_instance".to_owned(),
            project_id: "project-p15-3".to_owned(),
            generation: 1,
            observed_generation: 1,
            desired_state: "ACTIVE".to_owned(),
            observed_state: "ACTIVE".to_owned(),
            provider_id: None,
        })
        .await?;
    let address = free_address()?;
    let child = start_o3kd(&root, address)?;

    let repository: std::sync::Arc<dyn o3k_store::PlacementRepository> =
        std::sync::Arc::new(store.clone());
    let ledger = PlacementLedger::open(root.join("placement"), repository).await?;
    let parent = ledger.register_provider("parent", inventory()).await?;
    let provider = ledger
        .register_provider_hierarchical(
            "provider-b",
            inventory(),
            Some(&parent.id),
            BTreeSet::from(["COMPUTE".to_owned(), "SPECIAL_X".to_owned()]),
            BTreeSet::from(["fd-a".to_owned()]),
            Some("az-p15"),
        )
        .await?;
    let request = CandidateRequest {
        resources: BTreeMap::from([(VCPU.to_owned(), 2)]),
        required_traits: BTreeSet::from(["SPECIAL_X".to_owned()]),
        locations: BTreeSet::from(["az-p15".to_owned()]),
        limit: 8,
        ..CandidateRequest::default()
    };
    let candidate = ledger
        .candidates(&request)
        .await?
        .into_iter()
        .next()
        .ok_or("constrained candidate missing")?;
    assert_eq!(candidate.provider_id, provider.id);
    let intent = ledger
        .begin_allocation_intent(
            &candidate.provider_id,
            "allocation-p15-3",
            &consumer_id.to_string(),
            request.resources.clone(),
        )
        .await?;
    ledger
        .commit_allocation_intent(&intent, candidate.generation)
        .await?;
    drop(ledger);
    drop(store);
    stop(child).await?;

    let address = free_address()?;
    let child = start_o3kd(&root, address)?;
    let restored_store = open_file(&root.join("o3k.sqlite")).await?;
    let snapshot = restored_store.load_snapshot().await?;
    assert!(
        snapshot
            .regions
            .iter()
            .any(|region| region.id == "region-p15")
    );
    assert!(
        snapshot
            .regions
            .iter()
            .flat_map(|region| region.availability_domains.iter())
            .any(|az| az.id == "az-p15")
    );
    let repository: std::sync::Arc<dyn o3k_store::PlacementRepository> =
        std::sync::Arc::new(restored_store.clone());
    let restored = PlacementLedger::open(root.join("placement"), repository).await?;
    let provider = restored.provider("provider-b").await?;
    assert_eq!(provider.parent_provider_id.as_deref(), Some("parent"));
    assert!(provider.traits.contains("SPECIAL_X"));
    assert!(provider.failure_domains.contains("fd-a"));
    assert_eq!(provider.location.as_deref(), Some("az-p15"));
    assert!(provider.allocations.contains_key("allocation-p15-3"));
    assert_eq!(restored.candidates(&request).await?.len(), 1);
    drop(restored);
    drop(restored_store);
    stop(child).await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
