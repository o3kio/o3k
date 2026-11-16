//! Pins the qualification-only Python ceremony signer
//! (`tests/pp6-c1-ceremony/sign.py`) against the canonical Rust verifiers:
//! every document the signer emits must pass `identity::verify_signed`,
//! `verify_policy`, `verify_initial_state_transition`, and
//! `recovery_trust::verify_trust_bundle`, and a tampered byte must fail.
//!
//! The test is skipped (with a message) when python3 or the `cryptography`
//! module is unavailable; CI runners that have both execute it fully.

use ed25519_dalek::VerifyingKey;
use o3k::recovery_identity as identity;
use o3k::recovery_trust;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

fn signer_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/pp6-c1-ceremony/sign.py")
        .canonicalize()
        .expect("signer path")
}

fn python_available() -> bool {
    Command::new("python3")
        .args(["-c", "import cryptography"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_signer(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.arg(signer_path());
    cmd.args(args);
    let output = cmd.output().expect("run signer");
    assert!(
        output.status.success(),
        "signer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn vk(hex_key: &str) -> VerifyingKey {
    let bytes: [u8; 32] = hex::decode(hex_key).unwrap().try_into().unwrap();
    VerifyingKey::from_bytes(&bytes).unwrap()
}

#[test]
fn qualification_signer_output_passes_the_canonical_verifiers() {
    if !python_available() {
        eprintln!("skipping: python3 with the cryptography module is unavailable");
        return;
    }
    let unique = format!(
        "o3k-c1-signer-test-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let work = std::env::temp_dir().join(unique);
    let keys = work.join("keys");
    let out = work.join("out");
    let policy_key_id = "c1qual-policy-key";
    run_signer(&[
        "keygen",
        "--out",
        keys.to_str().unwrap(),
        "--policy-key-id",
        policy_key_id,
    ]);
    let keys_meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(keys.join("keys.json")).unwrap(),
    )
    .unwrap();
    let policy_pub = keys_meta["public_keys"]["policy"].as_str().unwrap().to_string();
    let journal_root_pub = keys_meta["public_keys"]["journal-root"]
        .as_str()
        .unwrap()
        .to_string();
    let evidence_root_pub = keys_meta["public_keys"]["evidence-root"]
        .as_str()
        .unwrap()
        .to_string();

    let installation_id = "ab".repeat(32);
    let descriptor = serde_json::json!({
        "format": "o3k-recovery-provisioning-v1",
        "unsigned": true,
        "authentication": "none",
        "installation_id": installation_id,
        "site_id": "cd".repeat(32),
        "profile": "o3k-demo-v1",
        "backend": "sqlite",
        "release_identity": "ef".repeat(32),
        "policy_authority": {
            "key_id": policy_key_id,
            "ed25519_public_key": policy_pub,
            "policy_format": "o3k-installation-policy-v1",
            "policy_path": "/etc/o3k/installation-policy.json"
        },
        "data_root": "/var/lib/o3k",
        "data_root_device": 2049,
        "data_root_inode": 1001,
        "recovery_state_root": format!("/var/lib/o3k-recovery-state/{installation_id}"),
        "recovery_state_device": 2049,
        "recovery_state_inode": 1002,
        "journal_directory": format!("/var/lib/o3k-recovery/{installation_id}"),
        "journal_device": 2049,
        "journal_inode": 1003,
        "policy_path": "/etc/o3k/installation-policy.json",
        "trust_bundle_path": "/etc/o3k/recovery-trust.json"
    });
    let descriptor_path = work.join("descriptor.json");
    std::fs::write(&descriptor_path, serde_json::to_string(&descriptor).unwrap()).unwrap();
    run_signer(&[
        "sign",
        "--descriptor",
        descriptor_path.to_str().unwrap(),
        "--keys",
        keys.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);

    let policy_bytes = std::fs::read(out.join("policy.json")).unwrap();
    let state_bytes = std::fs::read(out.join("state.json")).unwrap();
    let trust_bytes = std::fs::read(out.join("trust.json")).unwrap();

    let policy: identity::InstallationPolicy = identity::verify_signed(
        &policy_bytes,
        "o3k-installation-policy-v1",
        policy_key_id,
        &vk(&policy_pub),
    )
    .expect("signed policy must verify");
    identity::verify_policy(&policy, policy_key_id).expect("policy binding must verify");

    let state: identity::InstallationState = identity::verify_signed(
        &state_bytes,
        "o3k-installation-state-v1",
        policy_key_id,
        &vk(&policy_pub),
    )
    .expect("genesis state must verify");
    identity::verify_initial_state_transition(None, &state, &policy)
        .expect("genesis transition must verify");
    assert_eq!(
        state.policy_digest,
        hex::encode(Sha256::digest(&policy_bytes)),
        "genesis state must bind the signed policy bytes"
    );

    let trust: identity::TrustBundle =
        identity::decode_canonical(&trust_bytes).expect("trust bundle must be canonical");
    assert_eq!(
        hex::encode(Sha256::digest(&trust_bytes)),
        policy.trust_bundle_digest,
        "policy must bind the trust bundle bytes"
    );
    recovery_trust::verify_trust_bundle(
        trust,
        &vk(&journal_root_pub),
        &vk(&evidence_root_pub),
        chrono::Utc::now().timestamp(),
        None,
        None,
    )
    .expect("trust bundle must verify as current trust");

    // Negative: a single flipped byte anywhere in each signed document must
    // break authentication.
    let mut tampered_policy = policy_bytes.clone();
    let mid = tampered_policy.len() / 2;
    tampered_policy[mid] ^= 0x01;
    assert!(
        identity::verify_signed::<identity::InstallationPolicy>(
            &tampered_policy,
            "o3k-installation-policy-v1",
            policy_key_id,
            &vk(&policy_pub),
        )
        .is_err(),
        "tampered policy still authenticates"
    );
    let mut tampered_state = state_bytes.clone();
    let mid = tampered_state.len() / 2;
    tampered_state[mid] ^= 0x01;
    assert!(
        identity::verify_signed::<identity::InstallationState>(
            &tampered_state,
            "o3k-installation-state-v1",
            policy_key_id,
            &vk(&policy_pub),
        )
        .is_err(),
        "tampered state still authenticates"
    );
    let mut tampered_trust = trust_bytes.clone();
    let mid = tampered_trust.len() / 2;
    tampered_trust[mid] ^= 0x01;
    let trust_canonical =
        identity::decode_canonical::<identity::TrustBundle>(&tampered_trust).is_ok();
    assert!(
        !(trust_canonical
            && hex::encode(Sha256::digest(&tampered_trust)) == policy.trust_bundle_digest),
        "tampered trust bundle still authenticates"
    );

    std::fs::remove_dir_all(&work).ok();
}
