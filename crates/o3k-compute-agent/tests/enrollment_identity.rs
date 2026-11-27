use o3k_compute_agent::EnrollmentIdentity;

#[test]
fn csr_contains_agent_and_epoch_sans_without_exposing_key() {
    let identity = EnrollmentIdentity::generate("host-a", "epoch-1").unwrap();
    let csr = openssl::x509::X509Req::from_pem(identity.csr_pem()).unwrap();
    let text = csr.to_text().unwrap();
    let text = String::from_utf8_lossy(&text);
    assert!(text.contains("urn:o3k:compute:agent:host-a"));
    assert!(text.contains("urn:o3k:compute:epoch:epoch-1"));
    assert!(!format!("{identity:?}").contains("PRIVATE KEY"));
}

#[cfg(unix)]
#[test]
fn private_key_is_created_locally_with_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent-key.pem");
    let identity = EnrollmentIdentity::generate("host-a", "epoch-1").unwrap();
    identity.write_private_key(&path).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.starts_with(b"-----BEGIN PRIVATE KEY-----"));
}
