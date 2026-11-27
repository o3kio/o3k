use o3k_compute_agent::EnrollmentIdentity;

#[test]
fn rejects_san_delimiters_and_unbounded_epoch() {
    for value in ["bad,uri", "bad\\uri", "bad\nuri", "bad\"uri", ""] {
        assert!(EnrollmentIdentity::generate(value, "epoch-1").is_err());
        assert!(EnrollmentIdentity::generate("host-a", value).is_err());
    }
    assert!(EnrollmentIdentity::generate("host-a", &"x".repeat(129)).is_err());
}

#[test]
fn csr_contains_agent_and_epoch_sans_without_exposing_key() -> Result<(), Box<dyn std::error::Error>>
{
    let identity = EnrollmentIdentity::generate("host-a", "epoch-1")?;
    let csr = openssl::x509::X509Req::from_pem(identity.csr_pem())?;
    let text = csr.to_text()?;
    let text = String::from_utf8_lossy(&text);
    assert!(text.contains("urn:o3k:compute:agent:host-a"));
    assert!(text.contains("urn:o3k:compute:epoch:epoch-1"));
    assert!(!format!("{identity:?}").contains("PRIVATE KEY"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn private_key_is_created_locally_with_mode_0600() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("agent-key.pem");
    let identity = EnrollmentIdentity::generate("host-a", "epoch-1")?;
    identity.write_private_key(&path)?;
    use std::os::unix::fs::MetadataExt;
    assert_eq!(path.metadata()?.mode() & 0o777, 0o600);
    let bytes = std::fs::read(path)?;
    assert!(bytes.starts_with(b"-----BEGIN PRIVATE KEY-----"));
    Ok(())
}
