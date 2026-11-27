use o3k_compute_agent::validate_csr_uri_sans;
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509, X509Extension, X509NameBuilder, X509Req},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX: usize = 1024 * 1024;

#[cfg(all(unix, test))]
fn expected_owner_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(all(unix, not(test)))]
fn expected_owner_uid() -> u32 {
    0
}

#[derive(Deserialize)]
struct Request {
    grant_id: String,
    token: Vec<u8>,
    agent_id: String,
    agent_epoch: String,
    csr_pem: Vec<u8>,
}
#[derive(Serialize)]
struct Response {
    agent_id: String,
    agent_epoch: String,
    client_certificate_chain_pem: Vec<u8>,
    ca_certificate_pem: Vec<u8>,
    ca_fingerprint_sha256: String,
    certificate_expires_at_unix_ms: u64,
    rotation_deadline_unix_ms: u64,
}
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn bounded<R: Read>(stream: &mut R) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    stream
        .take((MAX + 1) as u64)
        .read_to_end(&mut b)
        .map_err(|_| "read failed".to_owned())?;
    if b.len() > MAX {
        return Err("request too large".to_owned());
    }
    Ok(b)
}
fn peer_ok<S: std::os::fd::AsFd>(stream: &S) -> Result<(), String> {
    let uid: u32 = std::env::var("O3K_ENROLLMENT_SOCKET_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/passwd").ok().and_then(|p| {
                p.lines()
                    .find(|l| l.starts_with("o3k:"))
                    .and_then(|l| l.split(':').nth(2))
                    .and_then(|v| v.parse().ok())
            })
        })
        .ok_or("o3k socket user is not configured")?;
    let peer = rustix::net::sockopt::get_socket_peercred(stream)
        .map_err(|_| "peer credentials unavailable".to_owned())?;
    if peer.uid.as_raw() != uid {
        return Err("unauthorized peer".to_owned());
    }
    Ok(())
}
fn load_ca(dir: &Path) -> Result<Option<(PKey<Private>, X509)>, String> {
    let dir_meta = match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("CA directory metadata unavailable".into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !dir_meta.file_type().is_dir()
            || dir_meta.uid() != expected_owner_uid()
            || (dir_meta.mode() & 0o077) != 0
        {
            return Err("CA directory ownership or mode is unsafe".into());
        }
    }
    let key_path = dir.join("key.pem");
    let cert_path = dir.join("cert.pem");
    load_ca_files(&key_path, &cert_path).map(Some)
}

fn load_ca_files(key_path: &Path, cert_path: &Path) -> Result<(PKey<Private>, X509), String> {
    let key_meta = std::fs::symlink_metadata(key_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "CA directory is incomplete"
        } else {
            "CA key metadata unavailable"
        }
    })?;
    let cert_meta = std::fs::symlink_metadata(cert_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "CA directory is incomplete"
        } else {
            "CA cert metadata unavailable"
        }
    })?;
    if !key_meta.file_type().is_file() || !cert_meta.file_type().is_file() {
        return Err("CA paths are unsafe".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if key_meta.uid() != expected_owner_uid()
            || key_meta.mode() & 0o077 != 0
            || cert_meta.uid() != expected_owner_uid()
            || cert_meta.mode() & 0o022 != 0
        {
            return Err("CA file ownership or mode is unsafe".into());
        }
    }
    let key =
        PKey::private_key_from_pem(&std::fs::read(key_path).map_err(|_| "CA key unavailable")?)
            .map_err(|_| "invalid CA key")?;
    let cert = X509::from_pem(&std::fs::read(cert_path).map_err(|_| "CA cert unavailable")?)
        .map_err(|_| "invalid CA cert")?;
    if !cert.verify(&key).unwrap_or(false) {
        return Err("CA key does not match certificate".into());
    }
    Ok((key, cert))
}

fn publish_ca(dir: &Path, key: &PKey<Private>, cert: &X509) -> Result<(), String> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let parent = dir.parent().ok_or("CA directory has no parent")?;
    std::fs::create_dir_all(parent).map_err(|_| "CA parent directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| "CA parent metadata")?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != expected_owner_uid()
            || metadata.mode() & 0o022 != 0
        {
            return Err("CA parent ownership or mode is unsafe".into());
        }
    }
    let mut suffix = [0u8; 16];
    openssl::rand::rand_bytes(&mut suffix).map_err(|_| "CA temporary name")?;
    let temporary = parent.join(format!(".enrollment-ca-{}", hex::encode(suffix)));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(&temporary)
        .map_err(|_| "CA temporary directory")?;
    let write_result = (|| {
        #[cfg(unix)]
        let key_options = {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
        };
        #[cfg(not(unix))]
        let key_options = {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            options
        };
        let key_path = temporary.join("key.pem");
        let mut key_file = key_options.open(&key_path).map_err(|_| "CA key create")?;
        key_file
            .write_all(
                &key.private_key_to_pem_pkcs8()
                    .map_err(|_| "CA key encode")?,
            )
            .map_err(|_| "CA key write")?;
        key_file.sync_all().map_err(|_| "CA key sync")?;

        #[cfg(unix)]
        let cert_options = {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o644);
            options
        };
        #[cfg(not(unix))]
        let cert_options = {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            options
        };
        let cert_path = temporary.join("cert.pem");
        let mut cert_file = cert_options
            .open(&cert_path)
            .map_err(|_| "CA cert create")?;
        cert_file
            .write_all(&cert.to_pem().map_err(|_| "CA cert encode")?)
            .map_err(|_| "CA cert write")?;
        cert_file.sync_all().map_err(|_| "CA cert sync")?;
        std::fs::File::open(&temporary)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "CA temporary directory sync")?;
        Ok::<(), String>(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_dir_all(&temporary);
        return Err(error);
    }
    match std::fs::rename(&temporary, dir) {
        Ok(()) => {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "CA parent directory sync")?;
            Ok(())
        }
        Err(_) if dir.exists() => {
            let _ = std::fs::remove_dir_all(&temporary);
            Ok(())
        }
        Err(_) => {
            let _ = std::fs::remove_dir_all(&temporary);
            Err("CA directory publish failed".into())
        }
    }
}

fn ensure_ca(
    dir: &Path,
    legacy_key_path: &Path,
    legacy_cert_path: &Path,
) -> Result<(PKey<Private>, X509), String> {
    if let Some(ca) = load_ca(dir)? {
        return Ok(ca);
    }
    let legacy_key = std::fs::symlink_metadata(legacy_key_path).ok();
    let legacy_cert = std::fs::symlink_metadata(legacy_cert_path).ok();
    let (key, cert) = match (legacy_key, legacy_cert) {
        (Some(_), Some(_)) => load_ca_files(legacy_key_path, legacy_cert_path)?,
        (None, None) => generate_ca()?,
        _ => return Err("legacy CA state is incomplete".into()),
    };
    publish_ca(dir, &key, &cert)?;
    load_ca(dir)?.ok_or_else(|| "published CA is unavailable".to_owned())
}

fn generate_ca() -> Result<(PKey<Private>, X509), String> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|_| "EC group")?;
    let key = PKey::from_ec_key(EcKey::generate(&group).map_err(|_| "CA key generation failed")?)
        .map_err(|_| "CA key generation failed")?;
    let mut name = X509NameBuilder::new().map_err(|_| "CA name")?;
    name.append_entry_by_text("CN", "O3K Early Access Enrollment CA")
        .map_err(|_| "CA name")?;
    let name = name.build();
    let mut b = X509::builder().map_err(|_| "CA builder")?;
    b.set_version(2).map_err(|_| "CA version")?;
    b.set_subject_name(&name).map_err(|_| "CA subject")?;
    b.set_issuer_name(&name).map_err(|_| "CA issuer")?;
    b.set_pubkey(&key).map_err(|_| "CA pubkey")?;
    #[allow(deprecated)]
    b.append_extension(
        X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, "critical,CA:TRUE")
            .map_err(|_| "CA constraints")?,
    )
    .map_err(|_| "CA constraints")?;
    let before = Asn1Time::days_from_now(0).map_err(|_| "CA time")?;
    let after = Asn1Time::days_from_now(3650).map_err(|_| "CA time")?;
    b.set_not_before(&before).map_err(|_| "CA time")?;
    b.set_not_after(&after).map_err(|_| "CA time")?;
    b.sign(&key, MessageDigest::sha256())
        .map_err(|_| "CA sign")?;
    let cert = b.build();
    Ok((key, cert))
}
#[allow(deprecated)]
fn issue(req: Request, key: &PKey<Private>, ca: &X509) -> Result<Response, String> {
    if req.grant_id.trim().is_empty()
        || req.token.is_empty()
        || req.agent_id.is_empty()
        || req.agent_epoch.is_empty()
    {
        return Err("incomplete request".into());
    }
    if !safe_component(&req.agent_id) || !safe_component(&req.agent_epoch) {
        return Err("invalid enrollment identity".into());
    }
    let csr = X509Req::from_pem(&req.csr_pem).map_err(|_| "invalid CSR")?;
    let subject = csr.subject_name();
    let cn = subject
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .ok_or("CSR CN missing")?
        .data()
        .to_string()
        .map_err(|_| "CSR CN invalid")?;
    if cn != req.agent_id {
        return Err("CSR identity mismatch".into());
    }
    let agent_uri = format!("urn:o3k:compute:agent:{}", req.agent_id);
    let epoch_uri = format!("urn:o3k:compute:epoch:{}", req.agent_epoch);
    validate_csr_uri_sans(&req.csr_pem, &agent_uri, &epoch_uri)
        .map_err(|_| "CSR SAN identity mismatch")?;
    let pubkey = csr.public_key().map_err(|_| "CSR key")?;
    if !csr.verify(&pubkey).unwrap_or(false) {
        return Err("CSR signature invalid".into());
    }
    let mut b = X509::builder().map_err(|_| "cert builder")?;
    b.set_version(2).map_err(|_| "cert version")?;
    b.set_subject_name(csr.subject_name())
        .map_err(|_| "cert subject")?;
    b.set_issuer_name(ca.subject_name())
        .map_err(|_| "cert issuer")?;
    b.set_pubkey(&pubkey).map_err(|_| "cert key")?;
    let mut serial_bytes = [0u8; 16];
    openssl::rand::rand_bytes(&mut serial_bytes).map_err(|_| "cert serial")?;
    serial_bytes[0] &= 0x7f;
    let serial = openssl::bn::BigNum::from_slice(&serial_bytes).map_err(|_| "cert serial")?;
    let serial = serial.to_asn1_integer().map_err(|_| "cert serial")?;
    b.set_serial_number(&serial).map_err(|_| "cert serial")?;
    let san = X509Extension::new_nid(
        None,
        None,
        Nid::SUBJECT_ALT_NAME,
        &format!("URI:{agent_uri},URI:{epoch_uri}"),
    )
    .map_err(|_| "cert SAN")?;
    let eku = X509Extension::new_nid(None, None, Nid::EXT_KEY_USAGE, "clientAuth")
        .map_err(|_| "cert EKU")?;
    let ku = X509Extension::new_nid(
        None,
        None,
        Nid::KEY_USAGE,
        "digitalSignature,keyEncipherment",
    )
    .map_err(|_| "cert key usage")?;
    b.append_extension(san).map_err(|_| "cert SAN")?;
    b.append_extension(eku).map_err(|_| "cert EKU")?;
    b.append_extension(ku).map_err(|_| "cert key usage")?;
    let before = Asn1Time::days_from_now(0).map_err(|_| "cert time")?;
    let after = Asn1Time::days_from_now(365).map_err(|_| "cert time")?;
    b.set_not_before(&before).map_err(|_| "cert time")?;
    b.set_not_after(&after).map_err(|_| "cert time")?;
    b.sign(key, MessageDigest::sha256())
        .map_err(|_| "cert sign")?;
    let cert = b.build();
    let ca_pem = ca.to_pem().map_err(|_| "CA encode")?;
    let ca_der = ca.to_der().map_err(|_| "CA encode")?;
    let expires = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(365 * 24 * 60 * 60))
        .ok_or("cert expiry")?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "cert expiry")?
        .as_millis() as u64;
    let rotation = expires.saturating_sub(30 * 24 * 60 * 60 * 1000);
    Ok(Response {
        agent_id: req.agent_id,
        agent_epoch: req.agent_epoch,
        client_certificate_chain_pem: cert.to_pem().map_err(|_| "cert encode")?,
        ca_certificate_pem: ca_pem.clone(),
        ca_fingerprint_sha256: hex::encode(Sha256::digest(&ca_der)),
        certificate_expires_at_unix_ms: expires,
        rotation_deadline_unix_ms: rotation,
    })
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let legacy_key = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_CA_KEY")
            .unwrap_or_else(|_| "/etc/o3k/ea/enrollment-ca-key.pem".into()),
    );
    let legacy_cert = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_CA_CERT")
            .unwrap_or_else(|_| "/etc/o3k/ea/enrollment-ca.pem".into()),
    );
    let ca_dir = PathBuf::from(std::env::var("O3K_ENROLLMENT_CA_DIR").unwrap_or_else(|_| {
        legacy_key
            .parent()
            .unwrap_or_else(|| Path::new("/etc/o3k/ea"))
            .join("enrollment-ca")
            .to_string_lossy()
            .into_owned()
    }));
    let (ca_key, ca_cert) =
        ensure_ca(&ca_dir, &legacy_key, &legacy_cert).map_err(std::io::Error::other)?;
    // systemd socket activation uses stdin/stdout for one connection (Accept=yes).
    let mut input = std::io::stdin().lock();
    let result = peer_ok(&input)
        .and_then(|_| bounded(&mut input))
        .and_then(|b| {
            serde_json::from_slice::<Request>(&b).map_err(|_| "invalid request".to_owned())
        })
        .and_then(|r| issue(r, &ca_key, &ca_cert));
    let out = match result {
        Ok(v) => serde_json::to_vec(&v)?,
        Err(e) => serde_json::to_vec(&ErrorResponse { error: e })?,
    };
    std::io::stdout().write_all(&out)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use o3k_compute_agent::{
        IssuedEnrollment, types::EnrollmentIdentity, validate_issued_enrollment,
    };

    fn test_dir(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "o3k-enrollment-ca-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).unwrap();
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[allow(deprecated)]
    fn csr_with_sans(sans: &[&str]) -> Vec<u8> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "agent-test").unwrap();
        let name = name.build();
        let mut request = X509Req::builder().unwrap();
        request.set_subject_name(&name).unwrap();
        request.set_pubkey(&key).unwrap();
        let mut extensions = openssl::stack::Stack::new().unwrap();
        for san in sans {
            extensions
                .push(X509Extension::new_nid(None, None, Nid::SUBJECT_ALT_NAME, san).unwrap())
                .unwrap();
        }
        request.add_extensions(&extensions).unwrap();
        request.sign(&key, MessageDigest::sha256()).unwrap();
        request.build().to_pem().unwrap()
    }

    #[test]
    fn ca_directory_publication_is_complete_idempotent_and_race_safe() {
        let root = test_dir("parallel");
        let ca_dir = root.join("enrollment-ca");
        let legacy_key = root.join("enrollment-ca-key.pem");
        let legacy_cert = root.join("enrollment-ca.pem");
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let ca_dir = ca_dir.clone();
                let legacy_key = legacy_key.clone();
                let legacy_cert = legacy_cert.clone();
                std::thread::spawn(move || {
                    let (key, cert) = ensure_ca(&ca_dir, &legacy_key, &legacy_cert).unwrap();
                    (key.public_key_to_der().unwrap(), cert.to_der().unwrap())
                })
            })
            .collect();
        let published: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(published.iter().all(|value| value == &published[0]));
        assert_eq!(
            load_ca(&ca_dir).unwrap().unwrap().1.to_der().unwrap(),
            published[0].1
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_ca_pair_is_imported_without_identity_change() {
        let root = test_dir("legacy");
        let ca_dir = root.join("enrollment-ca");
        let legacy_key = root.join("enrollment-ca-key.pem");
        let legacy_cert = root.join("enrollment-ca.pem");
        let (key, cert) = generate_ca().unwrap();
        std::fs::write(&legacy_key, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        std::fs::write(&legacy_cert, cert.to_pem().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&legacy_key, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&legacy_cert, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let (imported_key, imported_cert) = ensure_ca(&ca_dir, &legacy_key, &legacy_cert).unwrap();
        assert_eq!(
            key.public_key_to_der().unwrap(),
            imported_key.public_key_to_der().unwrap()
        );
        assert_eq!(cert.to_der().unwrap(), imported_cert.to_der().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn orphaned_incomplete_temporary_ca_does_not_poison_initialization() {
        let root = test_dir("orphan");
        std::fs::create_dir_all(&root).unwrap();
        let orphan = root.join(".enrollment-ca-interrupted");
        std::fs::create_dir(&orphan).unwrap();
        std::fs::write(orphan.join("key.pem"), b"interrupted").unwrap();
        let ca_dir = root.join("enrollment-ca");
        let (key, cert) = ensure_ca(
            &ca_dir,
            &root.join("legacy-key.pem"),
            &root.join("legacy-cert.pem"),
        )
        .unwrap();
        assert!(cert.verify(&key).unwrap());
        assert_eq!(
            load_ca(&ca_dir).unwrap().unwrap().1.to_der().unwrap(),
            cert.to_der().unwrap()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn incomplete_published_ca_fails_closed_without_replacing_state() {
        let root = test_dir("partial");
        let ca_dir = root.join("enrollment-ca");
        std::fs::create_dir_all(&ca_dir).unwrap();
        std::fs::write(ca_dir.join("key.pem"), b"partial").unwrap();
        let result = ensure_ca(
            &ca_dir,
            &root.join("legacy-key.pem"),
            &root.join("legacy-cert.pem"),
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(ca_dir.join("key.pem")).unwrap(), b"partial");
        assert!(!ca_dir.join("cert.pem").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[allow(deprecated)]
    #[test]
    fn issued_certificate_passes_agent_validator() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ca_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test CA").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&ca_key).unwrap();
        builder
            .append_extension(
                X509Extension::new_nid(None, None, Nid::BASIC_CONSTRAINTS, "critical,CA:TRUE")
                    .unwrap(),
            )
            .unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca = builder.build();
        let identity = EnrollmentIdentity::generate("agent-test", "epoch-test").unwrap();
        let response = issue(
            Request {
                grant_id: "g".into(),
                token: vec![1],
                agent_id: identity.agent_id().into(),
                agent_epoch: identity.agent_epoch().into(),
                csr_pem: identity.csr_pem().to_vec(),
            },
            &ca_key,
            &ca,
        )
        .unwrap();
        let issued = IssuedEnrollment {
            agent_id: response.agent_id,
            agent_epoch: response.agent_epoch,
            client_certificate_chain_pem: response.client_certificate_chain_pem,
            ca_certificate_pem: response.ca_certificate_pem,
            ca_fingerprint_sha256: response.ca_fingerprint_sha256,
            certificate_expires_at_unix_ms: response.certificate_expires_at_unix_ms,
            rotation_deadline_unix_ms: response.rotation_deadline_unix_ms,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        validate_issued_enrollment(&issued, now).unwrap();
    }

    #[test]
    fn enrollment_components_reject_extension_injection() {
        assert!(safe_component("agent-01.example"));
        assert!(!safe_component("agent,URI:DNS:evil"));
        assert!(!safe_component("epoch\nURI:DNS:evil"));
    }

    #[test]
    fn csr_san_validation_rejects_extra_names_and_identity_mismatch() {
        let agent_uri = "urn:o3k:compute:agent:agent-test";
        let epoch_uri = "urn:o3k:compute:epoch:epoch-test";
        let valid = csr_with_sans(&[&format!("URI:{agent_uri},URI:{epoch_uri}")]);
        assert!(validate_csr_uri_sans(&valid, agent_uri, epoch_uri).is_ok());

        let extra_uri = csr_with_sans(&[&format!(
            "URI:{agent_uri},URI:{epoch_uri},URI:urn:o3k:compute:agent:other"
        )]);
        assert!(validate_csr_uri_sans(&extra_uri, agent_uri, epoch_uri).is_err());

        let non_uri =
            csr_with_sans(&[&format!("URI:{agent_uri},URI:{epoch_uri},DNS:evil.example")]);
        assert!(validate_csr_uri_sans(&non_uri, agent_uri, epoch_uri).is_err());
        assert!(validate_csr_uri_sans(&valid, agent_uri, "urn:o3k:compute:epoch:other").is_err());
    }

    #[test]
    fn csr_san_validation_rejects_duplicate_san_extensions() {
        let agent_uri = "urn:o3k:compute:agent:agent-test";
        let epoch_uri = "urn:o3k:compute:epoch:epoch-test";
        let duplicate = csr_with_sans(&[&format!("URI:{agent_uri}"), &format!("URI:{epoch_uri}")]);
        assert!(validate_csr_uri_sans(&duplicate, agent_uri, epoch_uri).is_err());
    }
}
