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

struct LockGuard(PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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
fn ensure_ca(key_path: &Path, cert_path: &Path) -> Result<(PKey<Private>, X509), String> {
    let key_meta = std::fs::symlink_metadata(key_path).ok();
    let cert_meta = std::fs::symlink_metadata(cert_path).ok();
    if key_meta.is_some() || cert_meta.is_some() {
        if key_meta.as_ref().is_some_and(|m| !m.file_type().is_file())
            || cert_meta.as_ref().is_some_and(|m| !m.file_type().is_file())
            || key_meta.is_none()
            || cert_meta.is_none()
        {
            return Err("issuer CA paths are unsafe".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let km = key_meta.as_ref().ok_or("CA key metadata")?;
            if km.uid() != 0 || (km.mode() & 0o077) != 0 {
                return Err("CA key ownership or mode is unsafe".into());
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
        return Ok((key, cert));
    }
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
    let parent = key_path.parent().ok_or("CA path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|_| "CA directory")?;
    let lock_path = parent.join("enrollment-ca.lock");
    let _lock = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(file) => file,
        Err(_) => return Err("concurrent CA initialization".into()),
    };
    let _guard = LockGuard(lock_path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let dm = std::fs::symlink_metadata(parent).map_err(|_| "CA directory metadata")?;
        if !dm.file_type().is_dir() || dm.uid() != 0 || (dm.mode() & 0o022) != 0 {
            return Err("CA directory ownership or mode is unsafe".into());
        }
        let key_bytes = key
            .private_key_to_pem_pkcs8()
            .map_err(|_| "CA key encode")?;
        let cert_bytes = cert.to_pem().map_err(|_| "CA cert encode")?;
        let mut k = std::fs::OpenOptions::new();
        k.write(true).create_new(true).mode(0o600);
        use std::io::Write as _;
        k.open(key_path)
            .map_err(|_| "CA key create")?
            .write_all(&key_bytes)
            .map_err(|_| "CA key write")?;
        let mut c = std::fs::OpenOptions::new();
        c.write(true).create_new(true).mode(0o644);
        let mut cert_file = match c.open(cert_path) {
            Ok(file) => file,
            Err(_) => {
                let _ = std::fs::remove_file(key_path);
                return Err("CA cert create".into());
            }
        };
        if cert_file.write_all(&cert_bytes).is_err() {
            let _ = std::fs::remove_file(key_path);
            let _ = std::fs::remove_file(cert_path);
            return Err("CA cert write".into());
        }
    }
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
    let extensions = csr.extensions().map_err(|_| "CSR extensions unavailable")?;
    let mut uris = Vec::new();
    let mut san_extensions = 0;
    for extension in extensions.iter() {
        let encoded = extension.to_der().map_err(|_| "invalid CSR extension")?;
        if encoded
            .windows(5)
            .any(|w| w == [0x06, 0x03, 0x55, 0x1d, 0x11])
        {
            san_extensions += 1;
            if san_extensions > 1 {
                return Err("duplicate CSR SAN extension".into());
            }
            let marker = [0x06, 0x03, 0x55, 0x1d, 0x11];
            let oid_end = encoded
                .windows(marker.len())
                .position(|w| w == marker)
                .ok_or("invalid CSR SAN")?
                + marker.len();
            let octet = encoded[oid_end..]
                .iter()
                .position(|b| *b == 0x04)
                .ok_or("invalid CSR SAN")?
                + oid_end;
            let (len, used) = der_len(&encoded[octet + 1..])?;
            let start = octet + 1 + used;
            if start + len > encoded.len() {
                return Err("invalid CSR SAN".into());
            }
            uris = parse_san_uris(&encoded[start..start + len])?;
        }
    }
    if san_extensions != 1 {
        return Err("CSR SAN extension missing".into());
    }
    if uris.len() != 2
        || !uris.iter().any(|u| u == &agent_uri)
        || !uris.iter().any(|u| u == &epoch_uri)
    {
        return Err("CSR SAN identity mismatch".into());
    }
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

fn parse_san_uris(mut der: &[u8]) -> Result<Vec<String>, String> {
    if der.first().copied() != Some(0x30) {
        return Err("invalid CSR SAN".into());
    }
    let (len, used) = der_len(&der[1..])?;
    der = &der[1 + used..];
    if der.len() != len {
        return Err("invalid CSR SAN".into());
    }
    let mut result = Vec::new();
    while !der.is_empty() {
        if der[0] != 0x86 {
            return Err("CSR SAN contains non-URI name".into());
        }
        let (len, used) = der_len(&der[1..])?;
        let start = 1 + used;
        if start + len > der.len() {
            return Err("invalid CSR SAN".into());
        }
        result.push(
            String::from_utf8(der[start..start + len].to_vec()).map_err(|_| "invalid CSR SAN")?,
        );
        der = &der[start + len..];
    }
    Ok(result)
}

fn der_len(bytes: &[u8]) -> Result<(usize, usize), String> {
    let first = *bytes.first().ok_or("invalid CSR SAN")?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || bytes.len() < count + 1 {
        return Err("invalid CSR SAN".into());
    }
    let mut value = 0usize;
    for byte in &bytes[1..=count] {
        value = value
            .checked_mul(256)
            .and_then(|v| v.checked_add(*byte as usize))
            .ok_or("invalid CSR SAN")?;
    }
    Ok((value, count + 1))
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_CA_KEY")
            .unwrap_or_else(|_| "/etc/o3k/ea/enrollment-ca-key.pem".into()),
    );
    let cert = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_CA_CERT")
            .unwrap_or_else(|_| "/etc/o3k/ea/enrollment-ca.pem".into()),
    );
    let (ca_key, ca_cert) = ensure_ca(&key, &cert).map_err(std::io::Error::other)?;
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
mod tests {
    use super::*;
    use o3k_compute_agent::{
        IssuedEnrollment, types::EnrollmentIdentity, validate_issued_enrollment,
    };

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
}
