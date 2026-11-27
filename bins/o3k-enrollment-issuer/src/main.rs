use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509, X509NameBuilder, X509Req},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
};

const MAX: usize = 1024 * 1024;

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
    error: &'static str,
}

fn bounded(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
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
fn peer_ok(stream: &UnixStream) -> Result<(), String> {
    let uid: u32 = std::env::var("O3K_ENROLLMENT_SOCKET_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| nix_uid());
    let peer = rustix::net::sockopt::get_socket_peercred(stream)
        .map_err(|_| "peer credentials unavailable".to_owned())?;
    if peer.uid.as_raw() != uid {
        return Err("unauthorized peer".to_owned());
    }
    Ok(())
}
fn nix_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
fn ensure_ca(key_path: &Path, cert_path: &Path) -> Result<(PKey<Private>, X509), String> {
    if key_path.exists() || cert_path.exists() {
        if !key_path.is_file() || !cert_path.is_file() {
            return Err("issuer CA paths are unsafe".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let km = std::fs::metadata(key_path).map_err(|_| "CA key metadata")?;
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
    let before = Asn1Time::days_from_now(0).map_err(|_| "CA time")?;
    let after = Asn1Time::days_from_now(3650).map_err(|_| "CA time")?;
    b.set_not_before(&before).map_err(|_| "CA time")?;
    b.set_not_after(&after).map_err(|_| "CA time")?;
    b.sign(&key, MessageDigest::sha256())
        .map_err(|_| "CA sign")?;
    let cert = b.build();
    let parent = key_path.parent().ok_or("CA path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|_| "CA directory")?;
    std::fs::write(
        key_path,
        key.private_key_to_pem_pkcs8()
            .map_err(|_| "CA key encode")?,
    )
    .map_err(|_| "CA key write")?;
    std::fs::write(cert_path, cert.to_pem().map_err(|_| "CA cert encode")?)
        .map_err(|_| "CA cert write")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| "CA key mode")?;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| "CA cert mode")?;
    }
    Ok((key, cert))
}
fn issue(req: Request, key: &PKey<Private>, ca: &X509) -> Result<Response, String> {
    if req.grant_id.trim().is_empty()
        || req.token.is_empty()
        || req.agent_id.is_empty()
        || req.agent_epoch.is_empty()
    {
        return Err("incomplete request".into());
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
    let ext_der = csr
        .extensions()
        .map_err(|_| "CSR extensions unavailable")?
        .iter()
        .flat_map(|e| e.to_der().unwrap_or_default())
        .collect::<Vec<_>>();
    if !ext_der
        .windows(agent_uri.len())
        .any(|w| w == agent_uri.as_bytes())
        || !ext_der
            .windows(epoch_uri.len())
            .any(|w| w == epoch_uri.as_bytes())
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
    let before = Asn1Time::days_from_now(0).map_err(|_| "cert time")?;
    let after = Asn1Time::days_from_now(365).map_err(|_| "cert time")?;
    b.set_not_before(&before).map_err(|_| "cert time")?;
    b.set_not_after(&after).map_err(|_| "cert time")?;
    b.sign(key, MessageDigest::sha256())
        .map_err(|_| "cert sign")?;
    let cert = b.build();
    let ca_pem = ca.to_pem().map_err(|_| "CA encode")?;
    Ok(Response {
        agent_id: req.agent_id,
        agent_epoch: req.agent_epoch,
        client_certificate_chain_pem: cert.to_pem().map_err(|_| "cert encode")?,
        ca_certificate_pem: ca_pem.clone(),
        ca_fingerprint_sha256: hex::encode(Sha256::digest(&ca_pem)),
        certificate_expires_at_unix_ms: 0,
        rotation_deadline_unix_ms: 0,
    })
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_ISSUER_SOCKET")
            .unwrap_or_else(|_| "/run/o3k/enrollment-issuer.sock".into()),
    );
    let key = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_CA_KEY")
            .unwrap_or_else(|_| "/etc/o3k/ea/enrollment-ca-key.pem".into()),
    );
    let cert = PathBuf::from(
        std::env::var("O3K_ENROLLMENT_CA_CERT")
            .unwrap_or_else(|_| "/etc/o3k/ea/enrollment-ca.pem".into()),
    );
    let (ca_key, ca_cert) = ensure_ca(&key, &cert).map_err(std::io::Error::other)?;
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    std::fs::create_dir_all(socket.parent().ok_or("socket parent")?)?;
    let listener = UnixListener::bind(&socket)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    }
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let result = peer_ok(&stream)
            .and_then(|_| bounded(&mut stream))
            .and_then(|b| {
                serde_json::from_slice::<Request>(&b).map_err(|_| "invalid request".into())
            })
            .and_then(|r| issue(r, &ca_key, &ca_cert));
        let out = match result {
            Ok(v) => serde_json::to_vec(&v)?,
            Err(e) => serde_json::to_vec(&ErrorResponse {
                error: Box::leak(e.into_boxed_str()),
            })?,
        };
        let _ = stream.write_all(&out);
    }
    Ok(())
}
