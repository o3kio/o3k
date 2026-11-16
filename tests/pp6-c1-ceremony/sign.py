#!/usr/bin/env python3
"""Qualification-only offline signer for the C1 installation ceremony.

This tool exists so qualification campaigns can execute the complete
prepare -> offline-sign -> install journey (packaging/install.sh
--c1-prepare-only / --c1-policy/--c1-state/--c1-trust) on disposable test
hosts. It is NOT a production signer: it stores throwaway private keys
unencrypted on disk and implements no custody controls. Production
ceremonies follow docs/operator/C1_OFFLINE_SIGNING_CEREMONY.md with
custodian-held keys (SPEC-0050 section 2). This file is never shipped in a
release bundle and must never be pointed at production key material.

Document contract (must match bins/o3k/src/recovery_identity.rs and
bins/o3k/src/recovery_trust.rs exactly):
- canonical form: RFC 8785 JCS; documents must be byte-identical after a
  decode/re-encode round trip (the verifier enforces this);
- signature envelope: {"payload": ..., "envelope": {"algorithm": "Ed25519",
  "signer_key_id": ..., "signature": "<128 lowercase hex>"}} with the
  signature computed over the canonical payload bytes only;
- digest references: sha256 hex over the canonical bytes of the referenced
  signed document (trust bundle digest covers the whole unsigned bundle).
"""

import argparse
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from hashlib import sha256

KEY_NAMES = ("policy", "journal-root", "evidence-root", "journal-signer", "evidence-signer")
DEFAULT_KEY_IDS = {
    "journal-root": "c1qual-journal-root",
    "evidence-root": "c1qual-evidence-root",
    "journal-signer": "c1qual-journal-signer",
    "evidence-signer": "c1qual-evidence-signer",
}
GENESIS_PRIOR_POLICY_DIGEST = "00" * 32


def canonical(obj):
    # RFC 8785 JCS for the document shapes used here: ASCII-only strings,
    # integers, booleans, null, arrays, objects with ASCII keys.
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def digest_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def load_private_key(keys_dir: Path, name: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex((keys_dir / f"{name}.key").read_text().strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign_payload(payload: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    signature = key.sign(canonical(payload))
    return {
        "payload": payload,
        "envelope": {
            "algorithm": "Ed25519",
            "signer_key_id": key_id,
            "signature": signature.hex(),
        },
    }


def self_verify(doc: dict, expected_format: str, expected_key_id: str, public_key: Ed25519PublicKey):
    # Mirror of identity::verify_signed + decode_canonical: canonical
    # round-trip byte equality, envelope binding, payload format, signature.
    data = canonical(doc)
    assert json.loads(data.decode("utf-8")) == doc, "canonical round trip changed the document"
    envelope = doc["envelope"]
    assert envelope["algorithm"] == "Ed25519"
    assert envelope["signer_key_id"] == expected_key_id
    assert doc["payload"]["format"] == expected_format
    public_key.verify(bytes.fromhex(envelope["signature"]), canonical(doc["payload"]))
    return data


def cmd_keygen(args):
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_ids = dict(DEFAULT_KEY_IDS)
    key_ids["policy"] = args.policy_key_id
    summary = {"key_ids": key_ids, "public_keys": {}}
    for name in KEY_NAMES:
        key = Ed25519PrivateKey.generate()
        (out / f"{name}.key").write_text(
            key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex() + "\n"
        )
        (out / f"{name}.key").chmod(0o600)
        summary["public_keys"][name] = public_hex(key)
    (out / "keys.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({
        "warning": "qualification-only throwaway keys; never use for production custody",
        "policy_key_id": key_ids["policy"],
        "policy_public_key": summary["public_keys"]["policy"],
    }, indent=2))


def cmd_sign(args):
    keys_dir = Path(args.keys)
    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = json.loads(Path(args.descriptor).read_text())
    assert descriptor["format"] == "o3k-recovery-provisioning-v1", descriptor
    assert descriptor["unsigned"] is True and descriptor["authentication"] == "none", descriptor

    meta = json.loads((keys_dir / "keys.json").read_text())
    key_ids = meta["key_ids"]
    keys = {name: load_private_key(keys_dir, name) for name in KEY_NAMES}
    policy_key_id = key_ids["policy"]
    assert descriptor["policy_authority"]["key_id"] == policy_key_id, (
        "descriptor authority key id does not match the signing key id"
    )
    assert descriptor["policy_authority"]["ed25519_public_key"] == public_hex(keys["policy"]), (
        "descriptor authority public key does not match the signing key"
    )

    now = args.now if args.now is not None else int(time.time())
    cert_days = args.cert_days
    assert 0 < cert_days <= 90, "certificate validity must be at most 90 days"

    def revocation_document(sequence):
        return {
            "format": "o3k-recovery-revocations-v1",
            "site_id": descriptor["site_id"],
            "profile": descriptor["profile"],
            "sequence": sequence,
            "issued_at": now,
            "next_update": now + 86_400,
            "revoked_serials": [],
            "revoked_key_ids": [],
        }

    def certificate(purpose, key_id, public_key_hex, issuer, serial):
        fmt = {
            "restore_journal": "o3k-journal-authority-v1",
            "recovery_evidence": "o3k-evidence-authority-v1",
        }[purpose]
        return {
            "format": fmt,
            "key_id": key_id,
            "public_key": public_key_hex,
            "purpose": purpose,
            "site_id": descriptor["site_id"],
            "installation_id": descriptor["installation_id"],
            "profile": descriptor["profile"],
            "backend": descriptor["backend"],
            "serial": serial,
            "not_before": now - 3_600,
            "not_after": now + cert_days * 86_400,
            "issuer": issuer,
        }

    journal_cert = sign_payload(
        certificate("restore_journal", key_ids["journal-signer"], public_hex(keys["journal-signer"]),
                    key_ids["journal-root"], "serial-journal-1"),
        keys["journal-root"], key_ids["journal-root"])
    evidence_cert = sign_payload(
        certificate("recovery_evidence", key_ids["evidence-signer"], public_hex(keys["evidence-signer"]),
                    key_ids["evidence-root"], "serial-evidence-1"),
        keys["evidence-root"], key_ids["evidence-root"])
    journal_revocations = sign_payload(revocation_document(1), keys["journal-root"], key_ids["journal-root"])
    evidence_revocations = sign_payload(revocation_document(1), keys["evidence-root"], key_ids["evidence-root"])

    trust_bundle = {
        "format": "o3k-recovery-trust-v1",
        "site_id": descriptor["site_id"],
        "profile": descriptor["profile"],
        "installation_id": descriptor["installation_id"],
        "backend": descriptor["backend"],
        "journal_root_key_id": key_ids["journal-root"],
        "journal_root_public_key": public_hex(keys["journal-root"]),
        "evidence_root_key_id": key_ids["evidence-root"],
        "evidence_root_public_key": public_hex(keys["evidence-root"]),
        "journal_revocation_sequence": journal_revocations["payload"]["sequence"],
        "journal_revocation_digest": digest_hex(canonical(journal_revocations)),
        "evidence_revocation_sequence": evidence_revocations["payload"]["sequence"],
        "evidence_revocation_digest": digest_hex(canonical(evidence_revocations)),
        "journal_certificate": journal_cert,
        "evidence_certificate": evidence_cert,
        "journal_revocations": journal_revocations,
        "evidence_revocations": evidence_revocations,
    }
    trust_bytes = canonical(trust_bundle)
    trust_digest = digest_hex(trust_bytes)

    policy_payload = {
        "format": "o3k-installation-policy-v1",
        "installation_id": descriptor["installation_id"],
        "site_id": descriptor["site_id"],
        "profile": descriptor["profile"],
        "backend": descriptor["backend"],
        "release_identity": descriptor["release_identity"],
        "data_root": descriptor["data_root"],
        "target_device": descriptor["data_root_device"],
        "target_inode": descriptor["data_root_inode"],
        "policy_revision": 1,
        "prior_policy_digest": GENESIS_PRIOR_POLICY_DIGEST,
        "policy_path": descriptor["policy_path"],
        "trust_bundle_path": descriptor["trust_bundle_path"],
        "trust_bundle_digest": trust_digest,
        "recovery_state_root": descriptor["recovery_state_root"],
        "recovery_state_device": descriptor["recovery_state_device"],
        "recovery_state_inode": descriptor["recovery_state_inode"],
        "journal_directory": descriptor["journal_directory"],
        "journal_device": descriptor["journal_device"],
        "journal_inode": descriptor["journal_inode"],
        "journal_trust_root_id": key_ids["journal-root"],
        "journal_trust_root_public_key": public_hex(keys["journal-root"]),
        "evidence_trust_root_id": key_ids["evidence-root"],
        "evidence_trust_root_public_key": public_hex(keys["evidence-root"]),
        "signer_key_id": policy_key_id,
    }
    policy_doc = sign_payload(policy_payload, keys["policy"], policy_key_id)
    policy_bytes = canonical(policy_doc)
    policy_digest = digest_hex(policy_bytes)

    state_payload = {
        "format": "o3k-installation-state-v1",
        "installation_id": descriptor["installation_id"],
        "site_id": descriptor["site_id"],
        "profile": descriptor["profile"],
        "backend": descriptor["backend"],
        "policy_revision": 1,
        "policy_digest": policy_digest,
        "target_device": descriptor["data_root_device"],
        "target_inode": descriptor["data_root_inode"],
        "sequence": 0,
        "prior_record_digest": "",
        "state": "NEVER_RECOVERED",
        "operation_id": None,
        "artifact_sha256": None,
        "recovery_directory_digest": None,
        "trust_bundle_digest": None,
        "terminal_journal_digest": None,
        "evidence_digest": None,
    }
    state_doc = sign_payload(state_payload, keys["policy"], policy_key_id)
    state_bytes = canonical(state_doc)

    # Self-verification against the same rules the installed verifier applies.
    self_verify(policy_doc, "o3k-installation-policy-v1", policy_key_id, keys["policy"].public_key())
    self_verify(state_doc, "o3k-installation-state-v1", policy_key_id, keys["policy"].public_key())
    self_verify(journal_cert, "o3k-journal-authority-v1", key_ids["journal-root"], keys["journal-root"].public_key())
    self_verify(evidence_cert, "o3k-evidence-authority-v1", key_ids["evidence-root"], keys["evidence-root"].public_key())
    self_verify(journal_revocations, "o3k-recovery-revocations-v1", key_ids["journal-root"], keys["journal-root"].public_key())
    self_verify(evidence_revocations, "o3k-recovery-revocations-v1", key_ids["evidence-root"], keys["evidence-root"].public_key())
    assert json.loads(trust_bytes.decode("utf-8")) == trust_bundle

    (out / "policy.json").write_bytes(policy_bytes)
    (out / "state.json").write_bytes(state_bytes)
    (out / "trust.json").write_bytes(trust_bytes)
    print(json.dumps({
        "policy_digest": policy_digest,
        "trust_bundle_digest": trust_digest,
        "policy_path": descriptor["policy_path"],
        "trust_bundle_path": descriptor["trust_bundle_path"],
        "outputs": {name: str(out / name) for name in ("policy.json", "state.json", "trust.json")},
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="generate throwaway qualification key material")
    keygen.add_argument("--out", required=True)
    keygen.add_argument("--policy-key-id", required=True,
                        help="must equal the release build's O3K_C1_INSTALLATION_POLICY_KEY_ID")
    keygen.set_defaults(func=cmd_keygen)
    sign = sub.add_parser("sign", help="sign a provisioning descriptor into policy/state/trust documents")
    sign.add_argument("--descriptor", required=True)
    sign.add_argument("--keys", required=True)
    sign.add_argument("--out", required=True)
    sign.add_argument("--now", type=int, default=None,
                      help="override the issuance time (epoch seconds); defaults to the current time")
    sign.add_argument("--cert-days", type=int, default=80,
                      help="certificate validity in days (must be <= 90)")
    sign.set_defaults(func=cmd_sign)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
