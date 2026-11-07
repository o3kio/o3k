#!/usr/bin/env python3
"""Exercise the authenticated rc.27 installer ownership guard in temp paths."""
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


INSTALLER_SHA256 = "16d0dc98105c353bfd6469b47fc4ce58072a72c76b3eaacad7bc93f5c33567ca"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_evidence(directory, name, bundle, result, expected_code, expected_message):
    stdout_path, stderr_path = directory / f"{name}.stdout.txt", directory / f"{name}.stderr.txt"
    stdout_path.write_text(result.stdout, encoding="utf-8")
    stderr_path.write_text(result.stderr, encoding="utf-8")
    stdout_path.chmod(0o600)
    stderr_path.chmod(0o600)
    matched = result.returncode == expected_code and expected_message in result.stdout + result.stderr
    record = {
        "case": name, "captured_at": datetime.now(timezone.utc).isoformat(),
        "installer_sha256": digest(bundle / "packaging/install.sh"),
        "binary_sha256": {key: digest(bundle / f"bin/{key}") for key in ("o3kd", "o3k")},
        "expected_exit_code": expected_code, "exit_code": result.returncode,
        "expected_predicate": expected_message,
        "predicate_result": "PASS" if matched else "FAIL",
        "stdout_path": stdout_path.name, "stdout_sha256": digest(stdout_path),
        "stderr_path": stderr_path.name, "stderr_sha256": digest(stderr_path),
    }
    record_path = directory / f"{name}.result.json"
    record_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    record_path.chmod(0o600)
    if not matched:
        raise AssertionError(f"{name}: expected rc={expected_code} and predicate {expected_message!r}; got rc={result.returncode}")
    return record


def run_case(bundle, root, evidence, name, prepare, expected_code, expected_message):
    case = root / name
    case.mkdir()
    paths = {key: case / key for key in ("prefix", "data", "config", "log")}
    prepare(paths["data"])
    command = [
        "bash", str(bundle / "packaging/install.sh"),
        "--prefix", str(paths["prefix"]), "--data-dir", str(paths["data"]),
        "--config-dir", str(paths["config"]), "--log-dir", str(paths["log"]),
        "--binary", str(bundle / "bin/o3kd"), "--o3k-binary", str(bundle / "bin/o3k"),
        "--profile", "fake", "--noninteractive",
    ]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    return write_evidence(evidence, name, bundle, result, expected_code, expected_message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-root", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle = args.release_root.resolve(strict=True)
    installer = bundle / "packaging/install.sh"
    if installer.is_symlink() or digest(installer) != INSTALLER_SHA256:
        raise SystemExit("release installer digest is not the authenticated rc.27 installer")
    for required in (bundle / "bin/o3kd", bundle / "bin/o3k", bundle / "manifest.json",
                     bundle / "SHA256SUMS"):
        if not required.is_file() or required.is_symlink():
            raise SystemExit(f"incomplete release bundle fixture: {required}")
    evidence = args.evidence_dir
    if evidence.exists() or evidence.is_symlink():
        raise SystemExit(f"evidence directory must not already exist: {evidence}")
    evidence.mkdir(parents=True, mode=0o700)
    os.chmod(evidence, 0o700)

    def clean_disposable(path):
        path.mkdir()
        (path / ".o3k-owned").write_text("o3k-owned-v1 path=" + str(path) + "\n")
        (path / "state").mkdir()
        (path / "journal").mkdir()

    def foreign_state(path):
        path.mkdir()
        (path / "operator.db").write_text("foreign state must remain untouched\n")

    def invalid_marker(path):
        path.mkdir()
        (path / ".o3k-owned").write_text("o3k-owned-v9 path=wrong\n")

    def symlink(path):
        target = path.parent / "foreign-directory"
        target.mkdir()
        path.symlink_to(target, target_is_directory=True)

    with tempfile.TemporaryDirectory(prefix="pp6-rc27-guard-") as temporary:
        root = Path(temporary)
        records = [run_case(bundle, root, evidence, "clean-disposable", clean_disposable, 0,
                            "backup trust template:"),
        run_case(bundle, root, evidence, "foreign-state", foreign_state, 2,
                 "refusing to claim populated unowned directory"),
        run_case(bundle, root, evidence, "invalid-marker", invalid_marker, 2,
                 "refusing unrecognized ownership marker"),
        run_case(bundle, root, evidence, "symlink", symlink, 2,
                 "refusing symlink installation path")]
    summary = evidence / "summary.json"
    summary.write_text(json.dumps({"format": "pp6-rc27-installer-guard-v1", "results": records},
                                  sort_keys=True, indent=2) + "\n", encoding="utf-8")
    summary.chmod(0o600)
    print("PASS: immutable rc.27 installer guard accepted only the explicit clean disposable marker fixture")
    print("PASS: foreign data, invalid ownership marker and symlink were rejected")
    print(f"Evidence: {evidence}")


if __name__ == "__main__":
    main()
