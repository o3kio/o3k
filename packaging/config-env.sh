#!/usr/bin/env bash

o3k_verify_config_ledger() {
  local config_dir="$1"
  python3 - "$config_dir" <<'PY'
from pathlib import Path
import hashlib
import os
import sys

root = Path(sys.argv[1])
ledger = root / ".o3k-config-files"
if not ledger.exists():
    raise SystemExit(0)
if ledger.is_symlink() or not ledger.is_file():
    raise SystemExit(f"refusing invalid configuration ownership ledger: {ledger}")
for line in ledger.read_text().splitlines():
    fields = line.split("\t")
    if len(fields) != 3:
        raise SystemExit(f"refusing malformed configuration ownership ledger: {ledger}")
    marker, relative, digest = fields
    path = Path(relative)
    if (marker != "o3k-config-file-v1" or path.is_absolute()
            or ".." in path.parts or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)):
        raise SystemExit(f"refusing malformed configuration ownership ledger: {ledger}")
    target = root / path
    if target.is_symlink() or not target.is_file():
        raise SystemExit(f"refusing missing configuration file recorded in ledger: {relative}")
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    if actual != digest:
        raise SystemExit(f"refusing to overwrite operator-modified configuration file: {relative}")
PY
}

o3k_upsert_env_setting() {
  local env_file="$1" setting="$2"
  python3 - "$env_file" "$setting" <<'PY'
from pathlib import Path
import os
import stat
import sys
import tempfile

path = Path(sys.argv[1])
setting = sys.argv[2]
if path.is_symlink() or (path.exists() and not path.is_file()):
    raise SystemExit(f"refusing unsafe configuration file: {path}")
if "\n" in setting or "\r" in setting or "=" not in setting:
    raise SystemExit("invalid O3K environment setting")
key = setting.split("=", 1)[0]
if not key or any(not (ch.isascii() and (ch.isalnum() or ch == "_")) for ch in key):
    raise SystemExit("invalid O3K environment setting key")
original = path.read_bytes() if path.exists() else b""
lines = original.splitlines(keepends=True)
matches = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n").startswith(key.encode() + b"=")]
if len(matches) > 1:
    raise SystemExit(f"duplicate O3K environment setting: {key}")
new_line = setting.encode()
if matches:
    index = matches[0]
    existing = lines[index]
    ending = b"\r\n" if existing.endswith(b"\r\n") else b"\n" if existing.endswith(b"\n") else b""
    if existing.rstrip(b"\r\n") == new_line:
        raise SystemExit(0)
    lines[index] = new_line + ending
else:
    if lines and not lines[-1].endswith((b"\n", b"\r")):
        lines[-1] += b"\n"
    lines.append(new_line + b"\n")
updated = b"".join(lines)
mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write(updated)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY
}
