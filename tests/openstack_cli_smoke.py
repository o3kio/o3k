#!/usr/bin/env python3
"""Fail-closed smoke test for the disposable OpenStack CLI environment."""

from importlib import metadata, resources
import subprocess
import sys


EXPECTED_SDK = "4.22.0"

try:
    from openstack.config import OpenStackConfig  # noqa: F401

    sdk_version = metadata.version("openstacksdk")
    defaults = resources.files("openstack.config").joinpath("defaults.json")
    if sdk_version != EXPECTED_SDK:
        raise RuntimeError(f"openstacksdk version is {sdk_version}, expected {EXPECTED_SDK}")
    if not defaults.is_file():
        raise RuntimeError("openstack.config/defaults.json resource is missing")
    result = subprocess.run([sys.argv[1], "--version"], check=False, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("openstack CLI --version failed")
except Exception as error:
    print(f"OpenStack CLI bootstrap smoke failed: {error}", file=sys.stderr)
    raise SystemExit(1) from error

print(f"OpenStack CLI bootstrap smoke passed (openstacksdk {EXPECTED_SDK})")
