#!/usr/bin/env python3
"""Focused read-only PostgreSQL inventory regressions."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "real_host_owned_inventory", ROOT / "scripts/real-host-owned-inventory.py"
)
assert SPEC is not None and SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INVENTORY
SPEC.loader.exec_module(INVENTORY)


class PostgresInventoryTests(unittest.TestCase):
    def test_collects_read_only_csv_rows_without_putting_credentials_in_argv(self) -> None:
        outputs: list[str] = []

        def command(args: tuple[str, ...], *, extra_env=None, **_kwargs):
            if args == ("psql", "--version"):
                return "psql (PostgreSQL) 16.0"
            self.assertNotIn("postgresql://user:sentinel-password@", " ".join(args))
            self.assertEqual(extra_env["PGHOST"], "127.0.0.1")
            self.assertEqual(extra_env["PGDATABASE"], "o3k_pp5_s5_123")
            self.assertEqual(extra_env["PGPASSWORD"], "sentinel-password")
            self.assertIn("default_transaction_read_only=on", extra_env["PGOPTIONS"])
            sql = args[-1]
            if sql.startswith("SELECT COUNT(*)"):
                return "0\n"
            outputs.append(sql)
            if sql.startswith("SELECT id, resource_id, state, kind FROM operations"):
                return 'op-1,resource-1,running,create\n'
            if sql.startswith("SELECT c.command_id"):
                return 'cmd-1,resource-1,running,running\n'
            if sql.startswith("SELECT id, kind, observed_state FROM resources"):
                return 'resource-1,compute_instance,ACTIVE\n'
            if sql.startswith("SELECT id, network_id, status, binding_host, binding_state"):
                return 'port-1,network-1,ACTIVE,agent-a,bound\n'
            if sql.startswith("SELECT id, provider_id, consumer_id FROM placement_allocations"):
                return 'allocation-1,provider-1,resource-1\n'
            if sql.startswith("SELECT id, name, status FROM network_networks"):
                return 'network-1,private,ACTIVE\n'
            if sql.startswith("SELECT resource_id, provider_name, provider_resource_id FROM provider_refs"):
                return 'resource-1,libvirt,o3k-resource-1\n'
            if sql.startswith("SELECT id, desired_state FROM resources"):
                return 'resource-1,"{""network_attachments"":[{""port_id"":""port-1""}]}"\n'
            return ""

        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {
                    "O3K_DATABASE_BACKEND": "postgres",
                    "O3K_DATABASE_URL": "postgresql://user:sentinel-password@127.0.0.1:5432/o3k_pp5_s5_123",
                },
                clear=False,
            ), mock.patch.object(INVENTORY, "command", side_effect=command):
                result = INVENTORY.collect_durable(pathlib.Path(temporary))

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["operations"]["entries"][0]["classification"], "active_owned")
        self.assertEqual(result["port_resources"], {"port-1": "resource-1"})
        self.assertEqual(result["network_ports"]["entries"][0]["classification"], "active_owned")
        self.assertGreaterEqual(len(outputs), 10)

    def test_invalid_csv_fails_closed(self) -> None:
        def command(args: tuple[str, ...], **_kwargs):
            if args == ("psql", "--version"):
                return "psql (PostgreSQL) 16.0"
            return '"unterminated\n'

        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {
                    "O3K_DATABASE_BACKEND": "postgres",
                    "O3K_DATABASE_URL": "postgresql://user:secret@127.0.0.1/o3k_test",
                },
                clear=False,
            ), mock.patch.object(INVENTORY, "command", side_effect=command):
                result = INVENTORY.collect_durable(pathlib.Path(temporary))

        self.assertIsNone(result)
        self.assertEqual(INVENTORY.LAST_FAILURE_REASON, "durable_database_response_invalid")

    def test_rejects_unapproved_postgres_url_options(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "O3K_DATABASE_BACKEND": "postgres",
                "O3K_DATABASE_URL": "postgresql://user:secret@127.0.0.1/o3k_test?options=-c%20role%3Dsuperuser",
            },
            clear=False,
        ), mock.patch.object(INVENTORY, "command") as command:
            result = INVENTORY.collect_durable(pathlib.Path("/unused"))

        self.assertIsNone(result)
        self.assertEqual(INVENTORY.LAST_FAILURE_REASON, "durable_database_config_invalid")
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
