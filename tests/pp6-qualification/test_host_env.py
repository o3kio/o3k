import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("host-env.py")
SPEC = importlib.util.spec_from_file_location("pp6_host_env", MODULE_PATH)
HOST_ENV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST_ENV)


class HostEnvironmentSafetyTests(unittest.TestCase):
    def test_cloud_config_is_parseable_and_preserves_pinned_identities(self):
        import json
        private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n"
        raw = HOST_ENV.guest_user_data("guest", private_key, "ssh-ed25519 host-key", "ssh-ed25519 user-key",
                                     "O3KSTATE0", "O3KJOURNAL0")
        self.assertTrue(raw.startswith("#cloud-config\n"))
        config = json.loads(raw.split("\n", 1)[1])
        self.assertEqual(config["ssh_keys"]["ed25519_private"], private_key)
        self.assertEqual(config["ssh_keys"]["ed25519_public"], "ssh-ed25519 host-key")
        self.assertEqual(config["users"][1]["ssh_authorized_keys"], ["ssh-ed25519 user-key"])
        self.assertEqual(config["users"][1]["sudo"], ["ALL=(ALL) NOPASSWD:ALL"])
        self.assertIs(config["ssh_pwauth"], False)

    def test_static_guest_addresses_use_disjoint_reserved_slots(self):
        self.assertEqual(HOST_ENV.guest_static_ip(145, 0), "192.168.145.20")
        self.assertEqual(HOST_ENV.guest_static_ip(145, 1), "192.168.145.21")
        for subnet, ordinal in ((99, 0), (200, 0), (145, 2)):
            with self.subTest(subnet=subnet, ordinal=ordinal), self.assertRaises(ValueError):
                HOST_ENV.guest_static_ip(subnet, ordinal)

    def test_network_config_assigns_static_address_by_mac_without_dhcp_or_gateway(self):
        import json
        raw = HOST_ENV.guest_network_config("52:54:00:64:62:e5", "192.168.145.20")
        config = json.loads(raw)
        self.assertEqual(config["version"], 1)
        interface = config["config"][0]
        self.assertEqual(interface["type"], "physical")
        self.assertEqual(interface["mac_address"], "52:54:00:64:62:e5")
        self.assertEqual(interface["subnets"], [{"type": "static", "address": "192.168.145.20/24"}])
        self.assertNotIn("gateway", interface["subnets"][0])
        self.assertNotIn("routes", interface["subnets"][0])
        with self.assertRaises(ValueError):
            HOST_ENV.guest_network_config("bad-mac", "192.168.145.20")
        with self.assertRaises(ValueError):
            HOST_ENV.guest_network_config("52:54:00:64:62:e5", "192.168.145.1")

    def test_wait_ssh_uses_static_ip_and_pins_host_key_without_dhcp(self):
        ip = "192.168.145.20"
        with tempfile.TemporaryDirectory() as directory:
            known = Path(directory) / "known_hosts"
            key = Path(directory) / "id_ed25519"
            with patch.object(HOST_ENV, "ssh", return_value="Linux guest") as ssh_call, \
                    patch.object(HOST_ENV.time, "monotonic", side_effect=(0, 1)):
                self.assertEqual(HOST_ENV.wait_ssh(ip, key, known, "ssh-ed25519 host-key", 30), ip)
            ssh_call.assert_called_once_with(ip, key, known, "systemctl --version | head -1")
            self.assertEqual(known.read_text(encoding="utf-8"), f"{ip} ssh-ed25519 host-key\n")

    def test_run_id_is_bounded_and_canonical(self):
        self.assertEqual(HOST_ENV.run_path("pp6-20261101-run01").name, "pp6-20261101-run01")
        for value in ("../outside", "Bad-ID", "short", "x" * 41):
            with self.subTest(value=value), self.assertRaises(ValueError):
                HOST_ENV.run_path(value)

    def test_image_digest_and_symlink_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "base.qcow2"
            image.write_bytes(b"disposable test image")
            expected = hashlib.sha256(image.read_bytes()).hexdigest()
            resolved, actual = HOST_ENV.verified_image(str(image), expected, "test")
            self.assertEqual(resolved, image.resolve())
            self.assertEqual(actual, expected)
            with self.assertRaises(ValueError):
                HOST_ENV.verified_image(str(image), "0" * 64, "test")
            link = Path(directory) / "image-link.qcow2"
            link.symlink_to(image)
            with self.assertRaises(ValueError):
                HOST_ENV.verified_image(str(link), expected, "test")

    def test_run_path_rejects_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            alias = Path(directory) / "alias"
            root.mkdir()
            alias.symlink_to(root, target_is_directory=True)
            original = HOST_ENV.ROOT
            try:
                HOST_ENV.ROOT = alias
                with self.assertRaises(ValueError):
                    HOST_ENV.run_path("pp6-20261101-run01")
            finally:
                HOST_ENV.ROOT = original

    def test_domain_identity_accepts_only_run_owned_disks_and_network(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            guest_dir = private / "debian13"
            guest_dir.mkdir(parents=True)
            identities = {}
            for filename in ("base.qcow2", "root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso"):
                disk_path = guest_dir / filename
                disk_path.write_bytes(filename.encode())
                info = disk_path.lstat()
                identities[filename] = [info.st_dev, info.st_ino]
            guest = {"domain": "o3k-pp6-run123-debian13", "uuid": "guest-uuid",
                     "network": "o3k-pp6-run123", "mac": "52:54:00:00:00:01", "files": identities}
            disks = (''.join(f'<disk><target dev="{dev}"/><source file="{guest_dir / disk}"/></disk>'
                             for dev, disk in (("vda", "root.qcow2"), ("vdb", "state.qcow2"),
                                               ("vdc", "journal.qcow2")))
                     + f'<disk device="cdrom"><target dev="sda"/><source file="{guest_dir / "seed.iso"}"/></disk>')
            xml = (f'<domain><name>{guest["domain"]}</name><uuid>guest-uuid</uuid><devices>{disks}'
                   '<interface><mac address="52:54:00:00:00:01"/>'
                   '<source network="o3k-pp6-run123"/></interface></devices></domain>')
            self.assertEqual(HOST_ENV.domain_identity(xml, "debian13", guest, private), "guest-uuid")
            wrong_root_target = xml.replace('dev="vda"', 'dev="vdd"')
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(wrong_root_target, "debian13", guest, private)
            foreign = xml.replace(str(guest_dir / "state.qcow2"), "/var/lib/foreign.qcow2")
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(foreign, "debian13", guest, private)
            old_state = guest_dir / "state.qcow2"
            replacement = guest_dir / "replacement.tmp"
            replacement.write_bytes(b"substituted inode")
            replacement.replace(old_state)
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(xml, "debian13", guest, private)
            wrong_network = xml.replace("o3k-pp6-run123", "default")
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(wrong_network, "debian13", guest, private)

    def test_network_identity_rejects_forwarding_or_identity_change(self):
        xml = ("<network><name>o3k-pp6-run123</name><uuid>net-uuid</uuid>"
               "<forward mode='none'/><bridge name='p6123456'/>"
               "<ip address='192.168.145.1' netmask='255.255.255.0'/></network>")
        HOST_ENV.network_identity(xml, "o3k-pp6-run123", "net-uuid", "p6123456")
        with self.assertRaises(RuntimeError):
            HOST_ENV.network_identity(xml.replace("none", "nat"), "o3k-pp6-run123", "net-uuid", "p6123456")
        with self.assertRaises(RuntimeError):
            HOST_ENV.network_identity(xml.replace("'/></network>", "'><dhcp/></ip></network>"),
                                      "o3k-pp6-run123", "net-uuid", "p6123456")

    def test_installed_release_capture_requires_exact_manifest_and_binary_inventory(self):
        record = {
            "release_manifest": {
                "source_commit": "a" * 40,
                "version": "0.4.0-rc.27",
                "profile": "libvirt",
                "release_artifact_sha256": "b" * 64,
            },
            "release_manifest_sha256": "c" * 64,
            "release_manifest_inode": [8, 9],
            "executables": {
                name: {"path": f"/usr/local/bin/{name}", "sha256": "d" * 64,
                       "uid": 0, "gid": 0, "mode": 0o755, "device": 8, "inode": 10}
                for name in ("o3kd", "o3k", "o3k-compute", "o3k-network")
            },
        }
        HOST_ENV.validate_installation_record(record, "a" * 40, "0.4.0-rc.27", "b" * 64)
        with self.assertRaises(RuntimeError):
            HOST_ENV.validate_installation_record(record, "e" * 40, "0.4.0-rc.27", "b" * 64)
        altered = {**record, "executables": dict(record["executables"])}
        altered["executables"].pop("o3k-network")
        with self.assertRaises(RuntimeError):
            HOST_ENV.validate_installation_record(altered, "a" * 40, "0.4.0-rc.27", "b" * 64)

    def test_destroy_identity_check_rejects_unknown_and_replaced_files(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            # Legacy Debian 12 runs are cleanup-only and must remain safe to destroy.
            guest_dir = private / "debian12"
            (guest_dir / "seed").mkdir(parents=True)
            guest_dir.chmod(0o711)
            (guest_dir / "seed").chmod(0o700)
            network_xml = private / "network.xml"
            network_xml.write_text("<network/>", encoding="utf-8")
            recorded_file = guest_dir / "root.qcow2"
            recorded_file.write_bytes(b"run-owned disk")
            network_config = guest_dir / "seed" / "network-config"
            network_config.write_text('{"version": 2}', encoding="utf-8")
            network_info = network_xml.lstat()
            disk_info = recorded_file.lstat()
            config_info = network_config.lstat()
            marker = {
                "network_xml_inode": [network_info.st_dev, network_info.st_ino],
                "guests": {"debian12": {"files": {
                    "root.qcow2": [disk_info.st_dev, disk_info.st_ino],
                    "seed/network-config": [config_info.st_dev, config_info.st_ino],
                }}},
            }
            HOST_ENV.verify_recorded_files(private, marker)
            with self.assertRaises(RuntimeError):
                HOST_ENV.verify_recorded_files(private, {**marker, "guests": {}})
            foreign_file = guest_dir / "foreign-state.db"
            foreign_file.write_bytes(b"preserve this")
            with self.assertRaises(RuntimeError):
                HOST_ENV.verify_recorded_files(private, marker)
            foreign_file.unlink()
            replacement = guest_dir / "replacement.tmp"
            replacement.write_bytes(b"replacement")
            replacement.replace(recorded_file)
            with self.assertRaises(RuntimeError):
                HOST_ENV.verify_recorded_files(private, marker)


if __name__ == "__main__":
    unittest.main()
