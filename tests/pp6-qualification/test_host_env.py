import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("host-env.py")
SPEC = importlib.util.spec_from_file_location("pp6_host_env", MODULE_PATH)
HOST_ENV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST_ENV)


class HostEnvironmentSafetyTests(unittest.TestCase):
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
            guest_dir = private / "debian12"
            guest_dir.mkdir(parents=True)
            identities = {}
            for filename in ("base.qcow2", "root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso"):
                disk_path = guest_dir / filename
                disk_path.write_bytes(filename.encode())
                info = disk_path.lstat()
                identities[filename] = [info.st_dev, info.st_ino]
            guest = {"domain": "o3k-pp6-run123-debian12", "uuid": "guest-uuid",
                     "network": "o3k-pp6-run123", "mac": "52:54:00:00:00:01", "files": identities}
            disks = (''.join(f'<disk><target dev="{dev}"/><source file="{guest_dir / disk}"/></disk>'
                             for dev, disk in (("vda", "root.qcow2"), ("vdb", "state.qcow2"),
                                               ("vdc", "journal.qcow2")))
                     + f'<disk device="cdrom"><target dev="sda"/><source file="{guest_dir / "seed.iso"}"/></disk>')
            xml = (f'<domain><name>{guest["domain"]}</name><uuid>guest-uuid</uuid><devices>{disks}'
                   '<interface><mac address="52:54:00:00:00:01"/>'
                   '<source network="o3k-pp6-run123"/></interface></devices></domain>')
            self.assertEqual(HOST_ENV.domain_identity(xml, "debian12", guest, private), "guest-uuid")
            foreign = xml.replace(str(guest_dir / "state.qcow2"), "/var/lib/foreign.qcow2")
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(foreign, "debian12", guest, private)
            old_state = guest_dir / "state.qcow2"
            replacement = guest_dir / "replacement.tmp"
            replacement.write_bytes(b"substituted inode")
            replacement.replace(old_state)
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(xml, "debian12", guest, private)
            wrong_network = xml.replace("o3k-pp6-run123", "default")
            with self.assertRaises(RuntimeError):
                HOST_ENV.domain_identity(wrong_network, "debian12", guest, private)

    def test_network_identity_rejects_forwarding_or_identity_change(self):
        xml = ("<network><name>o3k-pp6-run123</name><uuid>net-uuid</uuid>"
               "<forward mode='none'/><bridge name='p6123456'/></network>")
        HOST_ENV.network_identity(xml, "o3k-pp6-run123", "net-uuid", "p6123456")
        with self.assertRaises(RuntimeError):
            HOST_ENV.network_identity(xml.replace("none", "nat"), "o3k-pp6-run123", "net-uuid", "p6123456")


if __name__ == "__main__":
    unittest.main()
