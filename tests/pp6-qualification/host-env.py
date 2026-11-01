#!/usr/bin/env python3
"""Run-owned Debian 12/Ubuntu 24.04 systemd and ext4 qualification guests."""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("O3K_PP6_QUAL_ROOT", "/var/lib/o3k-pp6-qualification"))
GUESTS = ("debian12", "ubuntu2404")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{5,39}$")


def call(argv, check=True):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f"{argv[0]} failed: {(result.stderr or result.stdout).strip()}")
    return result.stdout.strip()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run_path(run_id):
    if not ID_RE.fullmatch(run_id):
        raise ValueError("run ID must be 6-40 lowercase letters, digits, or hyphens")
    path = ROOT / "runs" / run_id
    if path.resolve() != path.absolute():
        raise ValueError("run path contains symlinks")
    return path


def require_host(*, provisioning=False):
    needed = ("virsh", "virt-install", "qemu-img", "genisoimage", "ssh", "ssh-keygen", "ssh-keyscan")
    if not provisioning:
        needed = ("virsh",)
    missing = [x for x in needed if shutil.which(x) is None]
    if os.geteuid() != 0 or (provisioning and not Path("/dev/kvm").exists()) or missing:
        raise RuntimeError("requires root" + (", /dev/kvm" if provisioning else "") +
                           " and tools; missing=" + ",".join(missing))
    if provisioning:
        for name in ("/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"):
            value = Path(name).read_text(encoding="ascii").strip()
            if value != "0":
                raise RuntimeError(f"host forwarding must be disabled ({name}={value})")


def verified_image(path, expected, label):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError(f"{label} image must be a regular file")
    actual = sha(p)
    if not re.fullmatch("[0-9a-f]{64}", expected) or actual != expected:
        raise ValueError(f"{label} image digest mismatch: {actual}")
    return p.resolve(), actual


def domain_identity(xml_text, guest_name, guest, private):
    """Fail closed unless every domain disk and NIC belongs to this run."""
    root = ET.fromstring(xml_text)
    name = root.findtext("name")
    uuid = root.findtext("uuid")
    expected_name = guest["domain"]
    if not uuid or name != expected_name or (guest.get("uuid") and uuid != guest["uuid"]):
        raise RuntimeError(f"domain identity mismatch: {expected_name}")
    disks = {}
    for disk in root.findall("./devices/disk"):
        source = disk.find("source")
        filename = source.get("file") if source is not None else None
        target = disk.find("target")
        role = ("seed.iso" if disk.get("device") == "cdrom" else
                {"vda": "root.qcow2", "vdb": "state.qcow2", "vdc": "journal.qcow2"}.get(
                    target.get("dev") if target is not None else None))
        if not filename or role is None or role in disks:
            raise RuntimeError(f"unexpected disk role: {expected_name}")
        disks[role] = str(Path(filename).resolve())
    guest_dir = (private / guest_name).resolve()
    if ((private / guest_name).is_symlink()
            or set(disks) != {"root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso"}
            or any(Path(disk).parent != guest_dir for disk in disks.values())):
        raise RuntimeError(f"domain references foreign or missing disks: {expected_name}")
    identities = guest.get("files")
    if not identities:
        raise RuntimeError(f"missing recorded file identities: {expected_name}")
    for disk_name, disk in disks.items():
        file_path = Path(disk)
        recorded = identities.get(disk_name)
        info = file_path.lstat()
        if (file_path.is_symlink() or not file_path.is_file() or not recorded
                or [info.st_dev, info.st_ino] != recorded):
            raise RuntimeError(f"disk file identity changed: {file_path}")
    interfaces = root.findall("./devices/interface")
    if len(interfaces) != 1:
        raise RuntimeError(f"unexpected NIC set: {expected_name}")
    source = interfaces[0].find("source")
    mac = interfaces[0].find("mac")
    if (source is None or source.get("network") != guest["network"] or mac is None
            or mac.get("address", "").lower() != guest["mac"].lower()):
        raise RuntimeError(f"domain network identity mismatch: {expected_name}")
    return uuid


def domain_state(name):
    result = call(["virsh", "domstate", name]).lower()
    return result


def network_identity(xml_text, name, uuid, bridge):
    root = ET.fromstring(xml_text)
    if root.findtext("name") != name or root.findtext("uuid") != uuid:
        raise RuntimeError("libvirt network identity mismatch")
    forward = root.find("forward")
    if forward is not None and forward.get("mode") != "none":
        raise RuntimeError("qualification network forwarding is enabled")
    actual_bridge = root.find("bridge")
    if actual_bridge is None or actual_bridge.get("name") != bridge:
        raise RuntimeError("qualification bridge identity mismatch")


def file_identities(directory):
    result = {}
    for name in ("base.qcow2", "root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso"):
        path = directory / name
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_uid != 0:
            raise RuntimeError(f"unsafe run-owned file: {path}")
        result[name] = [info.st_dev, info.st_ino]
    return result


def put(path, text, mode=0o600):
    Path(path).write_text(text, encoding="utf-8")
    Path(path).chmod(mode)


def ssh(ip, key, known, command):
    return call(["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                 "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
                 "-o", "ConnectTimeout=3", f"o3kqual@{ip}", command])


def lease_ip(network, mac):
    for line in call(["virsh", "net-dhcp-leases", network], check=False).splitlines():
        fields = line.split()
        if len(fields) > 2 and fields[1].lower() == mac.lower():
            ip = fields[2].split("/")[0]
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                return ip
    return None


def wait_ssh(network, mac, key, known, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ip = lease_ip(network, mac)
        if ip:
            scan = subprocess.run(["ssh-keyscan", "-T", "2", ip], text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if scan.stdout:
                put(known, scan.stdout)
                try:
                    ssh(ip, key, known, "systemctl --version | head -1")
                    return ip
                except (RuntimeError, subprocess.CalledProcessError):
                    pass
        time.sleep(3)
    raise RuntimeError(f"guest SSH timeout for {mac}")


def provision(a):
    require_host(provisioning=True)
    path = run_path(a.run_id)
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"run already exists: {path}")
    images = [verified_image(a.debian_image, a.debian_sha256, "Debian 12"),
              verified_image(a.ubuntu_image, a.ubuntu_sha256, "Ubuntu 24.04")]
    free = shutil.disk_usage(ROOT.parent if ROOT.exists() else Path("/var/lib")).free
    if free < 35 * 1024**3 or (os.cpu_count() or 0) < 8:
        raise RuntimeError("need >=35 GiB free and >=8 host CPUs; created no resources")
    memory_kib = next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                      if line.startswith("MemAvailable:"))
    if memory_kib < 16 * 1024**2:
        raise RuntimeError("need >=16 GiB available host memory; created no resources")
    network = "o3k-pp6-" + a.run_id[:12]
    bridge = "p6" + hashlib.sha256(a.run_id.encode()).hexdigest()[:6]
    octet = 100 + int(hashlib.sha256(a.run_id.encode()).hexdigest()[:2], 16) % 100
    private, evidence = path / "private", path / "evidence"
    # libvirt's qemu user needs traversal; listing remains denied.
    private.mkdir(parents=True, mode=0o711)
    evidence.mkdir(mode=0o700)
    marker_path = path / ".o3k-pp6-owned.json"
    marker = {"format": "o3k-pp6-run-v1", "run_id": a.run_id, "network": network,
              "bridge": bridge, "network_uuid": None, "private": str(private), "guests": {}}
    put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
    try:
        if subprocess.run(["virsh", "net-info", network], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError(f"libvirt network exists: {network}")
        netxml = private / "network.xml"
        put(netxml, f"""<network><name>{network}</name><forward mode='none'/>
<bridge name='{bridge}' stp='off' delay='0'/><ip address='192.168.{octet}.1' netmask='255.255.255.0'>
<dhcp><range start='192.168.{octet}.20' end='192.168.{octet}.99'/></dhcp></ip></network>
""")
        call(["virsh", "net-define", str(netxml)])
        marker["network_uuid"] = call(["virsh", "net-info", network]).split("UUID:", 1)[1].splitlines()[0].strip()
        put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
        call(["virsh", "net-start", network])
        for n, (guest, (base, base_sha)) in enumerate(zip(GUESTS, images)):
            name = f"o3k-pp6-{a.run_id[:12]}-{guest}"
            if subprocess.run(["virsh", "dominfo", name], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError(f"libvirt domain exists: {name}")
            d = private / guest
            d.mkdir(mode=0o711)
            local_base = d / "base.qcow2"
            shutil.copyfile(base, local_base)
            local_base.chmod(0o444)
            if sha(local_base) != base_sha:
                raise RuntimeError("base image copy digest mismatch")
            root, state, journal = (d / x for x in ("root.qcow2", "state.qcow2", "journal.qcow2"))
            image_format = json.loads(call(["qemu-img", "info", "--output=json", str(local_base)])).get("format")
            if image_format not in ("qcow2", "raw"):
                raise RuntimeError(f"unsupported base image format: {image_format}")
            call(["qemu-img", "create", "-f", "qcow2", "-F", image_format, "-b", str(local_base), str(root), "24G"])
            call(["qemu-img", "create", "-f", "qcow2", str(state), "4G"])
            call(["qemu-img", "create", "-f", "qcow2", str(journal), "4G"])
            key, pub, known = d / "id_ed25519", d / "id_ed25519.pub", d / "known_hosts"
            call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"pp6-{a.run_id}-{guest}", "-f", str(key)])
            key.chmod(0o600)
            mac = "52:54:00:" + ":".join(f"{b:02x}" for b in hashlib.sha256((a.run_id + guest).encode()).digest()[:3])
            state_label, journal_label = f"O3KSTATE{n}", f"O3KJOURNAL{n}"
            user_data = f"""#cloud-config
hostname: {name}
manage_etc_hosts: true
users:
 - default
 - name: o3kqual
   groups: [sudo]
   sudo: ["ALL=(ALL) NOPASSWD:ALL]
   shell: /bin/bash
   lock_passwd: true
   ssh_authorized_keys:
    - {pub.read_text().strip()}
ssh_pwauth: false
disable_root: true
runcmd:
 - [systemctl, enable, --now, ssh]
 - [bash, -lc, "set -eu; mkfs.ext4 -F -L {state_label} /dev/vdb; mkfs.ext4 -F -L {journal_label} /dev/vdc; groupadd --system o3k || getent group o3k >/dev/null; useradd --system --gid o3k --home-dir /nonexistent --shell /usr/sbin/nologin o3k || id o3k >/dev/null; install -d -o root -g o3k -m 0750 /var/lib/o3k/state /var/lib/o3k/journal; echo 'LABEL={state_label} /var/lib/o3k/state ext4 defaults,nofail 0 2' >> /etc/fstab; echo 'LABEL={journal_label} /var/lib/o3k/journal ext4 defaults,nofail 0 2' >> /etc/fstab; mount /var/lib/o3k/state; mount /var/lib/o3k/journal"]
"""
            seed = d / "seed"
            seed.mkdir(mode=0o700)
            put(seed / "user-data", user_data)
            put(seed / "meta-data", json.dumps({"instance-id": name, "local-hostname": name}) + "\n")
            iso = d / "seed.iso"
            call(["genisoimage", "-output", str(iso), "-volid", "cidata", "-joliet", "-rock",
                  str(seed / "user-data"), str(seed / "meta-data")])
            marker["guests"][guest] = {"domain": name, "mac": mac, "base_image_sha256": base_sha,
                                       "network": network, "files": file_identities(d)}
            put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
            call(["virt-install", "--connect", "qemu:///system", "--name", name, "--memory", "4096",
                  "--vcpus", "2", "--import", "--osinfo", "detect=on,require=off", "--noautoconsole",
                  "--graphics", "none", "--disk", f"path={root},format=qcow2,bus=virtio",
                  "--disk", f"path={state},format=qcow2,bus=virtio,target=vdb",
                  "--disk", f"path={journal},format=qcow2,bus=virtio,target=vdc",
                  "--disk", f"path={iso},device=cdrom", "--network", f"network={network},model=virtio,mac={mac}"])
            marker["guests"][guest]["uuid"] = domain_identity(
                call(["virsh", "dumpxml", name]), guest, marker["guests"][guest], private)
            put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
            ip = wait_ssh(network, mac, key, known, a.timeout)
            expected_id, expected_version = (("debian", "12") if guest == "debian12"
                                             else ("ubuntu", "24.04"))
            os_check = (". /etc/os-release; test \"$ID\" = " + expected_id
                        + "; test \"$VERSION_ID\" = " + expected_version + "; ")
            observed = ssh(ip, key, known, "set -eu; " + os_check + "test -x /usr/lib/systemd/systemd; "
                "test \"$(findmnt -n -o FSTYPE /var/lib/o3k/state)\" = ext4; "
                "test \"$(findmnt -n -o FSTYPE /var/lib/o3k/journal)\" = ext4; "
                f"test \"$(blkid -s LABEL -o value \"$(findmnt -n -o SOURCE /var/lib/o3k/state)\")\" = {state_label}; "
                f"test \"$(blkid -s LABEL -o value \"$(findmnt -n -o SOURCE /var/lib/o3k/journal)\")\" = {journal_label}; "
                "test \"$(findmnt -n -o SOURCE /var/lib/o3k/state)\" != \"$(findmnt -n -o SOURCE /var/lib/o3k/journal)\"; "
                "test \"$(stat -c %a /var/lib/o3k/state)\" = 750; "
                "test \"$(stat -c %a /var/lib/o3k/journal)\" = 750; "
                "test \"$(stat -c %U:%G /var/lib/o3k/state)\" = root:o3k; "
                "test \"$(stat -c %U:%G /var/lib/o3k/journal)\" = root:o3k; "
                "test ! -L /var/lib/o3k/state; test ! -L /var/lib/o3k/journal; id o3k; "
                "systemctl --version | head -1; cat /etc/os-release; uname -a; "
                "findmnt -n -o TARGET,SOURCE,FSTYPE /var/lib/o3k/state; "
                "findmnt -n -o TARGET,SOURCE,FSTYPE /var/lib/o3k/journal; "
                "stat -Lc '%n %d:%i %u:%g %a' /var/lib/o3k/state /var/lib/o3k/journal")
            (evidence / f"{guest}.identity.txt").write_text(observed + "\n", encoding="utf-8")
            marker["guests"][guest].update({"ip": ip, "identity_sha256": hashlib.sha256(observed.encode()).hexdigest()})
            put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
        repo = Path(__file__).resolve().parents[2]
        source_sha = os.environ.get("O3K_PP6_SOURCE_SHA") or call(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], check=False)
        if source_sha and not re.fullmatch(r"[0-9a-f]{40,64}", source_sha):
            source_sha = "INVALID_SOURCE_SHA"
        source_tree = call(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], check=False)
        host = {"kernel": call(["uname", "-a"]),
                "filesystem": call(["findmnt", "-n", "-o", "SOURCE,FSTYPE", "-T", str(ROOT)]),
                "virsh": call(["virsh", "--version"], check=False),
                "qemu_img": call(["qemu-img", "--version"], check=False)}
        result = {"format": "o3k-pp6-environment-v1", "run_id": a.run_id,
                  "source_sha": source_sha or "NOT_RECORDED", "source_tree_sha": source_tree or "NOT_RECORDED",
                  "harness_sha256": sha(Path(__file__)), "network_forwarding": "disabled",
                  "release_artifact": "NOT_PROVIDED", "installed_executable_digests": "NOT_INSTALLED",
                  "host": host, "guests": marker["guests"],
                  "created_at": datetime.now(timezone.utc).isoformat()}
        put(evidence / "environment.json", json.dumps(result, sort_keys=True, indent=2) + "\n", 0o644)
        print(json.dumps(result, sort_keys=True, indent=2))
    except Exception:
        print(f"provision failed; run-owned resources retained for diagnosis: {path}", file=sys.stderr)
        raise


def load_marker(run_id):
    path = run_path(run_id)
    marker_file = path / ".o3k-pp6-owned.json"
    if path.is_symlink() or marker_file.is_symlink() or not marker_file.is_file():
        raise RuntimeError("missing/unsafe ownership marker")
    if path.lstat().st_uid != 0 or marker_file.lstat().st_uid != 0 or marker_file.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("run ownership metadata has unsafe owner or mode")
    marker = json.loads(marker_file.read_text(encoding="utf-8"))
    if marker.get("format") != "o3k-pp6-run-v1" or marker.get("run_id") != run_id:
        raise RuntimeError("ownership identity mismatch")
    if marker.get("private") != str((path / "private").resolve()):
        raise RuntimeError("private path identity mismatch")
    if marker.get("network") != "o3k-pp6-" + run_id[:12]:
        raise RuntimeError("network name does not match run identity")
    expected_bridge = "p6" + hashlib.sha256(run_id.encode()).hexdigest()[:6]
    if marker.get("bridge") != expected_bridge:
        raise RuntimeError("bridge name does not match run identity")
    for guest in marker.get("guests", {}):
        guest_data = marker["guests"][guest]
        expected_mac = "52:54:00:" + ":".join(
            f"{byte:02x}" for byte in hashlib.sha256((run_id + guest).encode()).digest()[:3])
        if (guest not in GUESTS or guest_data.get("domain") != f"o3k-pp6-{run_id[:12]}-{guest}"
                or guest_data.get("network") != marker["network"]
                or guest_data.get("mac", "").lower() != expected_mac):
            raise RuntimeError("domain identity does not match run identity")
    return path, marker


def destroy(a):
    require_host()
    path, marker = load_marker(a.run_id)
    private = path / "private"
    evidence = path / "evidence"
    if private.is_symlink() or private.resolve() != private or evidence.is_symlink() or not evidence.is_dir():
        raise RuntimeError("unsafe run directories; refusing cleanup")
    if not private.exists():
        domains_remain = any(subprocess.run(
            ["virsh", "dominfo", guest["domain"]], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL).returncode == 0 for guest in marker["guests"].values())
        network_remains = subprocess.run(["virsh", "net-info", marker["network"]],
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL).returncode == 0
        if domains_remain or network_remains:
            raise RuntimeError("private run files are missing while libvirt resources remain")
        print(f"run already destroyed; retained evidence at {evidence}")
        return
    for guest_key, guest in marker["guests"].items():
        name = guest["domain"]
        if subprocess.run(["virsh", "dominfo", name], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            domain_identity(call(["virsh", "dumpxml", name]), guest_key, guest,
                            path / "private")
            if domain_state(name) not in ("shut off",):
                call(["virsh", "destroy", name])
                if domain_state(name) != "shut off":
                    raise RuntimeError(f"domain did not stop; refusing cleanup: {name}")
            call(["virsh", "undefine", name])
    network = marker["network"]
    if subprocess.run(["virsh", "net-info", network], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
        actual = call(["virsh", "net-info", network]).split("UUID:", 1)[1].splitlines()[0].strip()
        if actual != marker.get("network_uuid"):
            raise RuntimeError("network UUID changed; refusing cleanup")
        network_identity(call(["virsh", "net-dumpxml", network]), network,
                         marker["network_uuid"], marker["bridge"])
        call(["virsh", "net-destroy", network], check=False)
        call(["virsh", "net-undefine", network])
    shutil.rmtree(private)
    print(f"destroyed run-owned VMs/network; retained evidence at {path / 'evidence'}")


def force_restart(a):
    require_host()
    path, marker = load_marker(a.run_id)
    guest = marker["guests"].get(a.guest)
    if not guest:
        raise RuntimeError("guest not found in ownership marker")
    domain_identity(call(["virsh", "dumpxml", guest["domain"]]), a.guest, guest, path / "private")
    call(["virsh", "destroy", guest["domain"]])
    call(["virsh", "start", guest["domain"]])
    event = {"type": "guest-force-poweroff-restart", "domain": guest["domain"],
             "time": datetime.now(timezone.utc).isoformat(), "evidence_limit": "not host power-loss evidence"}
    with (path / "evidence" / "injections.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
    print(json.dumps(event, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("provision")
    q.add_argument("--run-id", required=True)
    q.add_argument("--debian-image", required=True)
    q.add_argument("--debian-sha256", required=True)
    q.add_argument("--ubuntu-image", required=True)
    q.add_argument("--ubuntu-sha256", required=True)
    q.add_argument("--timeout", type=int, default=300)
    q.set_defaults(func=provision)
    q = sub.add_parser("destroy")
    q.add_argument("--run-id", required=True)
    q.set_defaults(func=destroy)
    q = sub.add_parser("force-restart")
    q.add_argument("--run-id", required=True)
    q.add_argument("--guest", choices=GUESTS, required=True)
    q.set_defaults(func=force_restart)
    a = p.parse_args()
    try:
        a.func(a)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError,
            ET.ParseError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"pp6 qualification: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
