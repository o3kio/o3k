#!/usr/bin/env python3
"""Run-owned Debian 13/Ubuntu 24.04 systemd and ext4 qualification guests."""
import argparse, hashlib, json, os, re, shlex, shutil, signal, subprocess, sys, time
import glob
import ipaddress
import pwd
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("O3K_PP6_QUAL_ROOT", "/var/lib/o3k-pp6-qualification"))
GUESTS = ("debian13", "ubuntu2404")
# Existing Debian 12 runs remain eligible for ownership-checked cleanup only.
CLEANUP_GUESTS = (*GUESTS, "debian12")
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
    needed = ("virsh", "virt-install", "qemu-img", "genisoimage", "ssh", "ssh-keygen", "script")
    if not provisioning:
        needed = ("virsh",)
    missing = [x for x in needed if shutil.which(x) is None]
    if os.geteuid() != 0 or (provisioning and not Path("/dev/kvm").exists()) or missing:
        raise RuntimeError("requires root" + (", /dev/kvm" if provisioning else "") +
                           " and tools; missing=" + ",".join(missing))
    if provisioning:
        forwarding_controls = ["/proc/sys/net/ipv4/ip_forward"]
        forwarding_controls.extend(glob.glob("/proc/sys/net/ipv4/conf/*/forwarding"))
        forwarding_controls.extend(glob.glob("/proc/sys/net/ipv6/conf/*/forwarding"))
        for name in sorted(set(forwarding_controls)):
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


def selected_guests(requested):
    """Return the canonical selected guest set; omission retains both guests."""
    if requested is None or requested == []:
        return GUESTS
    if not isinstance(requested, list) or any(name not in GUESTS for name in requested):
        raise ValueError("guest selection must contain debian13 and/or ubuntu2404")
    if len(set(requested)) != len(requested):
        raise ValueError("guest selection contains duplicates")
    return tuple(name for name in GUESTS if name in requested)


def validate_provision_selection(requested, image_args):
    selected = selected_guests(requested)
    specs = {"debian13": ("debian_image", "debian_sha256", "Debian 13"),
             "ubuntu2404": ("ubuntu_image", "ubuntu_sha256", "Ubuntu 24.04")}
    images = {}
    for guest in selected:
        path_name, digest_name, label = specs[guest]
        path, digest = image_args.get(path_name), image_args.get(digest_name)
        if not path or not digest:
            raise ValueError(f"{label} image and SHA-256 are required when selected")
        images[guest] = verified_image(path, digest, label)
    return selected, images


def validate_environment_record(record):
    selected = record.get("selected_guests")
    canonical = selected_guests(selected)
    guests = record.get("guests")
    if not isinstance(guests, dict) or set(guests) != set(canonical):
        raise RuntimeError("completed run guest identities do not match selected guest set")
    if record.get("provisioning_status") != "complete":
        raise RuntimeError("run record does not represent completed selected-guest provisioning")


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
    network_ip = root.find("ip")
    if network_ip is None or network_ip.find("dhcp") is not None:
        raise RuntimeError("qualification network must have a host address and no DHCP service")


def file_identities(directory):
    result = {}
    names = ("base.qcow2", "root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso",
             "id_ed25519", "id_ed25519.pub", "known_hosts", "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub",
             "seed/user-data", "seed/meta-data", "seed/network-config")
    for name in names:
        path = directory / name
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_uid != os.geteuid():
            raise RuntimeError(f"unsafe run-owned file: {path}")
        result[name] = [info.st_dev, info.st_ino]
    return result


def verify_recorded_files(private, marker):
    network_xml = private / "network.xml"
    network_info = network_xml.lstat()
    if (network_xml.is_symlink() or not network_xml.is_file() or network_info.st_uid != os.geteuid()
            or marker.get("network_xml_inode") != [network_info.st_dev, network_info.st_ino]):
        raise RuntimeError("qualification network definition inode changed; refusing cleanup")
    allowed_files = {"network.xml"}
    allowed_dirs = set()
    recorded_identities = {}
    for guest_name in CLEANUP_GUESTS:
        allowed_dirs.add(guest_name)
        allowed_dirs.add(f"{guest_name}/seed")
        allowed_files.update(f"{guest_name}/{name}" for name in (
            "base.qcow2", "root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso",
            "id_ed25519", "id_ed25519.pub", "known_hosts", "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub",
            "seed/user-data", "seed/meta-data", "seed/network-config"))
    for guest_name, guest in marker.get("guests", {}).items():
        recorded = guest.get("files")
        if not isinstance(recorded, dict):
            raise RuntimeError(f"missing run-owned file identities: {guest_name}")
        for name, identity in recorded.items():
            recorded_identities[f"{guest_name}/{name}"] = identity
    for directory, names, files in os.walk(private, followlinks=False):
        current = Path(directory)
        for name in names:
            entry = current / name
            relative = entry.relative_to(private).as_posix()
            info = entry.lstat()
            if (relative not in allowed_dirs or entry.is_symlink() or not entry.is_dir()
                    or info.st_uid != os.geteuid() or info.st_mode & 0o022):
                raise RuntimeError(f"unexpected or unsafe private directory; refusing cleanup: {entry}")
        for name in files:
            entry = current / name
            relative = entry.relative_to(private).as_posix()
            info = entry.lstat()
            qemu_owned_disk = (len(Path(relative).parts) == 2
                               and Path(relative).name in ("base.qcow2", "root.qcow2", "state.qcow2",
                                                          "journal.qcow2", "seed.iso")
                               and info.st_uid == pwd.getpwnam("libvirt-qemu").pw_uid)
            if (relative not in allowed_files or entry.is_symlink() or not entry.is_file()
                    or (info.st_uid != os.geteuid() and not qemu_owned_disk)):
                raise RuntimeError(f"unexpected or unsafe private file; refusing cleanup: {entry}")
            if relative != "network.xml":
                recorded = recorded_identities.get(relative)
                if recorded != [info.st_dev, info.st_ino]:
                    raise RuntimeError(f"unrecorded or replaced private file; refusing cleanup: {entry}")
    for guest_name, guest in marker.get("guests", {}).items():
        directory = private / guest_name
        recorded = guest.get("files")
        if not isinstance(recorded, dict):
            raise RuntimeError(f"missing run-owned file identities: {guest_name}")
        for name, identity in recorded.items():
            path = directory / name
            info = path.lstat()
            qemu_owned_disk = (name in ("base.qcow2", "root.qcow2", "state.qcow2", "journal.qcow2", "seed.iso")
                               and info.st_uid == pwd.getpwnam("libvirt-qemu").pw_uid)
            if (path.is_symlink() or not path.is_file()
                    or (info.st_uid != os.geteuid() and not qemu_owned_disk)
                    or identity != [info.st_dev, info.st_ino]):
                raise RuntimeError(f"run-owned file identity changed; refusing cleanup: {path}")


def validate_installation_record(record, source_sha, version, artifact_sha256):
    manifest = record.get("release_manifest")
    if not isinstance(manifest, dict):
        raise RuntimeError("installed release manifest is missing or malformed")
    expected = {"source_commit": source_sha, "version": version, "profile": "libvirt",
                "release_artifact_sha256": artifact_sha256}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RuntimeError("installed release manifest does not match authenticated candidate identity")
    executables = record.get("executables")
    required = {"o3kd", "o3k", "o3k-compute", "o3k-network"}
    if not isinstance(executables, dict) or set(executables) != required:
        raise RuntimeError("installed release executable inventory is incomplete")
    for name, value in executables.items():
        if (not isinstance(value, dict)
                or value.get("path") != f"/usr/local/bin/{name}"
                or not isinstance(value.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
                or value.get("uid") != 0 or value.get("gid") != 0
                or value.get("mode") != 0o755
                or not isinstance(value.get("device"), int)
                or not isinstance(value.get("inode"), int)
                or value["device"] < 0 or value["inode"] <= 0):
            raise RuntimeError(f"unsafe installed executable identity: {name}")
    if (not isinstance(record.get("release_manifest_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["release_manifest_sha256"])
            or not isinstance(record.get("release_manifest_inode"), list)
            or len(record["release_manifest_inode"]) != 2
            or any(not isinstance(x, int) or x < 0 for x in record["release_manifest_inode"])):
        raise RuntimeError("installed release manifest identity is incomplete")


def put(path, text, mode=0o600):
    Path(path).write_text(text, encoding="utf-8")
    Path(path).chmod(mode)


def ssh(ip, key, known, command):
    argv = ["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
            "-o", "ConnectTimeout=3", f"o3kqual@{ip}", command]
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        message = (result.stderr or result.stdout).strip().replace("\n", " ")[:512]
        lowered = message.lower()
        category = ("host-key" if "host key" in lowered or "hostkey" in lowered else
                    "authentication" if "permission denied" in lowered else
                    "transport" if any(x in lowered for x in ("timed out", "refused", "no route")) else
                    "ssh-error")
        raise RuntimeError(f"SSH {category} failure: {message or 'no diagnostic output'}")
    return result.stdout.strip()


def guest_static_ip(subnet_octet, ordinal):
    if not isinstance(subnet_octet, int) or not 100 <= subnet_octet <= 199:
        raise ValueError("qualification subnet octet is out of range")
    if ordinal not in (0, 1):
        raise ValueError("qualification guest ordinal is out of range")
    return str(ipaddress.IPv4Address(f"192.168.{subnet_octet}.{20 + ordinal}"))


def guest_network_config(mac, ip):
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac.lower()):
        raise ValueError("qualification guest MAC is malformed")
    interface = ipaddress.IPv4Interface(f"{ip}/24")
    octets = str(interface.ip).split(".")
    if octets[:2] != ["192", "168"] or not 100 <= int(octets[2]) <= 199 or int(octets[3]) not in (20, 21):
        raise ValueError("qualification guest IP is outside the reserved host-only slots")
    config = {"version": 1, "config": [{
        "type": "physical", "name": "qualification", "mac_address": mac.lower(),
        "subnets": [{"type": "static", "address": str(interface)}],
    }]}
    return json.dumps(config, indent=2) + "\n"


def wait_ssh(ip, key, known, host_key_public, timeout):
    deadline = time.monotonic() + timeout
    put(known, f"{ip} {host_key_public}\n")
    last_error = "no SSH attempt made"
    while time.monotonic() < deadline:
        try:
            ssh(ip, key, known, "systemctl --version | head -1")
            return ip
        except (RuntimeError, subprocess.CalledProcessError) as error:
            last_error = str(error)[:600]
        time.sleep(3)
    raise RuntimeError(f"guest SSH timeout for static address {ip}; last_error={last_error}")


def guest_user_data(name, host_key_private, host_key_public, user_public_key, state_label, journal_label):
    # JSON is a YAML subset: serialize scalars and commands rather than hand
    # quoting a cloud-config document containing keys, colons and shell syntax.
    config = {
        "hostname": name, "manage_etc_hosts": True,
        "ssh_keys": {"ed25519_private": host_key_private, "ed25519_public": host_key_public},
        "users": ["default", {
            "name": "o3kqual", "groups": ["sudo"], "sudo": ["ALL=(ALL) NOPASSWD:ALL"],
            "shell": "/bin/bash", "lock_passwd": True, "ssh_authorized_keys": [user_public_key],
        }],
        "ssh_pwauth": False, "disable_root": True,
        "runcmd": [
            ["systemctl", "enable", "--now", "ssh"],
            ["bash", "-lc", f"set -eu; mkfs.ext4 -F -L {state_label} /dev/vdb; mkfs.ext4 -F -L {journal_label} /dev/vdc; groupadd --system o3k || getent group o3k >/dev/null; useradd --system --gid o3k --home-dir /nonexistent --shell /usr/sbin/nologin o3k || id o3k >/dev/null; install -d -o root -g o3k -m 0750 /var/lib/o3k/state /var/lib/o3k/journal; echo 'LABEL={state_label} /var/lib/o3k/state ext4 defaults,nofail 0 2' >> /etc/fstab; echo 'LABEL={journal_label} /var/lib/o3k/journal ext4 defaults,nofail 0 2' >> /etc/fstab; mount /var/lib/o3k/state; mount /var/lib/o3k/journal; chown root:o3k /var/lib/o3k/state /var/lib/o3k/journal; chmod 0750 /var/lib/o3k/state /var/lib/o3k/journal"],
        ],
    }
    return "#cloud-config\n" + json.dumps(config, indent=2) + "\n"


def bounded_call(argv, limit=16000, timeout=10):
    try:
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
        output = (result.stdout or "")[-limit:]
        return {"command": argv, "exit_code": result.returncode, "timed_out": False, "output": output}
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output = output[-limit:]
        return {"command": argv, "exit_code": None, "timed_out": True, "output": output}


def capture_guest_diagnostics(guest_name, guest, private, evidence, key=None, known=None):
    """Capture bounded host/guest observations before run-owned resources are cleaned."""
    prefix = evidence / f"diagnostics-{guest_name}"
    domain = guest.get("domain")
    records = {"guest": guest_name, "domain": domain,
               "captured_at": datetime.now(timezone.utc).isoformat(), "observations": []}
    if domain and subprocess.run(["virsh", "dominfo", domain], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL).returncode == 0:
        xml = call(["virsh", "dumpxml", domain], check=False)
        (Path(str(prefix) + ".domain.xml")).write_text(xml + "\n", encoding="utf-8")
        interface = None
        try:
            interface_node = ET.fromstring(xml).find("./devices/interface/target")
            interface = interface_node.get("dev") if interface_node is not None else None
        except ET.ParseError:
            pass
        commands = [["virsh", "domstate", domain], ["virsh", "domiflist", domain]]
        if interface:
            commands.append(["virsh", "domifstat", domain, interface])
        for argv in commands:
            records["observations"].append(bounded_call(argv))
    bridge = None
    if guest.get("network"):
        netxml = call(["virsh", "net-dumpxml", guest["network"]], check=False)
        if netxml:
            (Path(str(prefix) + ".network.xml")).write_text(netxml + "\n", encoding="utf-8")
            try:
                bridge_node = ET.fromstring(netxml).find("bridge")
                bridge = bridge_node.get("name") if bridge_node is not None else None
            except ET.ParseError:
                pass
    commands = [["ip", "-details", "link", "show"], ["ip", "-4", "address", "show"],
                ["ip", "-4", "route", "show"], ["ip", "neigh", "show"]]
    if bridge:
        commands += [["ip", "-details", "link", "show", bridge], ["ip", "-4", "address", "show", "dev", bridge]]
    records["observations"].extend(bounded_call(argv) for argv in commands)
    if key and known and guest.get("ip"):
        for command in ("cloud-init status --long", "journalctl -b --no-pager -u cloud-init-local -u cloud-init -u cloud-config -u cloud-final -n 100"):
            try:
                output = ssh(guest["ip"], key, known,
                             "sudo -n sh -c " + shlex.quote(command))
                (Path(str(prefix) + f".{command.split()[0]}.txt")).write_text(output[-16000:] + "\n", encoding="utf-8")
                records["observations"].append({"command": command, "exit_code": 0, "output": output[-16000:]})
            except Exception as error:
                records["observations"].append({"command": command, "error": str(error)[:600]})
    else:
        records["guest_diagnostics"] = "unavailable: host-key-pinned SSH did not become available"
    target = Path(str(prefix) + ".json")
    put(target, json.dumps(records, sort_keys=True, indent=2) + "\n", 0o600)


def start_serial_capture(domain, evidence, guest_name):
    output = evidence / f"{guest_name}.serial.log"
    errors = evidence / f"{guest_name}.serial.stderr"
    stream = output.open("wb")
    error_stream = errors.open("wb")
    stream.close()
    error_stream.close()
    # `script` gives virsh the controlling TTY required by its interactive
    # console client while writing the bounded transcript to the run evidence.
    argv = ["script", "--quiet", "--flush", "--output-limit", "262144", "--command",
            f"virsh console --force {shlex.quote(domain)}", str(output)]
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, start_new_session=True)
    return process, output, errors


def stop_serial_capture(capture):
    if not capture:
        return
    process, output, errors = capture
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
    if process.stderr:
        errors.write_bytes(process.stderr.read()[-16000:])
        process.stderr.close()
    for path in (output, errors):
        if path.exists():
            content = path.read_bytes()
            if len(content) > 256 * 1024:
                path.write_bytes(content[-256 * 1024:])
            path.chmod(0o600)


def provision(a):
    require_host(provisioning=True)
    selected, images = validate_provision_selection(a.guest, vars(a))
    path = run_path(a.run_id)
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"run already exists: {path}")
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
              "bridge": bridge, "network_uuid": None, "private": str(private), "selected_guests": list(selected), "guests": {},
              "run_inode": [path.lstat().st_dev, path.lstat().st_ino],
              "private_inode": [private.lstat().st_dev, private.lstat().st_ino],
              "evidence_inode": [evidence.lstat().st_dev, evidence.lstat().st_ino]}
    put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
    active_capture = None
    active_guest = None
    active_key = active_known = None
    try:
        if subprocess.run(["virsh", "net-info", network], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError(f"libvirt network exists: {network}")
        netxml = private / "network.xml"
        put(netxml, f"""<network><name>{network}</name><forward mode='none'/>
<bridge name='{bridge}' stp='off' delay='0'/><ip address='192.168.{octet}.1' netmask='255.255.255.0'/></network>
""")
        marker["network_xml_inode"] = [netxml.lstat().st_dev, netxml.lstat().st_ino]
        put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
        call(["virsh", "net-define", str(netxml)])
        marker["network_uuid"] = call(["virsh", "net-info", network]).split("UUID:", 1)[1].splitlines()[0].strip()
        put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
        call(["virsh", "net-start", network])
        for guest in selected:
            n = GUESTS.index(guest)
            active_guest = guest
            base, base_sha = images[guest]
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
            host_key = d / "ssh_host_ed25519_key"
            call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                  f"pp6-host-{a.run_id}-{guest}", "-f", str(host_key)])
            host_key.chmod(0o600)
            host_key_public = call(["ssh-keygen", "-y", "-f", str(host_key)])
            put(known, "", 0o600)
            mac = "52:54:00:" + ":".join(f"{b:02x}" for b in hashlib.sha256((a.run_id + guest).encode()).digest()[:3])
            static_ip = guest_static_ip(octet, n)
            state_label, journal_label = f"O3KSTATE{n}", f"O3KJOURNAL{n}"
            user_data = guest_user_data(name, host_key.read_text(), host_key_public,
                                        pub.read_text().strip(), state_label, journal_label)
            seed = d / "seed"
            seed.mkdir(mode=0o700)
            put(seed / "user-data", user_data)
            put(seed / "meta-data", json.dumps({"instance-id": name, "local-hostname": name}) + "\n")
            put(seed / "network-config", guest_network_config(mac, static_ip))
            iso = d / "seed.iso"
            call(["genisoimage", "-output", str(iso), "-volid", "cidata", "-joliet", "-rock",
                  "-graft-points", "user-data=" + str(seed / "user-data"),
                  "meta-data=" + str(seed / "meta-data"),
                  "network-config=" + str(seed / "network-config")])
            marker["guests"][guest] = {"domain": name, "mac": mac, "base_image_sha256": base_sha,
                                       "network": network, "ip": static_ip, "addressing": "static",
                                       "files": file_identities(d)}
            put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
            call(["virt-install", "--connect", "qemu:///system", "--name", name, "--memory", "4096",
                  "--vcpus", "2", "--import", "--osinfo", "detect=on,require=off", "--noautoconsole",
                  "--graphics", "none", "--disk", f"path={root},format=qcow2,bus=virtio,target=vda",
                  "--disk", f"path={state},format=qcow2,bus=virtio,target=vdb",
                  "--disk", f"path={journal},format=qcow2,bus=virtio,target=vdc",
                  "--disk", f"path={iso},device=cdrom", "--network", f"network={network},model=virtio,mac={mac}"])
            marker["guests"][guest]["uuid"] = domain_identity(
                call(["virsh", "dumpxml", name]), guest, marker["guests"][guest], private)
            put(marker_path, json.dumps(marker, sort_keys=True, indent=2) + "\n")
            capture = start_serial_capture(name, evidence, guest)
            active_capture, active_key, active_known = capture, key, known
            ip = wait_ssh(static_ip, key, known, host_key_public, a.timeout)
            ssh(ip, key, known, "sudo -n cloud-init status --wait")
            expected_id, expected_version = (("debian", "13") if guest == "debian13"
                                             else ("ubuntu", "24.04"))
            os_check = (". /etc/os-release; test \"$ID\" = " + expected_id
                        + "; test \"$VERSION_ID\" = " + expected_version + "; ")
            network_check = (f"test \"$(ip -4 -o addr show | awk '$4 == \"{static_ip}/24\" {{print $4}}')\" = \"{static_ip}/24\"; "
                             "test -z \"$(ip -4 route show default)\"; ip -4 -o addr show; ip -4 route; ")
            observed = ssh(ip, key, known, "sudo -n sh -c " + shlex.quote("set -eu; " + os_check + network_check + "test -x /usr/lib/systemd/systemd; "
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
                "stat -Lc '%n %d:%i %u:%g %a' /var/lib/o3k/state /var/lib/o3k/journal"))
            stop_serial_capture(capture)
            active_capture = None
            active_key = active_known = None
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
                  "network_addressing": "static-no-dhcp",
                  "selected_guests": list(selected), "provisioning_status": "complete",
                  "release_artifact": "NOT_PROVIDED", "installed_executable_digests": "NOT_INSTALLED",
                  "host": host, "guests": marker["guests"],
                  "created_at": datetime.now(timezone.utc).isoformat()}
        validate_environment_record(result)
        put(evidence / "environment.json", json.dumps(result, sort_keys=True, indent=2) + "\n", 0o644)
        print(json.dumps(result, sort_keys=True, indent=2))
    except Exception:
        if active_capture:
            stop_serial_capture(active_capture)
            if active_guest in marker["guests"]:
                capture_guest_diagnostics(active_guest, marker["guests"][active_guest],
                                          private, evidence, active_key, active_known)
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
    selected = selected_guests(marker.get("selected_guests"))
    if not set(marker.get("guests", {})).issubset(set(selected)):
        raise RuntimeError("ownership marker contains a guest outside the selected guest set")
    if marker.get("private") != str((path / "private").resolve()):
        raise RuntimeError("private path identity mismatch")
    if path.lstat().st_uid != 0 or path.lstat().st_mode & 0o022:
        raise RuntimeError("run directory ownership or permissions are unsafe")
    expected_run_inode = marker.get("run_inode")
    if expected_run_inode != [path.lstat().st_dev, path.lstat().st_ino]:
        raise RuntimeError("run directory inode changed")
    private = path / "private"
    if private.exists() and marker.get("private_inode") != [private.lstat().st_dev, private.lstat().st_ino]:
        raise RuntimeError("private run directory inode changed")
    evidence = path / "evidence"
    if (not evidence.is_dir() or evidence.is_symlink()
            or marker.get("evidence_inode") != [evidence.lstat().st_dev, evidence.lstat().st_ino]):
        raise RuntimeError("evidence directory inode changed")
    if marker.get("network") != "o3k-pp6-" + run_id[:12]:
        raise RuntimeError("network name does not match run identity")
    expected_bridge = "p6" + hashlib.sha256(run_id.encode()).hexdigest()[:6]
    if marker.get("bridge") != expected_bridge:
        raise RuntimeError("bridge name does not match run identity")
    for guest in marker.get("guests", {}):
        guest_data = marker["guests"][guest]
        expected_mac = "52:54:00:" + ":".join(
            f"{byte:02x}" for byte in hashlib.sha256((run_id + guest).encode()).digest()[:3])
        if (guest not in CLEANUP_GUESTS or guest_data.get("domain") != f"o3k-pp6-{run_id[:12]}-{guest}"
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
    if private.lstat().st_uid != 0 or private.lstat().st_mode & 0o022:
        raise RuntimeError("private run directory ownership or permissions changed; refusing cleanup")
    if evidence.lstat().st_uid != 0 or evidence.lstat().st_mode & 0o077:
        raise RuntimeError("evidence directory ownership or permissions changed; refusing cleanup")
    if private.exists():
        verify_recorded_files(private, marker)
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


def capture_installation(a):
    require_host()
    if not re.fullmatch(r"[0-9a-f]{40}", a.source_sha):
        raise ValueError("source SHA must be 40 lowercase hexadecimal characters")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?", a.version):
        raise ValueError("version must be an exact release version without the v prefix")
    if not re.fullmatch(r"[0-9a-f]{64}", a.artifact_sha256):
        raise ValueError("release artifact SHA-256 must be 64 lowercase hexadecimal characters")
    path, marker = load_marker(a.run_id)
    guest = marker["guests"].get(a.guest)
    if not guest:
        raise RuntimeError("guest not found in ownership marker")
    domain_identity(call(["virsh", "dumpxml", guest["domain"]]), a.guest, guest, path / "private")
    script = r'''import hashlib,json,os,pathlib,stat,subprocess,sys
expected_source,expected_version,expected_artifact=sys.argv[1:4]
manifest_path=pathlib.Path('/usr/local/share/o3k/release-manifest.json')
raw=manifest_path.read_bytes()
manifest=json.loads(raw)
expected={'source_commit':expected_source,'version':expected_version,'profile':'libvirt','release_artifact_sha256':expected_artifact}
if not isinstance(manifest,dict) or any(manifest.get(k)!=v for k,v in expected.items()):
 raise SystemExit('installed release manifest does not match expected authenticated candidate')
manifest_stat=manifest_path.lstat()
if not stat.S_ISREG(manifest_stat.st_mode) or manifest_stat.st_uid!=0 or stat.S_IMODE(manifest_stat.st_mode)!=0o644:
 raise SystemExit('installed release manifest ownership or mode is unsafe')
executables={}
for name in ('o3kd','o3k','o3k-compute','o3k-network'):
 p=pathlib.Path('/usr/local/bin')/name
 st=p.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o755:
  raise SystemExit('installed executable ownership or mode is unsafe: '+name)
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''): h.update(block)
 executables[name]={'path':str(p),'sha256':h.hexdigest(),'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'device':st.st_dev,'inode':st.st_ino}
print(json.dumps({'release_manifest':manifest,'release_manifest_sha256':hashlib.sha256(raw).hexdigest(),'release_manifest_inode':[manifest_stat.st_dev,manifest_stat.st_ino],'executables':executables,'os_release':pathlib.Path('/etc/os-release').read_text(),'kernel':subprocess.check_output(['uname','-a'],text=True).strip(),'systemd':subprocess.check_output(['systemctl','--version'],text=True).splitlines()[0],'filesystem':{p:subprocess.check_output(['findmnt','-n','-o','SOURCE,FSTYPE','--target',p],text=True).strip() for p in ('/var/lib/o3k/state','/var/lib/o3k/journal')}},sort_keys=True))'''
    command = "python3 -c " + shlex.quote(script) + " " + " ".join(
        shlex.quote(value) for value in (a.source_sha, a.version, a.artifact_sha256))
    raw = ssh(guest["ip"], path / "private" / a.guest / "id_ed25519",
              path / "private" / a.guest / "known_hosts", command)
    record = json.loads(raw)
    validate_installation_record(record, a.source_sha, a.version, a.artifact_sha256)
    record["guest"] = a.guest
    record["captured_at"] = datetime.now(timezone.utc).isoformat()
    evidence = path / "evidence"
    destination = evidence / f"{a.guest}.installation.json"
    temporary = evidence / f".{a.guest}.installation.tmp"
    put(temporary, json.dumps(record, sort_keys=True, indent=2) + "\n", 0o600)
    os.replace(temporary, destination)
    print(f"recorded authenticated candidate identity for {a.guest}: {destination}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("provision")
    q.add_argument("--run-id", required=True)
    q.add_argument("--guest", choices=GUESTS, action="append",
                    help="guest to provision; repeat for both (default: both)")
    q.add_argument("--debian-image")
    q.add_argument("--debian-sha256")
    q.add_argument("--ubuntu-image")
    q.add_argument("--ubuntu-sha256")
    q.add_argument("--timeout", type=int, default=300)
    q.set_defaults(func=provision)
    q = sub.add_parser("destroy")
    q.add_argument("--run-id", required=True)
    q.set_defaults(func=destroy)
    q = sub.add_parser("force-restart")
    q.add_argument("--run-id", required=True)
    q.add_argument("--guest", choices=GUESTS, required=True)
    q.set_defaults(func=force_restart)
    q = sub.add_parser("capture-installation")
    q.add_argument("--run-id", required=True)
    q.add_argument("--guest", choices=GUESTS, required=True)
    q.add_argument("--source-sha", required=True)
    q.add_argument("--version", required=True)
    q.add_argument("--artifact-sha256", required=True,
                    help="archive digest read from the already verified Sigstore digest manifest")
    q.set_defaults(func=capture_installation)
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
