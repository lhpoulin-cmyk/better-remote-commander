#!/usr/bin/env python3
"""Safely install the pinned HELIX-BIOS Toolkit v1 package onto Lore's USB."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import shutil
import subprocess
import sys
import argparse


STAGE = Path("/tmp/helix-bios-usb-stage-036a")
MANIFEST_REL = "MANIFESTS/helix-bios-toolkit-v1-files.json"
MANIFEST_SHA256 = "65e26db573120d091620aa57f9df75646c1917e02a2cfd01b4b014bef2f0655a"
FOUNDATION_COMMIT = "036a834d1d0f8292a6fea7420c04123de58e7a0d"
USB_UUID = "2AF8-4CD6"
USB_LABEL = "HELIX-BIOS"
USB_FSTYPE = "vfat"
USB_MOUNT = "/mnt/helix-bios"
USB_MODEL_TOKEN = "cruzer pop"
USB_MIN_BYTES = 7_000_000_000
USB_MAX_BYTES = 9_000_000_000
PROCEDURE_PATH = "DOCUMENTATION/LORE_BIOS_CAPTURE_PRINTABLE.html"
PROCEDURE_SHA256 = "840de33cac6109a453e08baecd1c8e9721e6abf8176763ceed34068a285954e9"
README_SHA256 = "d54bc3bf1cdce8e36128a9ce6ab34cf3c6b1629e998c149fad2d9bd3032689a1"
EXPECTED_INITIAL_DIRECTORY_COUNT = 16

SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
SSH_CONFIG = Path("/home/louis/.ssh/config")
REMOTE_INVENTORY_CODE = r'''import hashlib,json,os,stat,sys
root="/mnt/helix-bios"
if not os.path.isdir(root) or os.path.islink(root): raise SystemExit("FAIL mount root is not a real directory")
files={}; dirs=[]; folded={}
def addfold(p):
 k=p.casefold()
 if k in folded and folded[k]!=p: raise SystemExit("FAIL FAT case-fold collision")
 folded[k]=p
def walk(path,rel=""):
 with os.scandir(path) as entries:
  for e in sorted(entries,key=lambda x:x.name.casefold()):
   rp=(rel+"/"+e.name).lstrip("/"); st=e.stat(follow_symlinks=False); addfold(rp)
   if stat.S_ISLNK(st.st_mode): raise SystemExit("FAIL symlink on media")
   if stat.S_ISDIR(st.st_mode): dirs.append(rp); walk(e.path,rp)
   elif stat.S_ISREG(st.st_mode):
    h=hashlib.sha256()
    with open(e.path,"rb") as f:
     for b in iter(lambda:f.read(1048576),b""): h.update(b)
    files[rp]={"size_bytes":st.st_size,"sha256":h.hexdigest()}
   else: raise SystemExit("FAIL special file on media")
walk(root)
obj={"files":files,"directories":sorted(dirs)}
print(json.dumps(obj,sort_keys=True,separators=(",",":")))
'''


class DeploymentError(Exception):
    pass


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            h.update(block)
    return size, h.hexdigest()


def require_no_symlink_components(path: Path) -> None:
    try:
        rel = path.relative_to(STAGE)
    except ValueError as exc:
        raise DeploymentError(f"staged path escapes package root: {path}") from exc
    if STAGE.is_symlink() or not STAGE.is_dir():
        raise DeploymentError("staging root is missing or a symlink")
    current = STAGE
    for component in rel.parts:
        current = current / component
        if current.is_symlink():
            raise DeploymentError(f"symlink in staged package path: {current}")


def run_captured(argv: list[str], *, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            argv, input=input_text, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
    except OSError as exc:
        raise DeploymentError(f"cannot run {argv[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise DeploymentError(f"command failed ({argv[0]}): {detail}")
    return result.stdout


def ssh_capture(remote_script: str) -> str:
    remote_command = "bash -lc " + shlex.quote(remote_script)
    return run_captured(["ssh", "-F", str(SSH_CONFIG), *SSH_OPTIONS, "hv-lore", remote_command])


def ssh_privileged(remote_script: str, *, brc_operation: bool = False) -> int:
    if brc_operation:
        remote_command = "sudo -n bash -c " + shlex.quote(remote_script)
        try:
            result = subprocess.run(
                ["ssh", "-F", str(SSH_CONFIG), *SSH_OPTIONS, "hv-lore", remote_command],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, check=False,
            )
        except OSError as exc:
            raise DeploymentError(f"cannot run non-interactive SSH: {exc}") from exc
        if result.stdout:
            print(result.stdout, end="")
        return result.returncode
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise DeploymentError("run this command from an interactive authorized terminal so Lore sudo can prompt")
    remote_command = "sudo bash -c " + shlex.quote(remote_script)
    print("Lore may prompt for your authorized sudo password in this terminal.", flush=True)
    try:
        result = subprocess.run(
            ["ssh", "-tt", "-F", str(SSH_CONFIG), *SSH_OPTIONS, "hv-lore", remote_command],
            check=False,
        )
    except OSError as exc:
        raise DeploymentError(f"cannot run SSH: {exc}") from exc
    return result.returncode


def validate_manifest() -> tuple[list[dict], str]:
    manifest_path = STAGE / MANIFEST_REL
    sidecar_path = STAGE / "MANIFESTS/helix-bios-toolkit-v1-files.json.sha256"
    for path in (manifest_path, sidecar_path):
        require_no_symlink_components(path)
        if not path.is_file():
            raise DeploymentError(f"missing or unsafe staged manifest: {path}")
    manifest_bytes = manifest_path.read_bytes()
    actual_manifest_hash = digest_bytes(manifest_bytes)
    if actual_manifest_hash != MANIFEST_SHA256:
        raise DeploymentError("deployment manifest SHA-256 does not match the pinned runbook value")
    sidecar = sidecar_path.read_text(encoding="ascii").strip()
    if sidecar != f"{MANIFEST_SHA256}  helix-bios-toolkit-v1-files.json":
        raise DeploymentError("manifest checksum sidecar does not match its pinned SHA-256")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"deployment manifest is invalid JSON: {exc}") from exc
    if manifest.get("foundation_source_commit") != FOUNDATION_COMMIT:
        raise DeploymentError("manifest does not identify merged Foundation PR #7 source commit")
    if manifest.get("usb_uuid") != USB_UUID or manifest.get("artifact_count") != 25:
        raise DeploymentError("manifest target UUID or artifact count differs from approved deployment")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 25:
        raise DeploymentError("manifest does not contain exactly 25 artifacts")

    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise DeploymentError("invalid manifest artifact record")
        rel = item.get("path")
        if not isinstance(rel, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", rel):
            raise DeploymentError(f"unsafe manifest path: {rel!r}")
        pure = PurePosixPath(rel)
        if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
            raise DeploymentError(f"manifest path escapes package root: {rel}")
        folded = rel.casefold()
        if folded in seen:
            raise DeploymentError(f"case-insensitive manifest path collision: {rel}")
        seen.add(folded)
        source = STAGE / rel
        require_no_symlink_components(source)
        if not source.is_file():
            raise DeploymentError(f"missing or unsafe staged artifact: {rel}")
        size, sha = digest_file(source)
        if size != item.get("size_bytes") or sha != item.get("sha256"):
            raise DeploymentError(f"staged size or SHA-256 mismatch: {rel}")

    procedure = next((x for x in artifacts if x["path"] == PROCEDURE_PATH), None)
    if not procedure or procedure.get("sha256") != PROCEDURE_SHA256:
        raise DeploymentError("approved printable procedure is missing or has an unexpected digest")
    return artifacts, actual_manifest_hash


def validate_hp_manifest(artifacts: list[dict]) -> None:
    hp_path = STAGE / "MANIFESTS/hp-z840-deployed-files.json"
    require_no_symlink_components(hp_path)
    try:
        hp = json.loads(hp_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"HP artifact manifest cannot be read: {exc}") from exc
    entries = hp.get("artifacts")
    if not isinstance(entries, list) or len(entries) != 3:
        raise DeploymentError("HP artifact manifest does not contain the three reviewed packages")
    listed = {x["path"].casefold(): x for x in artifacts}
    for entry in entries:
        rel = entry.get("path")
        if (entry.get("execution_class") != "firmware_flasher" or
                not isinstance(rel, str) or rel.casefold() not in listed):
            raise DeploymentError("HP package classification or path is not in the approved deployment manifest")
        approved = listed[rel.casefold()]
        if (entry.get("sha256") != approved.get("sha256") or
                entry.get("size_bytes") != approved.get("size_bytes")):
            raise DeploymentError(f"HP package manifest mismatch: {rel}")


def remote_identity() -> dict:
    output = ssh_capture("printf '%s\\n' \"$(hostname -s)\" \"$(id -un)\" \"$(id -u)\" \"$(id -g)\"")
    lines = output.splitlines()
    if len(lines) != 4 or lines[0] != "hv-lore" or lines[1] != "louis":
        raise DeploymentError("SSH identity is not the approved hv-lore/louis target")
    try:
        uid, gid = int(lines[2]), int(lines[3])
    except ValueError as exc:
        raise DeploymentError("Lore returned invalid user/group IDs") from exc
    return {"uid": uid, "gid": gid}


def select_usb_device(block_data: dict) -> tuple[dict, dict]:
    """Return (parent disk, UUID-bearing partition) from lsblk's nested tree."""
    matches: list[tuple[dict, dict | None]] = []

    def visit(nodes: list[dict], parent: dict | None = None) -> None:
        for node in nodes:
            if (node.get("uuid") or "").upper() == USB_UUID:
                matches.append((node, parent))
            visit(node.get("children") or [], node)

    visit(block_data.get("blockdevices") or [])
    if len(matches) != 1:
        raise DeploymentError(f"USB UUID resolved to {len(matches)} block entries; expected exactly one")
    partition, disk = matches[0]
    if not disk or partition.get("type") != "part" or disk.get("type") != "disk":
        raise DeploymentError("USB UUID must identify a partition with a physical parent disk")
    if (partition.get("label") != USB_LABEL or partition.get("fstype") != USB_FSTYPE or
            not USB_MIN_BYTES <= int(partition.get("size") or 0) <= USB_MAX_BYTES):
        raise DeploymentError("USB partition does not have the expected UUID, HELIX-BIOS label, FAT32 type, and capacity")
    model = (disk.get("model") or "").strip().casefold()
    if (USB_MODEL_TOKEN not in model or
            not USB_MIN_BYTES <= int(disk.get("size") or 0) <= USB_MAX_BYTES):
        raise DeploymentError("USB parent disk does not have the expected SanDisk model and capacity")
    return disk, partition


def has_private_fat_masks(options: set[str]) -> bool:
    # Linux reports umask=077 as the equivalent FAT masks after mounting.
    return "umask=077" in options or {"fmask=0077", "dmask=0077"}.issubset(options)


def remote_media(identity: dict, *, expected_mode: str = "ro", require_hardened: bool = False) -> dict:
    script = (
        "lsblk --tree -b -J -o NAME,PATH,UUID,LABEL,FSTYPE,SIZE,MODEL,TYPE; "
        "printf '\\n--FINDMNT--\\n'; "
        f"findmnt -J -S UUID={USB_UUID} -o SOURCE,TARGET,FSTYPE,OPTIONS"
    )
    output = ssh_capture(script)
    try:
        first, mounts_text = output.split("\n--FINDMNT--\n", 1)
        block_data = json.loads(first)
        mount_data = json.loads(mounts_text)
    except (ValueError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"could not parse Lore filesystem identity: {exc}") from exc

    disk, partition = select_usb_device(block_data)
    mounts = mount_data.get("filesystems") or []
    if len(mounts) != 1:
        raise DeploymentError(f"UUID has {len(mounts)} mounts; expected exactly one")
    mount = mounts[0]
    options = set((mount.get("options") or "").split(","))
    if (mount.get("target") != USB_MOUNT or mount.get("fstype") != USB_FSTYPE or
            expected_mode not in options):
        raise DeploymentError(f"USB is not mounted {expected_mode} at /mnt/helix-bios")
    if require_hardened:
        required = {expected_mode, "nosuid", "nodev", "noexec", f"uid={identity['uid']}", f"gid={identity['gid']}"}
        if not required.issubset(options) or not has_private_fat_masks(options):
            raise DeploymentError("FAT mount lacks the required mode, ownership, or private-file restrictions")
    return {"disk": disk, "partition": partition, "mount": mount,
            "uid": identity["uid"], "gid": identity["gid"]}


def remote_inventory() -> dict:
    code = __import__("base64").b64encode(REMOTE_INVENTORY_CODE.encode()).decode("ascii")
    output = ssh_capture(f"python3 -c 'import base64;exec(base64.b64decode(\"{code}\"))'")
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise DeploymentError(f"USB inventory result is invalid: {exc}") from exc
    if not isinstance(result.get("files"), dict) or not isinstance(result.get("directories"), list):
        raise DeploymentError("USB inventory is incomplete")
    return result


def inventory_digest(inventory: dict) -> str:
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return digest_bytes(encoded)


def validate_initial_inventory(inventory: dict, artifacts: list[dict]) -> None:
    files = inventory["files"]
    dirs = inventory["directories"]
    if len(dirs) != EXPECTED_INITIAL_DIRECTORY_COUNT:
        raise DeploymentError(f"USB directory inventory changed from the runbook baseline ({len(dirs)} vs {EXPECTED_INITIAL_DIRECTORY_COUNT})")
    allowed = {"README.txt"} | {x["path"] for x in artifacts}
    unexpected = sorted(set(files) - allowed)
    if unexpected:
        raise DeploymentError("USB contains unexpected files; no writes made")
    readme = files.get("README.txt")
    if not readme or readme.get("sha256") != README_SHA256:
        raise DeploymentError("existing README.txt is missing or differs from its protected runbook hash")
    procedure = files.get(PROCEDURE_PATH)
    if not procedure or procedure.get("sha256") != PROCEDURE_SHA256:
        raise DeploymentError("existing printable procedure is missing or differs from its protected hash")
    expected = {x["path"]: {"size_bytes": x["size_bytes"], "sha256": x["sha256"]} for x in artifacts}
    for rel, value in files.items():
        if rel == "README.txt":
            continue
        if value != expected.get(rel):
            raise DeploymentError(f"existing manifest-listed file differs; no overwrite permitted: {rel}")


def validate_post_inventory(before: dict, after: dict, artifacts: list[dict]) -> None:
    before_files = before["files"]
    after_files = after["files"]
    for rel, value in before_files.items():
        if after_files.get(rel) != value:
            raise DeploymentError(f"pre-existing USB file changed or disappeared: {rel}")
    expected = {x["path"]: {"size_bytes": x["size_bytes"], "sha256": x["sha256"]} for x in artifacts}
    for rel, value in expected.items():
        if after_files.get(rel) != value:
            raise DeploymentError(f"deployed artifact missing or changed: {rel}")
    permitted_files = set(before_files) | set(expected)
    if set(after_files) != permitted_files:
        raise DeploymentError("USB file inventory contains unexpected additions or missing files")
    before_dirs = set(before["directories"])
    after_dirs = set(after["directories"])
    if not before_dirs.issubset(after_dirs):
        raise DeploymentError("pre-existing USB directory disappeared")
    expected_dirs = set()
    for item in artifacts:
        parent = PurePosixPath(item["path"]).parent
        while str(parent) != ".":
            expected_dirs.add(str(parent))
            parent = parent.parent
    if after_dirs - before_dirs - expected_dirs:
        raise DeploymentError("unexpected directories appeared on USB")


def privileged_mount_rw(identity: dict) -> str:
    uid, gid = identity["uid"], identity["gid"]
    return f'''set -u
src=/dev/disk/by-uuid/{USB_UUID}
mnt={USB_MOUNT}
test "$(hostname -s)" = hv-lore || exit 11
test "$(id -un)" = root || exit 12
test "$(blkid -s UUID -o value "$src" 2>/dev/null)" = {USB_UUID} || exit 13
test "$(blkid -s LABEL -o value "$src" 2>/dev/null)" = {USB_LABEL} || exit 14
test "$(blkid -s TYPE -o value "$src" 2>/dev/null)" = {USB_FSTYPE} || exit 15
test "$(findmnt -rn -S UUID={USB_UUID} -o TARGET)" = "$mnt" || exit 16
test "$(findmnt -rn -S UUID={USB_UUID} -o FSTYPE)" = {USB_FSTYPE} || exit 17
opts=$(findmnt -rn -S UUID={USB_UUID} -o OPTIONS) || exit 18
case ",$opts," in *,ro,*) ;; *) exit 19 ;; esac
mount -t vfat -o "remount,rw,nosuid,nodev,noexec,uid={uid},gid={gid},umask=077" "$src" "$mnt"
'''


def privileged_restore_ro(identity: dict) -> str:
    uid, gid = identity["uid"], identity["gid"]
    return f'''set -u
src=/dev/disk/by-uuid/{USB_UUID}
mnt={USB_MOUNT}
test "$(hostname -s)" = hv-lore || exit 21
test "$(id -un)" = root || exit 22
test "$(blkid -s UUID -o value "$src" 2>/dev/null)" = {USB_UUID} || exit 23
test "$(blkid -s LABEL -o value "$src" 2>/dev/null)" = {USB_LABEL} || exit 24
test "$(blkid -s TYPE -o value "$src" 2>/dev/null)" = {USB_FSTYPE} || exit 25
test "$(findmnt -rn -S UUID={USB_UUID} -o TARGET)" = "$mnt" || exit 26
test "$(findmnt -rn -S UUID={USB_UUID} -o FSTYPE)" = {USB_FSTYPE} || exit 27
opts=$(findmnt -rn -S UUID={USB_UUID} -o OPTIONS) || exit 28
case ",$opts," in *,rw,*) ;; *) exit 29 ;; esac
sync && umount "$mnt" && mount -t vfat -o "ro,nosuid,nodev,noexec,uid={uid},gid={gid},umask=077" "$src" "$mnt"
'''


def final_mount_state() -> dict | None:
    try:
        output = ssh_capture(f"findmnt -J -S UUID={USB_UUID} -o SOURCE,TARGET,FSTYPE,OPTIONS")
        data = json.loads(output)
        filesystems = data.get("filesystems") or []
        if len(filesystems) == 1:
            return filesystems[0]
    except (DeploymentError, json.JSONDecodeError):
        return None
    return None


def consume_brc_operation(operation: str) -> bool:
    token = os.environ.pop("HELIX_BRC_OPERATION_TOKEN", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", token):
        raise DeploymentError("missing one-use local operator capability")
    runtime = f"/run/user/{os.getuid()}"
    socket_path = Path(runtime) / "helix-brc-operator.sock"
    request = json.dumps({"action": "consume", "token": token, "operation": operation}, separators=(",", ":")) + "\n"
    result = subprocess.run(
        ["python3", str(Path(__file__).with_name("helix-bios-control.py")), "broker-request", str(socket_path)],
        input=request, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise DeploymentError("operator broker refused the fixed operation")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DeploymentError("operator broker returned invalid authorization") from exc
    if not response.get("ok") or not response.get("result", {}).get("allowed"):
        raise DeploymentError("operator broker refused the fixed operation")
    return True


def handle_termination(_signum, _frame) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--brc-operation", choices=("transfer_manifest",))
    args = parser.parse_args()
    brc_operation = args.brc_operation is not None
    if brc_operation:
        signal.signal(signal.SIGTERM, handle_termination)
    mounted_rw = False
    restored = False
    identity: dict | None = None
    try:
        if brc_operation:
            consume_brc_operation(args.brc_operation)
        if shutil.which("ssh") is None or shutil.which("rsync") is None:
            raise DeploymentError("ssh and rsync must already be installed; this script installs nothing")
        if SSH_CONFIG.is_symlink() or not SSH_CONFIG.is_file():
            raise DeploymentError("the existing Hadrian user SSH config is missing or unsafe")
        config_stat = SSH_CONFIG.stat()
        if config_stat.st_uid != os.getuid() or config_stat.st_nlink != 1 or config_stat.st_mode & 0o077:
            raise DeploymentError("the existing Hadrian user SSH config must be owner-owned and mode 0600 or stricter")
        artifacts, manifest_hash = validate_manifest()
        validate_hp_manifest(artifacts)
        print(f"PASS staged source: Foundation {FOUNDATION_COMMIT}; {len(artifacts)} manifest artifacts; manifest SHA-256 {manifest_hash}")

        identity = remote_identity()
        media = remote_media(identity)
        print("PASS Lore identity and UUID 2AF8-4CD6: HELIX-BIOS, vfat, SanDisk Cruzer Pop, approximately 7.5 GB")
        before = remote_inventory()
        validate_initial_inventory(before, artifacts)
        before_hash = inventory_digest(before)
        print(f"PASS protected pre-deployment inventory: {len(before['files'])} files, {len(before['directories'])} directories, inventory SHA-256 {before_hash}")

        if not brc_operation:
            answer = input("Type INSTALL to remount this UUID read-write and install the 25 listed artifacts: ").strip()
            if answer != "INSTALL":
                raise DeploymentError("operator did not confirm installation")

        rc = ssh_privileged(privileged_mount_rw(identity), brc_operation=brc_operation)
        state = final_mount_state()
        state_options = set((state.get("options") or "").split(",")) if state else set()
        if "rw" in state_options:
            mounted_rw = True
        if rc != 0:
            raise DeploymentError(f"UUID-scoped read-write remount failed (ssh exit {rc})")
        if not state or state.get("target") != USB_MOUNT or state.get("fstype") != USB_FSTYPE or "rw" not in state_options:
            raise DeploymentError("read-write remount did not produce the expected verified mount state")
        remote_media(identity, expected_mode="rw", require_hardened=True)
        check = remote_inventory()
        if check != before:
            raise DeploymentError("USB content changed between read-only preflight and read-write remount; no transfer attempted")

        paths = "\n".join(x["path"] for x in artifacts) + "\n"
        rsync_cmd = [
            "rsync", "-rt", "--ignore-existing", "--no-perms", "--no-owner", "--no-group",
            "--omit-dir-times", "--files-from=-", "-e",
            f"ssh -F {SSH_CONFIG} -o BatchMode=yes -o ConnectTimeout=10",
            f"{STAGE}/", f"hv-lore:{USB_MOUNT}/",
        ]
        try:
            copied = subprocess.run(rsync_cmd, input=paths, text=True, check=False)
        except OSError as exc:
            raise DeploymentError(f"cannot run rsync: {exc}") from exc
        if copied.returncode != 0:
            raise DeploymentError(f"rsync failed with exit {copied.returncode}; partial new files, if any, are preserved for inspection")

        after_copy = remote_inventory()
        validate_post_inventory(before, after_copy, artifacts)
        print(f"PASS mounted read-write verification: all {len(artifacts)} artifact hashes and sizes match; old files unchanged")

        rc = ssh_privileged(privileged_restore_ro(identity), brc_operation=brc_operation)
        state = final_mount_state()
        if rc != 0:
            mounted_rw = bool(state and "rw" in (state.get("options") or "").split(","))
            if state is None:
                print("NOTICE: filesystem may be cleanly unmounted; inspect with findmnt by UUID before further action")
            raise DeploymentError(f"sync/unmount/read-only remount command returned {rc}")
        mounted_rw = False
        restored = bool(state and state.get("target") == USB_MOUNT and state.get("fstype") == USB_FSTYPE and "ro" in (state.get("options") or "").split(","))
        if not restored:
            raise DeploymentError("filesystem was not verified read-only at the approved mountpoint after remount")

        final = remote_inventory()
        validate_post_inventory(before, final, artifacts)
        final_media = remote_media(identity, expected_mode="ro", require_hardened=True)
        if (final_media["partition"].get("uuid") or "").upper() != USB_UUID:
            raise DeploymentError("USB UUID changed after remount")
        print(f"PASS post-remount read-only verification: {len(artifacts)} artifacts; printable procedure SHA-256 {PROCEDURE_SHA256}")
        print(f"PASS filesystem remains read-only at {USB_MOUNT}; before inventory SHA-256 {before_hash}; after inventory SHA-256 {inventory_digest(final)}")
        print("No firmware utilities were executed. No BIOS, Proxmox, VM, service, or host configuration was changed; Lore was not rebooted.")
        return 0
    except (DeploymentError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("INTERRUPTED: deployment stopped; checking whether the verified USB needs read-only restoration", file=sys.stderr)
        try:
            state = final_mount_state()
            mounted_rw = bool(state and "rw" in (state.get("options") or "").split(","))
        except Exception:
            mounted_rw = False
        return 130
    finally:
        if mounted_rw and identity is not None and not restored:
            print("RECOVERY: attempting sync, clean unmount, and UUID-based read-only remount", file=sys.stderr, flush=True)
            try:
                rc = ssh_privileged(privileged_restore_ro(identity), brc_operation=brc_operation)
                state = final_mount_state()
                if rc == 0 and state and "ro" in (state.get("options") or "").split(",") and state.get("target") == USB_MOUNT:
                    print("RECOVERY PASS: HELIX-BIOS is mounted read-only")
                elif state is None:
                    print("RECOVERY NOTICE: volume appears unmounted; do not remount read-write")
                else:
                    print("RECOVERY FAIL: inspect the UUID mount state manually before further action")
            except Exception as exc:
                print(f"RECOVERY FAIL: {exc}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
