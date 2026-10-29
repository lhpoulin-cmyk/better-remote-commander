#!/usr/bin/env python3
"""Local-session broker for the fixed HELIX-BIOS operator grant.

The grant lives only in this process's memory. BRC's Node process can query
and authorize fixed operations; activation and revocation require a peer in a
Hadrian logind session with a real terminal. Restarting the agent clears it.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import socketserver
import stat
import sys
import time
from typing import Any

PRINCIPAL = "louis"
TARGET = "hv-lore"
WORK_ENTRY = "070"
USB_UUID = "2AF8-4CD6"
MOUNTPOINT = "/mnt/helix-bios"
MANIFEST_SHA256 = "65e26db573120d091620aa57f9df75646c1917e02a2cfd01b4b014bef2f0655a"
MAX_SECONDS = 30 * 60
OPERATIONS = ("transfer_manifest",)
CONFIRMATION = "ENABLE WE070 HELIX-BIOS FOR 30 MINUTES"
POLICY_RELEASE = "we071-helix-bios-v1"
EXPECTED_AGENT_VERSION = "0.2.50"
def _proc_uid(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _proc_identity(pid: int) -> tuple[int, int] | None:
    """Return (uid, starttime) to distinguish the agent from a reused PID."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        after = raw[raw.rfind(")") + 2:].split()
        state = after[0]
        starttime = int(after[19])
        uid = _proc_uid(pid)
        if uid is None or state == "Z":
            return None
        return uid, starttime
    except (OSError, ValueError, IndexError):
        return None


def _proc_cgroups(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cgroup").read_text()
    except OSError:
        return ""


def _has_interactive_login_session(pid: int) -> bool:
    """Reject service children, PTYs created for remote tools, and non-TTY callers."""
    try:
        fd0 = os.stat(f"/proc/{pid}/fd/0")
        tty_link = os.readlink(f"/proc/{pid}/fd/0")
    except OSError:
        return False
    if not stat.S_ISCHR(fd0.st_mode) or not tty_link.startswith("/dev/pts/"):
        return False
    groups = _proc_cgroups(pid)
    return bool(re.search(r"(?:^|/)session-[0-9]+\.scope(?:/|$)", groups, re.MULTILINE))


class GrantState:
    def __init__(self, agent_pid: int, agent_release: str, state_path: Path):
        self.agent_pid = agent_pid
        self.agent_identity: tuple[int, int] | None = None
        self.agent_release = agent_release
        self.state_path = state_path
        self.grant: dict[str, Any] | None = None
        self.started_monotonic: float | None = None
        self.started_wall: float | None = None
        self.current_fingerprint: str | None = None
        self.blocked_commands: tuple[str, ...] = ()
        self.operation_tokens: dict[str, tuple[str, float]] = {}
        self.operation_used = False
        self.audit_path = state_path.with_name("helix-bios-operator-audit.jsonl")

    def _audit(self, action: str, reason: str | None = None) -> None:
        record = {"at": datetime.now(timezone.utc).isoformat(), "action": action,
                  "principal": PRINCIPAL, "work_entry": WORK_ENTRY,
                  "target": TARGET, "uuid": USB_UUID}
        if reason:
            record["reason"] = reason[:160]
        self.audit_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.audit_path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    info.st_nlink != 1 or info.st_mode & 0o077):
                raise OSError("operator audit file is not a private owner-owned regular file")
            payload = memoryview((json.dumps(record, sort_keys=True) + "\n").encode())
            while payload:
                payload = payload[os.write(fd, payload):]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _expire_if_needed(self, fingerprint: str | None = None) -> None:
        if not self.grant:
            return
        reason = None
        if self.agent_release != POLICY_RELEASE:
            reason = "agent_release_changed"
        elif self.started_monotonic is None or time.monotonic() >= self.started_monotonic + MAX_SECONDS:
            reason = "expired"
        elif self.started_wall is None or abs((time.time() - self.started_wall) -
                                              (time.monotonic() - self.started_monotonic)) > 5:
            reason = "clock_changed"
        elif fingerprint is not None and fingerprint != self.grant["policy_fingerprint"]:
            reason = "policy_drift"
        if reason:
            self.grant = None
            self.started_monotonic = None
            self.started_wall = None
            self.operation_tokens.clear()
            self.operation_used = False
            self._audit("revoked", reason)

    def status(self, fingerprint: str | None = None) -> dict[str, Any]:
        self._expire_if_needed(fingerprint if fingerprint is not None else self.current_fingerprint)
        if not self.grant:
            return {"active": False, "effective_operations": [], "policy_release": POLICY_RELEASE}
        return {"active": True, "grant": self.grant.copy(),
                "effective_operations": list(OPERATIONS), "policy_release": POLICY_RELEASE}

    def activate(self, peer_pid: int, peer_uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if (os.uname().nodename.split(".")[0] != "ws-hadrian" or
                pwd.getpwuid(os.getuid()).pw_name != PRINCIPAL):
            raise ValueError("activation is supported only on ws-hadrian")
        if peer_uid != os.getuid() or peer_uid != _proc_uid(peer_pid):
            raise ValueError("operator principal mismatch")
        if not _has_interactive_login_session(peer_pid):
            raise ValueError("activation requires Louis's interactive local login terminal")
        if request.get("confirmation") != CONFIRMATION:
            raise ValueError("explicit confirmation did not match")
        if request.get("duration_seconds") != MAX_SECONDS:
            raise ValueError("grant duration is fixed at 30 minutes")
        if request.get("policy_release") != POLICY_RELEASE or self.agent_release != POLICY_RELEASE:
            raise ValueError("unexpected BRC policy release")
        fingerprint = self.current_fingerprint
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("invalid global-policy fingerprint")
        if not {"sudo", "mount", "umount"}.issubset(self.blocked_commands):
            raise ValueError("required global command blocks are not effective")
        grant = {
            "grant_id": secrets.token_hex(16),
            "principal": PRINCIPAL,
            "target": TARGET,
            "work_entry": WORK_ENTRY,
            "usb_uuid": USB_UUID,
            "mountpoint": MOUNTPOINT,
            "manifest_sha256": MANIFEST_SHA256,
            "operations": list(OPERATIONS),
            "expires_at": int(time.time()) + MAX_SECONDS,
            "policy_fingerprint": fingerprint,
            "policy_release": POLICY_RELEASE,
        }
        self._audit("activated")
        self.grant = grant
        self.operation_tokens.clear()
        self.operation_used = False
        self.started_monotonic = time.monotonic()
        self.started_wall = time.time()
        return self.status(fingerprint)

    def revoke(self, peer_pid: int, peer_uid: int) -> dict[str, Any]:
        if (os.uname().nodename.split(".")[0] != "ws-hadrian" or
                pwd.getpwuid(os.getuid()).pw_name != PRINCIPAL):
            raise ValueError("control is supported only on ws-hadrian")
        if peer_uid != os.getuid() or peer_uid != _proc_uid(peer_pid):
            raise ValueError("operator principal mismatch")
        if not _has_interactive_login_session(peer_pid):
            raise ValueError("revocation requires Louis's interactive local login terminal")
        if self.grant:
            self.grant = None
            self.started_monotonic = None
            self.started_wall = None
            self.operation_tokens.clear()
            self.operation_used = False
            self._audit("revoked", "operator_off")
        return self.status()

    def authorize(self, peer_pid: int, request: dict[str, Any]) -> dict[str, Any]:
        if peer_pid != self.agent_pid:
            raise ValueError("policy checks are restricted to the BRC agent process")
        self.update_policy(peer_pid, request)
        state = self.status()
        operation = request.get("operation")
        now = time.monotonic()
        self.operation_tokens = {token: record for token, record in self.operation_tokens.items()
                                 if now < record[1] and self.grant is not None and
                                 record[2] == self.grant["grant_id"]}
        allowed = bool(state["active"] and operation in OPERATIONS and
                       not self.operation_used and not self.operation_tokens)
        token = None
        if allowed:
            token = secrets.token_urlsafe(32)
            self.operation_tokens[token] = (operation, now + 10.0, state["grant"]["grant_id"])
        return {"allowed": allowed, "state": state, "operation_token": token}

    def consume(self, peer_pid: int, peer_uid: int, request: dict[str, Any]) -> dict[str, Any]:
        if (peer_uid != os.getuid() or peer_uid != _proc_uid(peer_pid) or
                not self._is_agent_descendant(peer_pid)):
            raise ValueError("operation token consumption is restricted to a fixed BRC child process")
        self._expire_if_needed()
        token = request.get("token")
        operation = request.get("operation")
        record = self.operation_tokens.pop(token, None) if isinstance(token, str) else None
        if (not record or record[0] != operation or time.monotonic() >= record[1] or
                not self.grant or record[2] != self.grant["grant_id"]):
            raise ValueError("operator capability is missing, expired, or already consumed")
        if operation not in self.grant["operations"]:
            raise ValueError("operation is outside the active grant")
        self.operation_used = True
        return {"allowed": True, "operation": operation}

    def _is_agent_descendant(self, pid: int) -> bool:
        current = pid
        for _ in range(16):
            if current == self.agent_pid:
                return True
            try:
                data = Path(f"/proc/{current}/stat").read_text()
                after = data[data.rfind(")") + 2:].split()
                current = int(after[1])  # ppid follows state in /proc/PID/stat
            except (OSError, ValueError, IndexError):
                return False
            if current <= 1:
                return False
        return False

    def update_policy(self, peer_pid: int, request: dict[str, Any]) -> dict[str, Any]:
        if peer_pid != self.agent_pid:
            raise ValueError("policy refresh is restricted to the BRC agent process")
        if request.get("policy_release") != self.agent_release or self.agent_release != POLICY_RELEASE:
            if self.grant:
                self.grant = None
                self.started_monotonic = None
                self.started_wall = None
                self.operation_tokens.clear()
                self.operation_used = False
                self._audit("revoked", "agent_release_changed")
            raise ValueError("unexpected BRC policy release")
        fingerprint = request.get("policy_fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("invalid global-policy fingerprint")
        blocked = request.get("blocked_commands")
        if (not isinstance(blocked, list) or not all(isinstance(x, str) for x in blocked) or
                not {"sudo", "mount", "umount"}.issubset(blocked)):
            if self.grant:
                self.grant = None
                self.started_monotonic = None
                self.started_wall = None
                self.operation_tokens.clear()
                self.operation_used = False
                self._audit("revoked", "required_global_block_missing")
            raise ValueError("required global command blocks are not effective")
        self.current_fingerprint = fingerprint
        self.blocked_commands = tuple(blocked)
        self._expire_if_needed(fingerprint)
        return self.status()


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        peer_pid = int.from_bytes(creds[0:4], sys.byteorder, signed=True)
        peer_uid = int.from_bytes(creds[4:8], sys.byteorder, signed=False)
        raw = self.rfile.readline(8193)
        try:
            if len(raw) > 8192 or not raw.endswith(b"\n"):
                raise ValueError("invalid request size")
            request = json.loads(raw)
            if not isinstance(request, dict) or not isinstance(request.get("action"), str):
                raise ValueError("invalid request")
            action = request["action"]
            exact_fields = {
                "activate": {"action", "confirmation", "duration_seconds", "policy_release"},
                "revoke": {"action"},
                "status": {"action"},
                "authorize": {"action", "policy_release", "policy_fingerprint", "blocked_commands", "operation"},
                "agent_state": {"action", "policy_release", "policy_fingerprint", "blocked_commands"},
                "consume": {"action", "token", "operation"},
            }
            if action not in exact_fields or set(request) != exact_fields[action]:
                raise ValueError("request fields do not match the fixed operation schema")
            state: GrantState = self.server.state  # type: ignore[attr-defined]
            if action == "activate":
                result = state.activate(peer_pid, peer_uid, request)
            elif action == "revoke":
                result = state.revoke(peer_pid, peer_uid)
            elif action == "status":
                if peer_pid != state.agent_pid and not _has_interactive_login_session(peer_pid):
                    raise ValueError("status is available only to the agent or a local login terminal")
                result = state.status(request.get("policy_fingerprint"))
            elif action == "authorize":
                result = state.authorize(peer_pid, request)
            elif action == "agent_state":
                result = state.update_policy(peer_pid, request)
            elif action == "consume":
                result = state.consume(peer_pid, peer_uid, request)
            else:
                raise ValueError("unknown action")
            response = {"ok": True, "result": result}
        except Exception as exc:
            response = {"ok": False, "error": str(exc)[:240]}
        self.wfile.write((json.dumps(response, sort_keys=True) + "\n").encode())


class BrokerServer(socketserver.UnixStreamServer):
    allow_reuse_address = False

    def __init__(self, address: str, state: GrantState):
        self.state = state
        super().__init__(address, BrokerHandler)

    def service_actions(self) -> None:
        # Expiration is enforced even while no tools or terminal are active.
        self.state.status()
        expected = self.state.agent_identity
        if expected is not None and _proc_identity(self.state.agent_pid) != expected:
            if self.state.grant:
                self.state.grant = None
                self.state.operation_tokens.clear()
                self.state.operation_used = False
                self.state._audit("revoked", "agent_process_ended_or_replaced")
            raise SystemExit(0)


def request(socket_path: Path, obj: dict[str, Any]) -> dict[str, Any]:
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(str(socket_path))
        client.sendall(data)
        response = b""
        while not response.endswith(b"\n") and len(response) <= 8192:
            chunk = client.recv(1024)
            if not chunk:
                break
            response += chunk
    if len(response) > 8192:
        raise RuntimeError("oversized broker response")
    result = json.loads(response)
    if not result.get("ok"):
        raise RuntimeError(result.get("error", "operator control refused"))
    return result["result"]


def run_broker(args: argparse.Namespace) -> int:
    if (sys.platform != "linux" or os.uname().nodename.split(".")[0] != "ws-hadrian" or
            pwd.getpwuid(os.getuid()).pw_name != PRINCIPAL or args.release != POLICY_RELEASE or
            args.agent_version != EXPECTED_AGENT_VERSION):
        print("broker refused: supported only on Linux ws-hadrian", file=sys.stderr)
        return 2
    socket_path = Path(args.socket)
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = socket_path.parent.stat()
    if socket_path.parent.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        print("broker refused: unsafe BRC configuration directory", file=sys.stderr)
        return 2
    if socket_path.exists() or socket_path.is_symlink():
        if socket_path.is_symlink() or not stat.S_ISSOCK(socket_path.lstat().st_mode):
            print("broker refused: unsafe existing socket path", file=sys.stderr)
            return 2
        socket_path.unlink()
    state = GrantState(args.agent_pid, args.release, Path(args.state))
    state.agent_identity = _proc_identity(args.agent_pid)
    if state.agent_identity is None or state.agent_identity[0] != os.getuid():
        print("broker refused: BRC agent process identity is unavailable or belongs to another user", file=sys.stderr)
        return 2
    server = BrokerServer(str(socket_path), state)
    os.chmod(socket_path, 0o600)
    print(json.dumps({"ready": True, "release": POLICY_RELEASE}), flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
    return 0


def _local_request(socket_path: Path, action: str) -> dict[str, Any]:
    obj: dict[str, Any] = {"action": action}
    if action == "activate":
        obj.update({"confirmation": CONFIRMATION, "duration_seconds": MAX_SECONDS,
                    "policy_release": POLICY_RELEASE})
    return request(socket_path, obj)


def run_cli(args: argparse.Namespace) -> int:
    if sys.platform != "linux" or os.uname().nodename.split(".")[0] != "ws-hadrian":
        print("BRC_PROMOTE=REFUSED; supported only on Linux ws-hadrian")
        return 2
    if os.getuid() == 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print("BRC_PROMOTE=REFUSED; run as louis from an interactive local terminal")
        return 2
    socket_path = Path(f"/run/user/{os.getuid()}") / "helix-brc-operator.sock"
    try:
        if args.command == "on":
            with open("/dev/tty", "r+", encoding="utf-8", buffering=1) as tty:
                tty.write(f"Type exactly: {CONFIRMATION}\n> ")
                if tty.readline().rstrip("\r\n") != CONFIRMATION:
                    print("BRC_PROMOTE=OFF; confirmation did not match")
                    return 1
            result = _local_request(socket_path, "activate")
        elif args.command == "off":
            result = _local_request(socket_path, "revoke")
        else:
            result = _local_request(socket_path, "status")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"BRC_PROMOTE=REFUSED; {exc}")
        return 2
    if not result.get("active"):
        print("BRC_PROMOTE=OFF; effective HELIX-BIOS operations: none")
    else:
        grant = result["grant"]
        print("BRC_PROMOTE=ON")
        expires = datetime.fromtimestamp(grant["expires_at"], tz=timezone.utc).isoformat()
        print(f"Expires: {expires}")
        print("Effective: principal=louis target=hv-lore Work Entry=070 UUID=2AF8-4CD6 mount=/mnt/helix-bios")
        print("Operations: " + ", ".join(result["effective_operations"]))
        print("Shell, interpreter, chained command, and unlisted tool requests remain denied until off/expiry.")
    return 0


def run_broker_request(args: argparse.Namespace) -> int:
    raw = sys.stdin.buffer.readline(8193)
    if not raw.endswith(b"\n") or len(raw) > 8192:
        print("invalid broker request", file=sys.stderr)
        return 2
    try:
        obj = json.loads(raw)
        result = request(Path(args.socket), obj)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:200]}))
        return 2
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    broker = sub.add_parser("broker")
    broker.add_argument("--socket", required=True)
    broker.add_argument("--state", required=True)
    broker.add_argument("--agent-pid", required=True, type=int)
    broker.add_argument("--release", required=True)
    broker.add_argument("--agent-version", required=True)
    cli = sub.add_parser("cli")
    cli.add_argument("command", choices=("on", "off", "status"))
    client = sub.add_parser("broker-request")
    client.add_argument("socket")
    args = parser.parse_args()
    if args.mode == "broker":
        return run_broker(args)
    if args.mode == "broker-request":
        return run_broker_request(args)
    return run_cli(args)


if __name__ == "__main__":
    if Path(sys.argv[0]).name == "brc-promote":
        sys.argv.insert(1, "cli")
    raise SystemExit(main())
