import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "src/core/helix-bios-control.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("helix_bios_control", MODULE_PATH)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class GrantPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="brc-we071-test-")
        self.addCleanup(self.tempdir.cleanup)
        self.state = control.GrantState(42, control.POLICY_RELEASE, Path(self.tempdir.name) / "state")
        self.fingerprint = "a" * 64
        self.agent_pid = 42
        self.uid = 1000
        self.policy = {
            "policy_release": control.POLICY_RELEASE,
            "policy_fingerprint": self.fingerprint,
            "blocked_commands": ["sudo", "mount", "umount"],
        }
        self.state.update_policy(self.agent_pid, self.policy)
        self.session_auth = patch.object(control.os, "uname", return_value=type("Uname", (), {"nodename": "ws-hadrian"})())
        self.session_auth.start()
        self.addCleanup(self.session_auth.stop)
        self.login_auth = patch.object(control, "_has_interactive_login_session", return_value=True)
        self.login_auth.start()
        self.addCleanup(self.login_auth.stop)
        self.uid_auth = patch.object(control, "_proc_uid", return_value=self.uid)
        self.uid_auth.start()
        self.addCleanup(self.uid_auth.stop)

    def activate(self):
        return self.state.activate(99, self.uid, {
            "confirmation": control.CONFIRMATION,
            "duration_seconds": control.MAX_SECONDS,
            "policy_release": control.POLICY_RELEASE,
        })

    def test_activation_is_fixed_scope_and_30_minutes(self):
        result = self.activate()
        self.assertTrue(result["active"])
        grant = result["grant"]
        self.assertEqual(grant["principal"], "louis")
        self.assertEqual(grant["target"], "hv-lore")
        self.assertEqual(grant["work_entry"], "070")
        self.assertEqual(grant["usb_uuid"], "2AF8-4CD6")
        self.assertEqual(grant["mountpoint"], "/mnt/helix-bios")
        self.assertEqual(grant["manifest_sha256"], control.MANIFEST_SHA256)
        self.assertEqual(grant["expires_at"] - int(control.time.time()), 1800)

    def test_confirmation_duration_and_global_blocklist_are_required(self):
        for changes in (
            {"confirmation": "enable"},
            {"duration_seconds": control.MAX_SECONDS + 1},
        ):
            request = {"confirmation": control.CONFIRMATION,
                       "duration_seconds": control.MAX_SECONDS,
                       "policy_release": control.POLICY_RELEASE, **changes}
            with self.assertRaises(ValueError):
                self.state.activate(99, self.uid, request)
        self.state.blocked_commands = ("sudo", "mount")
        with self.assertRaisesRegex(ValueError, "global command blocks"):
            self.activate()

    def test_activation_requires_exact_local_principal_and_interactive_session(self):
        request = {"confirmation": control.CONFIRMATION,
                   "duration_seconds": control.MAX_SECONDS,
                   "policy_release": control.POLICY_RELEASE}
        with self.assertRaisesRegex(ValueError, "principal mismatch"):
            self.state.activate(99, self.uid + 1, request)
        with patch.object(control, "_has_interactive_login_session", return_value=False):
            with self.assertRaisesRegex(ValueError, "interactive local login terminal"):
                self.state.activate(99, self.uid, request)
        with patch.object(control.os, "uname", return_value=SimpleNamespace(nodename="other-host")):
            with self.assertRaisesRegex(ValueError, "ws-hadrian"):
                self.state.activate(99, self.uid, request)

    def test_only_fixed_operation_identifiers_are_authorized_for_agent(self):
        self.activate()
        request = {**self.policy, "operation": "transfer_manifest"}
        self.assertTrue(self.state.authorize(self.agent_pid, request)["allowed"])
        for operation in ("sudo reboot", "ssh hv-lore sudo mount", "python3 -c import_os", "install; reboot"):
            request = {**self.policy, "operation": operation}
            self.assertFalse(self.state.authorize(self.agent_pid, request)["allowed"])
        with self.assertRaisesRegex(ValueError, "restricted to the BRC agent"):
            self.state.authorize(31415, {**self.policy, "operation": "preflight"})

    def test_policy_drift_and_unexpected_release_revoke(self):
        self.activate()
        drift = {**self.policy, "policy_fingerprint": "b" * 64}
        result = self.state.authorize(self.agent_pid, {**drift, "operation": "preflight"})
        self.assertFalse(result["allowed"])
        self.assertEqual(result["state"]["active"], False)
        self.activate()
        with self.assertRaisesRegex(ValueError, "unexpected BRC policy release"):
            self.state.update_policy(self.agent_pid, {**self.policy, "policy_release": "unexpected"})
        self.assertFalse(self.state.status()["active"])

    def test_expiry_revocation_and_restart_fail_closed(self):
        with patch.object(control.time, "monotonic", return_value=100.0):
            self.activate()
        with patch.object(control.time, "monotonic", return_value=100.0 + control.MAX_SECONDS):
            self.assertFalse(self.state.status()["active"])
        self.activate()
        restarted = control.GrantState(42, control.POLICY_RELEASE, Path(self.tempdir.name) / "restarted")
        self.assertFalse(restarted.status()["active"])

    def test_broker_timer_expires_grant_without_an_operator_request(self):
        with patch.object(control.time, "monotonic", return_value=100.0):
            self.activate()
        server = object.__new__(control.BrokerServer)
        server.state = self.state
        with patch.object(control.time, "monotonic", return_value=100.0 + control.MAX_SECONDS):
            control.BrokerServer.service_actions(server)
        self.assertFalse(self.state.status()["active"])

    def test_broker_exits_and_revokes_when_agent_process_identity_changes(self):
        self.activate()
        self.state.agent_identity = (self.uid, 1234)
        server = object.__new__(control.BrokerServer)
        server.state = self.state
        with patch.object(control, "_proc_identity", return_value=None):
            with self.assertRaises(SystemExit):
                control.BrokerServer.service_actions(server)
        self.assertFalse(self.state.status()["active"])

    def test_wall_clock_jump_revokes_and_local_off_is_immediate(self):
        with patch.object(control.time, "monotonic", return_value=100.0), \
                patch.object(control.time, "time", return_value=1000.0):
            self.activate()
        with patch.object(control.time, "monotonic", return_value=101.0), \
                patch.object(control.time, "time", return_value=1010.0):
            self.assertFalse(self.state.status()["active"])
        self.activate()
        result = self.state.revoke(99, self.uid)
        self.assertFalse(result["active"])

    def test_no_arbitrary_scope_inputs_are_part_of_a_grant(self):
        self.activate()
        grant = self.state.status()["grant"]
        self.assertNotIn("command", grant)
        self.assertNotIn("shell", grant)
        self.assertNotIn("arguments", grant)
        self.assertNotIn("host_override", grant)

    def test_fixed_operation_capability_is_single_use_and_short_lived(self):
        self.activate()
        response = self.state.authorize(self.agent_pid, {**self.policy, "operation": "transfer_manifest"})
        token = response["operation_token"]
        self.assertTrue(token)
        with patch.object(self.state, "_is_agent_descendant", return_value=True):
            with patch.object(control, "_proc_uid", return_value=self.uid + 1):
                with self.assertRaisesRegex(ValueError, "operation token consumption"):
                    self.state.consume(100, self.uid + 1, {"token": token, "operation": "transfer_manifest"})
            result = self.state.consume(100, self.uid, {"token": token, "operation": "transfer_manifest"})
            self.assertTrue(result["allowed"])
            with self.assertRaisesRegex(ValueError, "missing, expired, or already consumed"):
                self.state.consume(100, self.uid, {"token": token, "operation": "transfer_manifest"})
            second = self.state.authorize(self.agent_pid, {**self.policy, "operation": "preflight"})["operation_token"]
            self.assertIsNone(second)

    def test_one_transfer_per_grant_and_pending_token_blocks_parallel_calls(self):
        self.activate()
        first = self.state.authorize(self.agent_pid, {**self.policy, "operation": "transfer_manifest"})
        self.assertTrue(first["allowed"])
        second = self.state.authorize(self.agent_pid, {**self.policy, "operation": "transfer_manifest"})
        self.assertFalse(second["allowed"])
        with patch.object(self.state, "_is_agent_descendant", return_value=True):
            self.state.consume(100, self.uid, {"token": first["operation_token"], "operation": "transfer_manifest"})
        third = self.state.authorize(self.agent_pid, {**self.policy, "operation": "transfer_manifest"})
        self.assertFalse(third["allowed"])

    def test_expired_unconsumed_operation_token_can_be_retried(self):
        request = {**self.policy, "operation": "transfer_manifest"}
        with patch.object(control.time, "monotonic", return_value=100.0), \
                patch.object(control.time, "time", return_value=1000.0):
            self.activate()
            first = self.state.authorize(self.agent_pid, request)
        with patch.object(control.time, "monotonic", return_value=111.0), \
                patch.object(control.time, "time", return_value=1011.0):
            retry = self.state.authorize(self.agent_pid, request)
        self.assertTrue(first["allowed"])
        self.assertTrue(retry["allowed"])
        self.assertNotEqual(first["operation_token"], retry["operation_token"])

    def test_activation_audit_failure_does_not_leave_grant_active(self):
        with patch.object(self.state, "_audit", side_effect=OSError("audit unavailable")):
            with self.assertRaisesRegex(OSError, "audit unavailable"):
                self.activate()
        self.assertFalse(self.state.status()["active"])

    def test_status_cli_sends_only_the_strict_status_request(self):
        class TerminalBuffer(io.StringIO):
            def isatty(self):
                return True

        stdout = TerminalBuffer()
        with patch.object(control.sys, "platform", "linux"), \
                patch.object(control.os, "uname", return_value=SimpleNamespace(nodename="ws-hadrian")), \
                patch.object(control.os, "getuid", return_value=1000), \
                patch.object(control.sys, "stdin", TerminalBuffer()), \
                patch.object(control.sys, "stdout", stdout), \
                patch.object(control, "_local_request", return_value={"active": False} ) as request:
            result = control.run_cli(SimpleNamespace(command="status"))
        self.assertEqual(result, 0)
        request.assert_called_once_with(Path("/run/user/1000/helix-brc-operator.sock"), "status")

    def test_broker_request_descendant_check_rejects_unrelated_process(self):
        self.state.agent_pid = -1
        self.assertFalse(self.state._is_agent_descendant(__import__("os").getpid()))
        self.state.agent_pid = __import__("os").getpid()
        self.assertTrue(self.state._is_agent_descendant(__import__("os").getpid()))


if __name__ == "__main__":
    unittest.main()
