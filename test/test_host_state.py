"""Tests for the changes that touch host state: firewall rules, forwarding
sysctls, the global lock and routing-table capture.

These are the paths where a bug leaves the operator's machine in a bad state
after the scan, so they are exercised with the external commands mocked out
rather than against the real host.
"""
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from ptnetinspector.utils import interface as interface_module
from ptnetinspector.utils.interface import RULE_TAG, Interface, IptablesRule
from ptnetinspector.utils.lock import _cleanup_stale_lock


class FakeIptables:
    """Records iptables invocations and answers `-C` from the recorded state."""

    def __init__(self, existing=None):
        self.rules = set(existing or ())
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append(command)
        binary, action, chain, arguments = command[0], command[1], command[2], tuple(command[3:])
        key = (binary, chain, arguments)

        if action == "-C":
            return subprocess.CompletedProcess(command, 0 if key in self.rules else 1)
        if action == "-A":
            self.rules.add(key)
            return subprocess.CompletedProcess(command, 0)
        if action == "-D":
            self.rules.discard(key)
            return subprocess.CompletedProcess(command, 0)
        return subprocess.CompletedProcess(command, 0)

    def added(self):
        return [call for call in self.calls if call[1] == "-A"]


@pytest.fixture
def fake_iptables(monkeypatch):
    fake = FakeIptables()

    def _run(command, check=False, **kwargs):
        return fake.run(command)

    monkeypatch.setattr(interface_module, "_run", _run)
    return fake


class TestBlockingRulesAreIdempotent:
    """H3: a run killed before restore used to stack a second DROP rule that a
    single removal pass could not clear."""

    def _interface(self, monkeypatch):
        iface = Interface("eth0")
        monkeypatch.setattr(Interface, "check_status", lambda self: "state UP")
        return iface

    def test_shutdown_twice_adds_each_rule_once(self, fake_iptables, monkeypatch):
        iface = self._interface(monkeypatch)

        iface.shutdown_traffic()
        first_pass = len(fake_iptables.added())
        iface.shutdown_traffic()

        assert first_pass == 8  # four chains, two address families
        assert len(fake_iptables.added()) == first_pass

    def test_restore_removes_every_rule_that_was_added(self, fake_iptables, monkeypatch):
        iface = self._interface(monkeypatch)

        iface.shutdown_traffic()
        iface.restore_traffic()

        assert fake_iptables.rules == set()

    def test_added_rules_carry_the_tag_used_for_recovery(self, fake_iptables, monkeypatch):
        iface = self._interface(monkeypatch)

        iface.shutdown_traffic()

        for command in fake_iptables.added():
            assert "--comment" in command
            assert RULE_TAG in command


class TestForwardingIsRestoredNotZeroed:
    """H3: aggressive mode used to force forwarding off afterwards, even on a
    host that had it on before the scan."""

    def test_original_value_is_put_back(self, fake_iptables, tmp_path, monkeypatch):
        monkeypatch.setattr(interface_module, "get_tmp_path", lambda *a, **k: tmp_path)
        written = {}

        monkeypatch.setattr(interface_module, "_read_sysctl", lambda name: "1")
        monkeypatch.setattr(interface_module, "_write_sysctl",
                            lambda name, value: written.__setitem__(name, value))

        IptablesRule.add("a+", ipv4=True, ipv6=True, nofwd=False)
        IptablesRule.remove(True, "a+", ipv4=True, ipv6=True)

        assert written["net.ipv4.ip_forward"] == "1"
        assert written["net.ipv6.conf.all.forwarding"] == "1"

    def test_state_file_records_the_value_seen_before_any_change(self, fake_iptables, tmp_path, monkeypatch):
        monkeypatch.setattr(interface_module, "get_tmp_path", lambda *a, **k: tmp_path)
        monkeypatch.setattr(interface_module, "_read_sysctl", lambda name: "0")
        monkeypatch.setattr(interface_module, "_write_sysctl", lambda name, value: None)

        interface_module.save_forwarding_state()

        assert (tmp_path / "sysctl_state.json").exists()


class TestForwardingSurvivesAHardKill:
    """SIGKILL cannot be trapped, so a run can die with the host forwarding.

    The tagged firewall rules were already flushed by the next run; the
    forwarding sysctls were not, so a killed aggressive run left the host
    routing until an aggressive run happened to exit cleanly.
    """

    def test_a_leftover_state_file_is_restored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(interface_module, "get_tmp_path", lambda *a, **k: tmp_path)
        written = {}
        monkeypatch.setattr(interface_module, "_write_sysctl",
                            lambda name, value: written.__setitem__(name, value))

        # what a killed run left behind
        (tmp_path / "sysctl_state.json").write_text(
            '{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}',
            encoding="utf-8")

        interface_module.restore_forwarding_state()

        assert written["net.ipv4.ip_forward"] == "0"
        assert written["net.ipv6.conf.all.forwarding"] == "0"
        # consumed, so a later run does not restore a stale value
        assert not (tmp_path / "sysctl_state.json").exists()

    def test_a_host_that_always_forwarded_is_left_alone(self, tmp_path, monkeypatch):
        """With no recorded state the restore must be a no-op, not a write of 0."""
        monkeypatch.setattr(interface_module, "get_tmp_path", lambda *a, **k: tmp_path)
        written = {}
        monkeypatch.setattr(interface_module, "_write_sysctl",
                            lambda name, value: written.__setitem__(name, value))

        interface_module.restore_forwarding_state()

        assert written == {}

    def test_startup_recovers_both_rules_and_forwarding(self):
        """main.py performs the recovery, in that order, after taking the lock."""
        source = (Path(__file__).resolve().parent.parent
                  / "ptnetinspector" / "main.py").read_text()

        assert "flush_tagged_rules()" in source
        assert "restore_forwarding_state()" in source
        # the tmp directory is per interface, so the context must be set first
        assert source.index("set_current_interface(interface)") < source.index("flush_tagged_rules()")
        assert source.index("flush_tagged_rules()") < source.index("restore_forwarding_state()")


class TestRuleDetection:
    """M6: detection used to string-match `-S` output, whose canonical spelling
    differs between iptables versions and the legacy/nft backends."""

    def test_check_asks_iptables_instead_of_parsing_output(self, fake_iptables, monkeypatch):
        monkeypatch.setattr(interface_module, "_read_sysctl", lambda name: "1")

        assert IptablesRule.check("a", ipv4=True, ipv6=True) is False
        IptablesRule.add("a", ipv4=True, ipv6=True)
        assert IptablesRule.check("a", ipv4=True, ipv6=True) is True

        assert all("-S" not in call for call in fake_iptables.calls)


class TestGlobalLock:
    """M5: an empty lock file (written after the flock was taken) was treated as
    stale, so a second run unlinked the live holder's file and both proceeded."""

    def test_a_held_lock_is_never_treated_as_stale(self, tmp_path):
        import fcntl

        lock_file = tmp_path / ".ptnetinspector.lock"
        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            # The window the race lived in: locked, but not yet written.
            assert lock_file.read_text() == ""
            assert _cleanup_stale_lock(lock_file) is False
            assert lock_file.exists()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_an_unheld_lock_from_a_dead_process_is_cleared(self, tmp_path):
        lock_file = tmp_path / ".ptnetinspector.lock"
        # A PID that cannot be running: 0 is never a normal process id.
        lock_file.write_text("999999999")

        assert _cleanup_stale_lock(lock_file) is True
        assert not lock_file.exists()


    def test_a_lock_held_by_a_child_of_a_dead_run_is_cleared(self, tmp_path):
        """A child that outlived an interrupted run keeps the flock, but the PID in the file is gone."""
        import fcntl

        lock_file = tmp_path / ".ptnetinspector.lock"
        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, b"999999999")
        try:
            assert _cleanup_stale_lock(lock_file) is True
            assert not lock_file.exists()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_a_held_lock_of_a_running_process_is_kept(self, tmp_path):
        import fcntl

        lock_file = tmp_path / ".ptnetinspector.lock"
        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, str(os.getpid()).encode())
        try:
            assert _cleanup_stale_lock(lock_file) is False
            assert lock_file.exists()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
    def test_a_forked_child_does_not_keep_the_lock(self, tmp_path):
        """The child closes its inherited copy, so the lock ends with the parent."""
        import ptnetinspector.utils.lock as lock

        lock_file = tmp_path / ".ptnetinspector.lock"
        lock.acquire_global_lock(lock_file, verbose=False)
        try:
            read_end, write_end = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_end)
                os.write(write_end, b"1" if lock._LOCK_FD is None else b"0")
                os._exit(0)
            os.close(write_end)
            child_closed = os.read(read_end, 1)
            os.close(read_end)
            os.waitpid(pid, 0)
            assert child_closed == b"1"
            assert lock._LOCK_FD is not None
            assert lock._lock_is_held(lock_file)
        finally:
            lock._release_lock()


    def test_another_instance_is_running_only_while_a_live_run_holds_the_lock(self, tmp_path):
        import fcntl
        from ptnetinspector.utils.lock import another_instance_running

        lock_file = tmp_path / ".ptnetinspector.lock"
        assert another_instance_running(lock_file) is False

        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            os.write(fd, str(os.getpid()).encode())
            assert another_instance_running(lock_file) is True
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b"999999999")
            assert another_instance_running(lock_file) is False
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


class TestRoutingTableCapture:
    """M4: net-tools' `route` is absent on current distributions, and its
    FileNotFoundError is neither CalledProcessError nor TimeoutExpired, so the
    routing tables silently vanished from the report."""

    def test_iproute2_output_is_parsed(self, tmp_path, monkeypatch):
        from ptnetinspector.entities.node import Node

        monkeypatch.setattr("ptnetinspector.utils.path.get_output_dir", lambda base_path=None: tmp_path)
        from ptnetinspector.utils.csv_helpers import create_csv
        from ptnetinspector.utils.path import get_tmp_path, set_current_interface

        set_current_interface("routeiface")
        create_csv("routeiface")

        sample = (
            "default via 192.168.19.2 dev eth0 proto dhcp src 192.168.19.131 metric 100 \n"
            "192.168.19.0/24 dev eth0 proto kernel scope link src 192.168.19.131 metric 100\n"
        )
        with patch("subprocess.check_output", return_value=sample.encode()):
            Node.get_ipv4_route_metrics_and_addresses()

        content = (get_tmp_path("routeiface") / "ipv4_route_table.csv").read_text()
        set_current_interface(None)

        assert "0.0.0.0,192.168.19.2,0.0.0.0" in content
        assert "192.168.19.0,0.0.0.0,255.255.255.0" in content

    def test_a_missing_ip_binary_is_handled(self, monkeypatch):
        from ptnetinspector.entities.node import Node

        with patch("subprocess.check_output", side_effect=FileNotFoundError):
            # Must not raise: the report simply lacks the routing table.
            assert Node._run_ip_route(["route", "show"], 1.0) is None


class TestTerminationSignals:
    """H3: only SIGINT was trapped, so `kill`, a timeout wrapper or a systemd
    stop skipped every restore path and left the interface firewalled."""

    def test_catchable_termination_signals_are_handled(self):
        # main.py parses argv and takes the global lock at import time, so the
        # module is read from disk rather than imported.
        import ptnetinspector

        main_path = Path(ptnetinspector.__file__).parent / "main.py"
        source = main_path.read_text(encoding="utf-8")

        for name in ("SIGINT", "SIGTERM", "SIGHUP"):
            assert f"signal.signal(signal.{name}, custom_signal_handler)" in source

    def test_host_state_is_restored_from_a_single_shared_path(self):
        import ptnetinspector

        main_path = Path(ptnetinspector.__file__).parent / "main.py"
        source = main_path.read_text(encoding="utf-8")

        # Registered with atexit so any exit short of SIGKILL still restores.
        assert "atexit.register(_restore_host_state)" in source
        # And a self-heal for the SIGKILL case, which cannot be trapped.
        assert "flush_tagged_rules()" in source
