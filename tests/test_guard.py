import copy
import importlib.machinery
import importlib.util
import unittest
from unittest import mock
import tempfile
import subprocess
import sys
import threading
import json
import io
from pathlib import Path

source = Path(__file__).resolve().parents[1] / 'claude-guard.pyw'
loader = importlib.machinery.SourceFileLoader('claude_guard', str(source))
spec = importlib.util.spec_from_loader(loader.name, loader)
guard = importlib.util.module_from_spec(spec)
loader.exec_module(guard)

CONFIG = {'proxy_url': 'http://127.0.0.1:7897', 'require_tun': True,
          'request_timeout_seconds': 10, 'allowed_exit_ips': []}
SYSTEM = {'enabled': 1, 'server': '127.0.0.1:7897', 'pac': '', 'bypass': '<local>'}
RUNTIME = {'mode': 'global', 'mixed-port': 7897, 'tun': {'enable': True, 'auto-route': True}}
PROXIES = {'GLOBAL': {'type': 'Selector', 'all': ['chosen'], 'now': 'chosen'},
           'chosen': {'type': 'Socks5'}}


class FakeController:
    def __init__(self, runtime=None, proxies=None):
        self.runtime = copy.deepcopy(runtime or RUNTIME)
        self.proxies = copy.deepcopy(proxies or PROXIES)

    def get(self, path, **kwargs):
        return copy.deepcopy(self.runtime if path == '/configs' else {'proxies': self.proxies})


class GuardTests(unittest.TestCase):
    def test_example_config_expands_user_environment_paths(self):
        example = json.loads((source.parent / 'guard-config.example.json').read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'guard-config.json').write_text(json.dumps(example), encoding='utf-8')
            local = root / 'Local'
            roaming = root / 'Roaming'
            with mock.patch.object(guard, 'ROOT', root), mock.patch.dict(guard.os.environ, {
                    'LOCALAPPDATA': str(local), 'APPDATA': str(roaming)}):
                config = guard.load_config()
            self.assertEqual(Path(config['claude_executable']), local / 'AnthropicClaude/claude.exe')
            self.assertEqual(Path(config['clash_config']),
                             roaming / 'io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml')

    def pipe_response(self, data=None, chunked=False):
        body = json.dumps(data or RUNTIME).encode('utf-8')
        payload = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        if chunked:
            payload = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
                       + hex(len(body))[2:].encode() + b'\r\n' + body + b'\r\n0\r\n\r\n')
        class FragmentedPipe(io.RawIOBase):
            def __init__(self):
                self.data = io.BytesIO(payload)
            def readable(self):
                return True
            def readinto(self, buffer):
                value = self.data.read(min(len(buffer), 7))
                buffer[:len(value)] = value
                return len(value)
            def write(self, data):
                return min(len(data), 5)
        return FragmentedPipe()

    def controller(self):
        controller = guard.Controller.__new__(guard.Controller)
        controller.pipe, controller.secret = 'fake-pipe', ''
        return controller

    def test_controller_reads_fragmented_named_pipe_response_completely(self):
        with mock.patch('builtins.open', return_value=self.pipe_response()):
            self.assertEqual(self.controller().get('/configs'), RUNTIME)

    def test_controller_reads_fragmented_chunked_response_completely(self):
        with mock.patch('builtins.open', return_value=self.pipe_response(chunked=True)):
            self.assertEqual(self.controller().get('/configs'), RUNTIME)

    def test_controller_retries_short_pipe_busy_within_original_deadline(self):
        busy = OSError('pipe busy')
        busy.winerror = 231
        with mock.patch('builtins.open', side_effect=[busy, self.pipe_response()]):
            self.assertEqual(self.controller().get('/configs', timeout=0.2), RUNTIME)

    def test_controller_rejects_persistent_pipe_failure(self):
        with mock.patch('builtins.open', side_effect=OSError('broken pipe')), mock.patch.object(guard, 'record'):
            with self.assertRaises(guard.GuardError):
                self.controller().get('/configs', timeout=0.2)

    def test_controller_retry_returns_unsafe_mode_for_policy_rejection(self):
        broken = OSError('transient pipe error')
        with mock.patch('builtins.open', side_effect=[broken, self.pipe_response(dict(RUNTIME, mode='direct'))]):
            data = self.controller().get('/configs', timeout=0.2)
        with self.assertRaises(guard.GuardError):
            guard.validate_runtime(data, PROXIES)

    def check(self, controller=None, state=None, probe=None, running=None, config=None):
        return guard.preflight(config or CONFIG, controller or FakeController(),
                               state_reader=state or (lambda: copy.deepcopy(SYSTEM)),
                               ip_probe=probe or (lambda *_: '8.8.8.8'),
                               running_check=running or (lambda: False))

    def forbidden_probe(self, *_):
        self.fail('Network probe must not run before unsafe state is rejected')

    def test_verified_proxy_succeeds_without_launching(self):
        self.assertEqual(self.check()['exit_ip'], '8.8.8.8')

    def test_disabled_system_proxy_blocks_before_network(self):
        state = dict(SYSTEM, enabled=0)
        with self.assertRaises(guard.GuardError):
            self.check(state=lambda: state, probe=self.forbidden_probe)

    def test_wrong_system_endpoint_blocks_before_network(self):
        state = dict(SYSTEM, server='127.0.0.1:9999')
        with self.assertRaises(guard.GuardError):
            self.check(state=lambda: state, probe=self.forbidden_probe)

    def test_rule_mode_blocks_before_network(self):
        with self.assertRaises(guard.GuardError):
            self.check(FakeController(runtime=dict(RUNTIME, mode='rule')), probe=self.forbidden_probe)

    def test_tun_disabled_blocks_before_network(self):
        runtime = copy.deepcopy(RUNTIME)
        runtime['tun']['enable'] = False
        with self.assertRaises(guard.GuardError):
            self.check(FakeController(runtime=runtime), probe=self.forbidden_probe)

    def test_nested_direct_selection_blocks_before_network(self):
        proxies = copy.deepcopy(PROXIES)
        proxies['chosen'] = {'type': 'Selector', 'all': ['DIRECT'], 'now': 'DIRECT'}
        proxies['DIRECT'] = {'type': 'Direct'}
        with self.assertRaises(guard.GuardError):
            self.check(FakeController(proxies=proxies), probe=self.forbidden_probe)

    def test_auto_switch_group_blocks_before_network(self):
        proxies = copy.deepcopy(PROXIES)
        proxies['GLOBAL']['type'] = 'URLTest'
        with self.assertRaises(guard.GuardError):
            self.check(FakeController(proxies=proxies), probe=self.forbidden_probe)

    def test_existing_claude_blocks_before_network(self):
        with self.assertRaises(guard.GuardError):
            self.check(running=lambda: True, probe=self.forbidden_probe)

    def test_exit_ip_mismatch_blocks(self):
        ips = iter(['8.8.8.8', '1.1.1.1'])
        with self.assertRaises(guard.GuardError):
            self.check(probe=lambda *_: next(ips))

    def test_exit_lookup_failure_blocks(self):
        def failed(*_):
            raise guard.GuardError('offline')
        with self.assertRaises(guard.GuardError):
            self.check(probe=failed)

    def test_node_change_during_check_blocks(self):
        controller = FakeController()
        def probe(*_):
            controller.proxies['GLOBAL']['all'].append('other')
            controller.proxies['GLOBAL']['now'] = 'other'
            controller.proxies['other'] = {'type': 'Socks5'}
            return '8.8.8.8'
        with self.assertRaises(guard.GuardError):
            self.check(controller, probe=probe)

    def test_unapproved_exit_blocks(self):
        with self.assertRaises(guard.GuardError):
            self.check(config=dict(CONFIG, allowed_exit_ips=['1.1.1.1']))

    def test_one_ip_service_failure_does_not_block_healthy_proxy(self):
        def probe(host, *_):
            if host == 'api.ipify.org':
                raise guard.GuardError('service timeout')
            return '8.8.8.8'
        self.assertEqual(self.check(probe=probe)['exit_ip'], '8.8.8.8')

    def test_slow_service_does_not_delay_two_successful_services(self):
        stalled = threading.Event()
        def probe(host, *_):
            if host == 'api.ipify.org':
                stalled.wait(5)
            return '8.8.8.8'
        started = guard.time.monotonic()
        try:
            self.assertEqual(self.check(probe=probe)['exit_ip'], '8.8.8.8')
            self.assertLess(guard.time.monotonic() - started, 0.5)
        finally:
            stalled.set()

    def test_two_service_failures_still_block(self):
        def probe(host, *_):
            if host != 'ipv4.icanhazip.com':
                raise guard.GuardError('unreachable')
            return '8.8.8.8'
        with self.assertRaises(guard.GuardError):
            self.check(probe=probe)

    def test_claude_started_during_check_blocks(self):
        running = iter([False, True])
        with self.assertRaises(guard.GuardError):
            self.check(running=lambda: next(running))

    def test_launch_passes_proxy_and_clears_remote_bypass_for_child_only(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / 'claude.exe'
            executable.touch()
            config = dict(CONFIG, claude_executable=str(executable))
            with mock.patch.dict(guard.os.environ, {'NO_PROXY': '*'}), mock.patch.object(guard.subprocess, 'Popen') as popen:
                guard.launch(config)
                args, kwargs = popen.call_args
                self.assertIn('--proxy-server=http://127.0.0.1:7897', args[0])
                self.assertEqual(kwargs['env']['HTTPS_PROXY'], CONFIG['proxy_url'])
                self.assertEqual(kwargs['env']['NO_PROXY'], 'localhost,127.0.0.1,::1')
                self.assertEqual(guard.os.environ['NO_PROXY'], '*')
                self.assertFalse(kwargs.get('shell', False))


WATCH_CONFIG = dict(CONFIG, watch_interval_seconds=0.25, controller_timeout_seconds=0.8,
                    runtime_check_interval_seconds=1, remote_check_interval_seconds=5,
                    remote_timeout_seconds=8, connectivity_timeout_seconds=5,
                    upstream_retry_delay_seconds=1)


class FailedExitProbe:
    def poll(self):
        raise guard.ProbeUnavailable('query timeout')


class StaticConnectivityProbe:
    def __init__(self, value=True):
        self.value = value

    def poll(self):
        return self.value

    def diagnostics(self):
        return []


class FakeJob:
    def __init__(self):
        self.attached = []
        self.terminated = False

    def attach(self, pids):
        self.attached += pids

    def terminate(self):
        self.terminated = True


class WatchdogTests(unittest.TestCase):
    def monitor(self, port=None, firewall=None, probes=None, processes=None, controller=None,
                connectivity=None, state=None):
        self.clock = 0
        self.job = FakeJob()
        self.closed = False
        self.events = []
        self.states = []
        class HealthyProbe:
            def poll(self):
                return '8.8.8.8'
        return guard.NetworkMonitor(WATCH_CONFIG, controller or FakeController(),
                                    {'chain': ['GLOBAL', 'chosen'], 'exit_ip': '8.8.8.8'}, self.job,
                                    clock=lambda: self.clock,
                                    process_reader=processes or (lambda: [123]),
                                    state_reader=state or (lambda: copy.deepcopy(SYSTEM)),
                                    port_check=port or (lambda: True),
                                    probe_factory=probes or (lambda _, **kwargs: HealthyProbe()),
                                    state_writer=lambda status, pids, message=None: self.states.append((status, message)),
                                    firewall_checker=firewall or (lambda: True),
                                    connectivity_factory=connectivity or (lambda _, **kwargs: StaticConnectivityProbe()),
                                    event_writer=lambda status, message, **kwargs: self.events.append((status, kwargs)))

    def close(self):
        self.assertTrue(self.job.terminated, 'Windows job must be terminated before fallback process kill')
        self.closed = True

    def sleep(self, seconds):
        self.clock += seconds
        if self.clock > 10:
            self.fail('Monitor failed to stop within the test deadline')

    def assert_closed_on_fault(self, monitor):
        with self.assertRaises(Exception):
            guard.supervise(monitor, self.close, self.sleep)
        self.assertTrue(self.closed)

    def test_local_proxy_loss_forces_close_in_same_iteration(self):
        def lost():
            raise guard.GuardError('disconnected')
        monitor = self.monitor(port=lost)
        self.assert_closed_on_fault(monitor)
        self.assertEqual(self.clock, 0)

    def test_confirmed_upstream_failure_forces_close_after_two_rounds(self):
        monitor = self.monitor(probes=lambda _, **kwargs: FailedExitProbe(),
                               connectivity=lambda _, **kwargs: StaticConnectivityProbe(False))
        self.assert_closed_on_fault(monitor)
        self.assertEqual(monitor.failed_connectivity_rounds, 2)
        self.assertGreaterEqual(self.clock, WATCH_CONFIG['upstream_retry_delay_seconds'])

    def test_query_timeout_does_not_close_if_independent_https_works(self):
        monitor = self.monitor(probes=lambda _, **kwargs: FailedExitProbe())
        for _ in range(3):
            self.assertTrue(monitor.step())
        self.assertFalse(self.job.terminated)
        self.assertTrue(monitor.exit_degraded)
        self.assertIsNone(monitor.next_connectivity)
        self.assertEqual([event[0] for event in self.events],
                         ['remote-check-degraded', 'remote-check-healthy'])

    def test_second_round_recovery_resets_failures_and_keeps_claude(self):
        rounds = iter([False, True])
        monitor = self.monitor(probes=lambda _, **kwargs: FailedExitProbe(),
                               connectivity=lambda _, **kwargs: StaticConnectivityProbe(next(rounds)))
        for _ in range(3):
            self.assertTrue(monitor.step())
        self.assertEqual(monitor.failed_connectivity_rounds, 1)
        self.clock = 1
        self.assertTrue(monitor.step())
        self.assertTrue(monitor.step())
        self.assertEqual(monitor.failed_connectivity_rounds, 0)
        self.assertFalse(self.job.terminated)

    def test_ip_query_recovery_clears_degraded_state(self):
        class RecoveredExit:
            def poll(self):
                return '8.8.8.8'
        rounds = iter([FailedExitProbe(), RecoveredExit()])
        monitor = self.monitor(probes=lambda _, **kwargs: next(rounds))
        for _ in range(3):
            monitor.step()
        self.clock = 5
        monitor.step()
        monitor.step()
        self.assertFalse(monitor.exit_degraded)
        self.assertEqual(self.events[-1][0], 'remote-check-recovered')

    def test_local_proxy_loss_still_closes_during_remote_confirmation(self):
        broken = [False]
        def port():
            if broken[0]:
                raise guard.GuardError('local proxy stopped')
        monitor = self.monitor(port=port, probes=lambda _, **kwargs: FailedExitProbe(),
                               connectivity=lambda _, **kwargs: StaticConnectivityProbe(None))
        monitor.step()
        monitor.step()
        broken[0] = True
        self.assert_closed_on_fault(monitor)
        self.assertEqual(self.clock, 0)

    def test_firewall_loss_still_closes_during_remote_confirmation(self):
        broken = [False]
        def firewall():
            if broken[0]:
                raise guard.GuardError('firewall disabled')
        monitor = self.monitor(firewall=firewall, probes=lambda _, **kwargs: FailedExitProbe(),
                               connectivity=lambda _, **kwargs: StaticConnectivityProbe(None))
        monitor.step()
        monitor.step()
        self.clock = 1
        broken[0] = True
        self.assert_closed_on_fault(monitor)
        self.assertEqual(self.clock, 1)

    def test_direct_mode_still_closes_during_remote_confirmation(self):
        controller = FakeController()
        monitor = self.monitor(controller=controller, probes=lambda _, **kwargs: FailedExitProbe(),
                               connectivity=lambda _, **kwargs: StaticConnectivityProbe(None))
        monitor.step()
        monitor.step()
        self.clock = 1
        controller.runtime['mode'] = 'direct'
        self.assert_closed_on_fault(monitor)

    def test_invalid_probe_error_does_not_enter_transient_retry(self):
        class InvalidProbe:
            def poll(self):
                raise RuntimeError('unexpected bug')
        self.assert_closed_on_fault(self.monitor(probes=lambda _, **kwargs: InvalidProbe()))
        self.assertEqual(self.events, [])

    def test_exit_ip_change_forces_close(self):
        class ChangedProbe:
            def poll(self):
                return '1.1.1.1'
        self.assert_closed_on_fault(self.monitor(probes=lambda _, **kwargs: ChangedProbe()))

    def test_rule_mode_switch_forces_close(self):
        runtime = dict(RUNTIME, mode='rule')
        self.assert_closed_on_fault(self.monitor(controller=FakeController(runtime=runtime)))

    def test_firewall_loss_forces_close(self):
        def lost():
            raise guard.GuardError('firewall missing')
        self.assert_closed_on_fault(self.monitor(firewall=lost))

    def test_monitor_exception_is_fail_closed(self):
        def crashed():
            raise RuntimeError('unexpected monitor failure')
        self.assert_closed_on_fault(self.monitor(port=crashed))

    def test_controller_transient_error_recovers_without_closing(self):
        broken = [True]
        class Controller(FakeController):
            def get(self, *args, **kwargs):
                if broken[0]:
                    raise guard.ControllerUnavailable('temporary reload')
                return super().get(*args, **kwargs)
        monitor = self.monitor(controller=Controller())
        self.assertTrue(monitor.step())
        self.assertTrue(monitor.runtime_degraded)
        broken[0] = False
        self.clock = 0.5
        self.assertTrue(monitor.step())
        self.assertFalse(monitor.runtime_degraded)
        self.assertFalse(self.job.terminated)

    def test_controller_failures_do_not_extend_five_second_deadline(self):
        class Controller(FakeController):
            def get(self, *args, **kwargs):
                raise guard.ControllerUnavailable('unavailable')
        monitor = self.monitor(controller=Controller())
        self.assert_closed_on_fault(monitor)
        self.assertGreater(self.clock, 5)
        self.assertLess(self.clock, 6)

    def test_normal_exit_does_not_force_kill(self):
        processes = iter([[123], []])
        monitor = self.monitor(processes=lambda: next(processes))
        guard.supervise(monitor, self.close, self.sleep)
        self.assertFalse(self.closed)
        self.assertFalse(self.job.terminated)

    def test_probe_has_absolute_deadline(self):
        event = threading.Event()
        clock = [0]
        probe = guard.ExitProbe(3, probe=lambda *_: event.wait(10), clock=lambda: clock[0])
        try:
            clock[0] = 3.1
            with self.assertRaises(guard.ProbeUnavailable):
                probe.poll()
        finally:
            event.set()

    def test_one_changed_ip_is_fatal_even_without_quorum(self):
        stalled = threading.Event()
        def request(host, *_):
            if host == 'api.ipify.org':
                return '1.1.1.1'
            stalled.wait(5)
            return '8.8.8.8'
        probe = guard.ExitProbe(3, probe=request, expected_ip='8.8.8.8')
        try:
            deadline = guard.time.monotonic() + 1
            with self.assertRaisesRegex(guard.GuardError, 'IP'):
                while guard.time.monotonic() < deadline:
                    probe.poll()
                    guard.time.sleep(0.01)
        finally:
            stalled.set()

    def test_connectivity_probe_has_deadline_and_one_success_is_enough(self):
        event = threading.Event()
        clock = [0]
        pending = guard.ConnectivityProbe(5, probe=lambda *_: event.wait(10), clock=lambda: clock[0])
        try:
            self.assertIsNone(pending.poll())
            clock[0] = 5
            self.assertFalse(pending.poll())
        finally:
            event.set()
        def one_healthy(host, *_):
            if host != 'www.apple.com':
                raise OSError('blocked endpoint')
            return True
        reachable = guard.ConnectivityProbe(5, probe=one_healthy)
        deadline = guard.time.monotonic() + 1
        result = None
        while result is None and guard.time.monotonic() < deadline:
            result = reachable.poll()
            guard.time.sleep(0.01)
        self.assertTrue(result)

    def test_query_diagnostics_do_not_include_ip_or_raw_exception(self):
        def failure(*_):
            raise OSError('private-token 203.0.113.17')
        probe = guard.ExitProbe(1, probe=failure)
        deadline = guard.time.monotonic() + 2
        with self.assertRaises(guard.ProbeUnavailable) as raised:
            while guard.time.monotonic() < deadline:
                probe.poll()
                guard.time.sleep(0.01)
        diagnostics = json.dumps(raised.exception.diagnostics)
        self.assertNotIn('private-token', diagnostics)
        self.assertNotIn('203.0.113.17', diagnostics)
        self.assertIn('OSError', diagnostics)

    def test_https_recheck_rejects_redirect_without_direct_fallback(self):
        with mock.patch.object(guard.http.client, 'HTTPSConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            with self.assertRaises(guard.ProbeUnavailable):
                guard.proxy_connectivity('www.gstatic.com', '/generate_204', 5)
            self.assertEqual(connection.call_count, 1)
            self.assertEqual(connection.call_args.args, ('127.0.0.1', 7897))
            connection.return_value.set_tunnel.assert_called_once_with('www.gstatic.com', 443)
            connection.return_value.close.assert_called_once()

    def test_https_recheck_transport_failure_never_falls_back_to_direct(self):
        with mock.patch.object(guard.http.client, 'HTTPSConnection') as connection:
            connection.return_value.request.side_effect = OSError('proxy offline')
            with self.assertRaises(OSError):
                guard.proxy_connectivity('www.gstatic.com', '/generate_204', 5)
            self.assertEqual(connection.call_count, 1)
            self.assertEqual(connection.call_args.args, ('127.0.0.1', 7897))
            connection.return_value.close.assert_called_once()

    def test_job_handle_close_kills_only_owned_test_process(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        job = guard.ProcessJob()
        try:
            job.attach([child.pid])
            job.close()
            self.assertIsNotNone(child.wait(timeout=3))
        finally:
            job.close()
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)

    def test_force_close_targets_claude_tree(self):
        with mock.patch.object(guard, 'claude_pids', side_effect=[[123], []]), mock.patch.object(guard.subprocess, 'run') as kill:
            self.assertTrue(guard.force_close_claude())
            self.assertEqual(kill.call_args.args[0][-4:], ['/F', '/T', '/IM', 'claude.exe'])

    def test_missing_firewall_is_rejected(self):
        reply = subprocess.CompletedProcess([], 1, stdout=b'{"ok":false}', stderr=b'')
        with mock.patch.object(guard.subprocess, 'run', return_value=reply):
            with self.assertRaises(guard.GuardError):
                guard.check_firewall()

    def test_firewall_validation_timeout_is_rejected(self):
        with mock.patch.object(guard.subprocess, 'run', side_effect=subprocess.TimeoutExpired('check', 4)):
            with self.assertRaises(guard.GuardError):
                guard.check_firewall()

    def test_firewall_validation_must_report_boolean_true(self):
        reply = subprocess.CompletedProcess([], 0, stdout=b'{"ok":"true"}', stderr=b'')
        with mock.patch.object(guard.subprocess, 'run', return_value=reply):
            with self.assertRaises(guard.GuardError):
                guard.check_firewall()

    def test_native_launch_binds_job_before_program_executes(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'executed.txt'
            job = guard.ProcessJob()
            outer = self
            class CheckedJob:
                def attach(self, pids):
                    outer.assertFalse(marker.exists())
                    job.attach(pids)
            try:
                pid = guard.start_suspended(sys.executable,
                    ['-c', 'from pathlib import Path; import time; Path(' + repr(str(marker)) + ').write_text("ok"); time.sleep(60)'],
                    dict(guard.os.environ), folder, CheckedJob())
                deadline = guard.time.monotonic() + 3
                while not marker.exists() and guard.time.monotonic() < deadline:
                    guard.time.sleep(0.02)
                self.assertTrue(marker.exists())
                process = guard.KERNEL.OpenProcess(0x0400 | 0x0001, False, pid)
                try:
                    member = guard.wintypes.BOOL()
                    self.assertTrue(guard.KERNEL.IsProcessInJob(process, job.handle, guard.ctypes.byref(member)))
                    self.assertTrue(member.value)
                finally:
                    if process:
                        guard.KERNEL.TerminateProcess(process, 1)
                        guard.KERNEL.CloseHandle(process)
            finally:
                job.close()

    def test_failed_binding_never_runs_program(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'must-not-run.txt'
            class FailedJob:
                def attach(self, pids):
                    raise guard.GuardError('assignment failed')
            with self.assertRaises(guard.GuardError):
                guard.start_suspended(sys.executable,
                    ['-c', 'from pathlib import Path; Path(' + repr(str(marker)) + ').write_text("bad")'],
                    dict(guard.os.environ), folder, FailedJob())
            guard.time.sleep(0.1)
            self.assertFalse(marker.exists())

    def test_resolves_actual_latest_binary_instead_of_stub(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'claude.exe').touch()
            for version in ['1.9.0', '2.1.0']:
                directory = root / ('app-' + version)
                directory.mkdir()
                (directory / 'claude.exe').touch()
            self.assertEqual(guard.claude_binary({'claude_executable': str(root / 'claude.exe')}),
                             root / 'app-2.1.0/claude.exe')


class RuleRoutingTests(unittest.TestCase):
    RULES = [{'type': 'InPort', 'payload': '17897', 'proxy': 'GLOBAL'},
             {'type': 'ProcessPath', 'payload': 'C:\\Apps\\Claude\\claude.exe', 'proxy': 'GLOBAL'}]

    def test_setup_preserves_other_routing_and_is_idempotent(self):
        helper_spec = importlib.util.spec_from_file_location('rule_setup', source.parent / 'configure-rule-mode.py')
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        original = {'mode': 'rule', 'rules': ['GEOIP,CN,DIRECT', 'MATCH,PROXY'],
                    'listeners': [{'name': 'other', 'port': 9000}],
                    'proxies': [{'name': 'node', 'password': 'dummy-fixture'}]}
        result = helper.guard_configuration(original, ['C:\\Apps\\Claude\\claude.exe'], 'PROXY')
        self.assertEqual(result['rules'][:2], ['IN-PORT,17897,PROXY', 'PROCESS-PATH,C:\\Apps\\Claude\\claude.exe,PROXY'])
        self.assertEqual(result['rules'][2:], original['rules'])
        self.assertEqual(result['mode'], 'rule')
        self.assertEqual(result['listeners'][-1]['proxy'], 'PROXY')
        self.assertEqual(result['listeners'][-1]['listen'], '127.0.0.1')
        self.assertEqual(result['proxies'], original['proxies'])
        self.assertEqual(helper.guard_configuration(result, ['C:\\Apps\\Claude\\claude.exe'], 'PROXY'), result)

    def test_setup_rejects_listener_collision_and_rule_injection(self):
        helper_spec = importlib.util.spec_from_file_location('rule_setup', source.parent / 'configure-rule-mode.py')
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        with self.assertRaises(ValueError):
            helper.guard_configuration({'listeners': [{'name': 'other', 'port': 17897}]}, ['C:\\Claude.exe'], 'PROXY')
        with self.assertRaises(ValueError):
            helper.guard_configuration({}, ['C:\\bad,path.exe'], 'PROXY')

    def test_rule_mode_accepts_dedicated_forced_route(self):
        chain = guard.validate_runtime(dict(RUNTIME, mode='rule'), PROXIES, rules=self.RULES, dedicated=True)
        self.assertEqual(chain[0], ('GLOBAL', 'chosen'))

    def test_rule_mode_rejects_any_direct_rule_ahead_of_guard_route(self):
        rules = [{'type': 'Match', 'payload': '', 'proxy': 'DIRECT'}] + self.RULES
        with self.assertRaises(guard.GuardError):
            guard.validate_runtime(dict(RUNTIME, mode='rule'), PROXIES, rules=rules, dedicated=True)

    def test_rule_mode_rejects_wrong_inbound_or_target(self):
        for field, value in [('payload', '7897'), ('proxy', 'DIRECT'), ('type', 'Domain')]:
            rules = copy.deepcopy(self.RULES)
            rules[0][field] = value
            with self.assertRaises(guard.GuardError):
                guard.validate_runtime(dict(RUNTIME, mode='rule'), PROXIES, rules=rules, dedicated=True)

    def test_direct_mode_remains_fatal_even_with_guard_rules(self):
        with self.assertRaises(guard.GuardError):
            guard.validate_runtime(dict(RUNTIME, mode='direct'), PROXIES, rules=self.RULES, dedicated=True)

    def test_live_route_rejects_foreign_listener_owner_and_missing_process_route(self):
        class Controller:
            server_pid = 123
            def get(self, path, **kwargs):
                if path == '/connections':
                    return {'connections': []}
                return {'rules': copy.deepcopy(RuleRoutingTests.RULES)}
        config = dict(CONFIG, proxy_url='http://127.0.0.1:17897')
        manifest = json.dumps({'programs': ['C:\\Apps\\Claude\\claude.exe']})
        with mock.patch.object(guard.Path, 'read_text', return_value=manifest), mock.patch.object(guard, 'listener_owned_by', return_value=True):
            self.assertEqual(guard.validate_live_route(config, Controller(), dict(RUNTIME, mode='rule'), PROXIES)[0], ('GLOBAL', 'chosen'))
        with mock.patch.object(guard.Path, 'read_text', return_value=manifest), mock.patch.object(guard, 'listener_owned_by', return_value=False):
            with self.assertRaises(guard.GuardError):
                guard.validate_live_route(config, Controller(), dict(RUNTIME, mode='rule'), PROXIES)
        wrong = json.dumps({'programs': ['C:\\Apps\\Claude\\other.exe']})
        with mock.patch.object(guard.Path, 'read_text', return_value=wrong), mock.patch.object(guard, 'listener_owned_by', return_value=True):
            with self.assertRaises(guard.GuardError):
                guard.validate_live_route(config, Controller(), dict(RUNTIME, mode='rule'), PROXIES)

    def test_exit_probe_and_https_recheck_use_the_dedicated_port(self):
        with mock.patch.object(guard.http.client, 'HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value.status = 200
            connection.return_value.getresponse.return_value.read.return_value = b'8.8.8.8'
            self.assertEqual(guard.proxy_exit_ip('api.ipify.org', '/', 5, port=17897), '8.8.8.8')
            self.assertEqual(connection.call_args.args, ('127.0.0.1', 17897))
            connection.return_value.getresponse.return_value.status = 204
            self.assertTrue(guard.proxy_connectivity('www.gstatic.com', '/generate_204', 5, port=17897))
            self.assertEqual(connection.call_args.args, ('127.0.0.1', 17897))

    def test_actual_direct_or_different_outbound_route_is_rejected(self):
        class Controller:
            server_pid = 123
            def get(self, path, **kwargs):
                if path == '/connections':
                    return {'connections': [{'metadata': {'inboundPort': '17897'}, 'chains': route}]}
                return {'rules': copy.deepcopy(RuleRoutingTests.RULES)}
        config = dict(CONFIG, proxy_url='http://127.0.0.1:17897')
        manifest = json.dumps({'programs': ['C:\\Apps\\Claude\\claude.exe']})
        for route in [['DIRECT'], ['another-node', 'GLOBAL']]:
            with mock.patch.object(guard.Path, 'read_text', return_value=manifest), mock.patch.object(guard, 'listener_owned_by', return_value=True):
                with self.assertRaises(guard.GuardError):
                    guard.validate_live_route(config, Controller(), dict(RUNTIME, mode='rule'), PROXIES)
class FirewallWatcherTests(unittest.TestCase):
    def watcher(self):
        self.clock = 0
        self.events = []
        with mock.patch.object(guard.threading, 'Thread'):
            return guard.FirewallWatcher(clock=lambda: self.clock,
                event_writer=lambda status, message, **kwargs: self.events.append(status))

    def test_transient_query_error_does_not_override_recent_verified_rules(self):
        watcher = self.watcher()
        watcher.accept({'ok': True, 'protected_programs': 14})
        self.clock = 1
        watcher.accept({'ok': False, 'code': 'checker_exception', 'error_category': 'COMException'})
        self.assertTrue(watcher.check()['ok'])
        self.assertEqual(watcher.last_time, 0)
        self.assertEqual(self.events, ['firewall-check-unavailable'])

    def test_repeated_query_errors_cannot_extend_freshness_deadline(self):
        watcher = self.watcher()
        watcher.accept({'ok': True})
        for second in range(1, 7):
            self.clock = second
            watcher.accept({'ok': False, 'code': 'checker_exception'})
        with self.assertRaisesRegex(guard.GuardError, '5'):
            watcher.check()

    def test_explicit_firewall_fault_is_immediate_and_latched(self):
        for code in ['profile_disabled', 'policy_overridden', 'rule_missing', 'rule_invalid',
                     'self_test_missing', 'self_test_failed']:
            watcher = self.watcher()
            watcher.accept({'ok': True})
            watcher.accept({'ok': False, 'code': code})
            with self.assertRaises(guard.GuardError):
                watcher.check()
            watcher.accept({'ok': True})
            with self.assertRaises(guard.GuardError):
                watcher.check()

    def test_query_error_before_first_valid_check_is_rejected(self):
        watcher = self.watcher()
        watcher.accept({'ok': False, 'code': 'checker_exception'})
        with self.assertRaises(guard.GuardError):
            watcher.check()

    def test_valid_recovery_updates_freshness_and_records_recovery(self):
        watcher = self.watcher()
        watcher.accept({'ok': True})
        self.clock = 1
        watcher.accept({'ok': False, 'code': 'checker_exception'})
        self.clock = 4
        watcher.accept({'ok': True})
        self.clock = 8
        self.assertTrue(watcher.check()['ok'])
        self.assertEqual(self.events, ['firewall-check-unavailable', 'firewall-check-recovered'])

    def test_invalid_checker_response_is_rejected(self):
        watcher = self.watcher()
        with self.assertRaises(ValueError):
            watcher.accept({'ok': 'true'})

    def test_persistent_verifier_launches_only_once_and_closes_on_cleanup(self):
        watcher = self.watcher()
        class FakeProcess:
            def __init__(self):
                self.terminated = False
                self.stdout = self
                self.lines = iter([b'{"ok":true}\n', b'{"ok":true}\n'])
            def readline(self, *_):
                try:
                    return next(self.lines)
                except StopIteration:
                    watcher.stop_event.set()
                    return b''
            def poll(self):
                return 0 if self.terminated else None
            def terminate(self):
                self.terminated = True
            def wait(self, **kwargs):
                return 0
            def close(self):
                pass
        process = FakeProcess()
        with mock.patch.object(guard.subprocess, 'Popen', return_value=process) as launch:
            watcher.worker()
        self.assertTrue(watcher.check()['ok'])
        self.assertEqual(launch.call_count, 1)
        self.assertIn('-Watch', launch.call_args.args[0])
        self.assertTrue(process.terminated)

    def test_verifier_process_exit_is_fail_closed(self):
        watcher = self.watcher()
        process = mock.Mock()
        process.stdout.readline.return_value = b''
        process.poll.return_value = 0
        with mock.patch.object(guard.subprocess, 'Popen', return_value=process):
            watcher.worker()
        with self.assertRaises(guard.GuardError):
            watcher.check()
        self.assertEqual(self.events, ['firewall-checker-stopped'])


if __name__ == '__main__':
    unittest.main()
