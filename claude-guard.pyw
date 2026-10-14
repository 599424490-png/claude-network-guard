"""Claude pre-launch checks and fail-closed runtime proxy monitoring."""
import argparse
import ctypes
import datetime
import glob
import http.client
import ipaddress
import io
import json
import os
import msvcrt
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
from ctypes import wintypes
import winreg

ROOT = Path(__file__).resolve().parent
IP_CHECKS = (("api.ipify.org", "/"), ("checkip.amazonaws.com", "/"), ("ipv4.icanhazip.com", "/"))
CONNECTIVITY_CHECKS = (("www.gstatic.com", "/generate_204"),
                       ("cp.cloudflare.com", "/generate_204"),
                       ("www.apple.com", "/library/test/success.html"))
LOCAL_BYPASS = "localhost;127.0.0.1;[::1]"
DIRECT_TYPES = {"direct", "reject", "rejectdrop", "pass", "compatible"}
NODE_TYPES = {"socks5", "http", "ss", "shadowsocks", "ssr", "shadowsocksr",
              "vmess", "vless", "trojan", "snell", "hysteria", "hysteria2",
              "tuic", "wireguard", "ssh", "anytls", "mieru"}


class GuardError(RuntimeError):
    pass


class ProbeUnavailable(GuardError):
    """A query failure is not evidence of direct routing or an upstream outage."""
    def __init__(self, message, diagnostics=None):
        super().__init__(message)
        self.diagnostics = diagnostics or []


class ControllerUnavailable(GuardError):
    pass


def proxy_port(config):
    return 17897 if config["proxy_url"] == "http://127.0.0.1:17897" else 7897


def load_config():
    config = json.loads((ROOT / "guard-config.json").read_text(encoding="utf-8-sig"))
    for name in ("claude_executable", "clash_config"):
        value = config.get(name)
        if not isinstance(value, str) or not value:
            raise GuardError("程序路径配置无效。")
        config[name] = os.path.expandvars(os.path.expanduser(value))
    if config.get("proxy_url") not in {"http://127.0.0.1:7897", "http://127.0.0.1:17897"}:
        raise GuardError("代理地址不在已核验范围。请先重新核验启动器配置。")
    timeout = config.get("request_timeout_seconds", 10)
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 30:
        raise GuardError("启动器超时配置无效。")
    if config.get("require_tun") is not True:
        raise GuardError("必须开启 TUN 检查，避免只检查网页代理而遗漏原生连接。")
    if config.get("require_firewall") is not True:
        raise GuardError("必须启用防火墙直连限制，拒绝启动。")
    for name, lower, upper in (("watch_interval_seconds", 0.1, 0.5),
                               ("controller_timeout_seconds", 0.2, 1),
                               ("runtime_check_interval_seconds", 0.25, 1),
                               ("remote_check_interval_seconds", 1, 15),
                               ("remote_timeout_seconds", 1, 10),
                               ("connectivity_timeout_seconds", 1, 10),
                               ("upstream_retry_delay_seconds", 0.25, 2)):
        value = config.get(name)
        if not isinstance(value, (int, float)) or not lower <= value <= upper:
            raise GuardError("后台网络监控配置无效，拒绝启动。")
    return config


def bounded_call(fn, seconds=6, on_start=None, on_timeout=None):
    result = queue.Queue(maxsize=1)

    def worker():
        try:
            result.put((True, fn()))
        except Exception as exc:
            result.put((False, exc))

    thread = threading.Thread(target=worker, daemon=True)
    if on_start:
        on_start(thread)
    thread.start()
    try:
        ok, value = result.get(timeout=seconds)
    except queue.Empty:
        if on_timeout:
            on_timeout(thread)
        raise ControllerUnavailable("读取 Clash 运行状态超时。") from None
    thread.join(0.05)
    if not ok:
        categories = []
        cause = value
        while cause is not None:
            category = {"error_category": type(cause).__name__}
            if isinstance(getattr(cause, "winerror", None), int):
                category["windows_error"] = cause.winerror
            categories.append(category)
            cause = cause.__cause__
        record("controller-query-failed", "Clash 本地接口读取失败。", diagnostics=categories)
        raise ControllerUnavailable("无法读取 Clash 运行状态。") from value
    return value


class Controller:
    def __init__(self, config):
        # The GUI's saved pipe path can be stale after service-side restarts.
        pipes = glob.glob(r"\\.\pipe\verge-mihomo-*")
        if len(pipes) != 1:
            raise GuardError("未找到唯一的 Clash 代理内核。请先启动 Clash Verge。")
        self.pipe = pipes[0]
        self.server_pid = None
        self.pending_worker = None
        self.secret = ""
        try:
            import yaml
            data = yaml.safe_load(Path(config["clash_config"]).read_text(encoding="utf-8")) or {}
            self.secret = str(data.get("secret", ""))
        except Exception:
            # Named-pipe API access is governed by local IPC permissions.
            # If this build also requires a token, a non-200 result blocks startup.
            pass
        if "\r" in self.secret or "\n" in self.secret:
            raise GuardError("代理控制器配置无效。")

    def get(self, path, timeout=6):
        if path not in {"/configs", "/proxies", "/rules", "/connections"}:
            raise GuardError("不允许的代理控制器请求。")
        pending = getattr(self, "pending_worker", None)
        if pending is not None and pending.is_alive():
            raise ControllerUnavailable("上一轮本地接口请求仍在取消中。")

        deadline = time.monotonic() + timeout
        cancelled = threading.Event()
        phase = ["open"]

        def ensure_active():
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise ControllerUnavailable("Clash 本地接口请求已过期。")

        def request():
            class PipeSocket:
                def __init__(self, pipe):
                    while True:
                        ensure_active()
                        try:
                            self.file = open(pipe, "r+b", buffering=0)
                            break
                        except OSError as exc:
                            # GUI/other clients can briefly occupy all pipe
                            # instances. Retry only ERROR_PIPE_BUSY, bounded
                            # by the original request deadline.
                            if getattr(exc, "winerror", None) != 231 or time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                    # HTTPResponse expects a buffered socket-style reader.
                    # Raw pipe reads can return just one fragment even when
                    # the HTTP Content-Length says more bytes are coming.
                    self.reader = io.BufferedReader(self.file)

                def makefile(self, *args, **kwargs):
                    return self.reader

            sock = PipeSocket(self.pipe)
            response = None
            try:
                ensure_active()
                if hasattr(self, "server_pid"):
                    owner = wintypes.DWORD()
                    handle = msvcrt.get_osfhandle(sock.file.fileno())
                    if not KERNEL.GetNamedPipeServerProcessId(handle, ctypes.byref(owner)):
                        raise GuardError("无法核验 Clash 控制器所属进程。")
                    self.server_pid = owner.value
                headers = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                if self.secret:
                    headers += f"Authorization: Bearer {self.secret}\r\n"
                request_bytes = (headers + "\r\n").encode("utf-8")
                written = 0
                phase[0] = "write"
                while written < len(request_bytes):
                    ensure_active()
                    size = sock.file.write(request_bytes[written:])
                    if not size:
                        raise OSError("Named pipe write failed")
                    written += size
                response = http.client.HTTPResponse(sock)
                phase[0] = "headers"
                response.begin()
                if response.status != 200:
                    raise GuardError("Clash 控制器拒绝查询。")
                phase[0] = "body"
                body = response.read(4 * 1024 * 1024 + 1)
                ensure_active()
                if len(body) > 4 * 1024 * 1024:
                    raise GuardError("Clash 控制器响应过大。")
                return json.loads(body)
            finally:
                if response is not None:
                    response.close()
                sock.reader.close()

        def retry_request():
            for attempt in range(3):
                ensure_active()
                try:
                    return request()
                except (OSError, ValueError, http.client.HTTPException):
                    if attempt == 2 or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)

        def cancel(thread):
            cancelled.set()
            # Cancel a blocking ReadFile/WriteFile instead of leaving one
            # additional pipe/thread alive after every timeout.
            handle = KERNEL.OpenThread(0x0001, False, thread.native_id)
            if handle:
                try:
                    KERNEL.CancelSynchronousIo(handle)
                finally:
                    KERNEL.CloseHandle(handle)
            thread.join(0.1)
            record("controller-query-timeout", "本地接口请求超时，已请求取消该次管道读取。",
                   diagnostics=[{"endpoint": path, "phase": phase[0], "worker_pending": thread.is_alive()}])

        return bounded_call(retry_request, timeout,
                            on_start=lambda thread: setattr(self, "pending_worker", thread), on_timeout=cancel)


def system_proxy_state():
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        def value(name, default=None):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return default
        return {"enabled": value("ProxyEnable", 0), "server": value("ProxyServer", ""),
                "pac": value("AutoConfigURL", ""), "bypass": value("ProxyOverride", "")}


def validate_system_proxy(state):
    if state["enabled"] != 1:
        raise GuardError("Windows 系统代理未开启。请在 Clash Verge 中开启系统代理。")
    if state["server"].strip().lower() not in {"127.0.0.1:7897", "http://127.0.0.1:7897"}:
        raise GuardError("Windows 当前代理不是已配置的 127.0.0.1:7897，拒绝启动。")
    if state["pac"]:
        raise GuardError("检测到 PAC 脚本，无法确认固定出口，拒绝启动。")


def resolve_proxy_chain(proxies, name="GLOBAL"):
    chain, visited = [], set()
    while True:
        if name in visited:
            raise GuardError("代理策略出现循环，拒绝启动。")
        visited.add(name)
        if name not in proxies:
            raise GuardError("代理策略引用未知节点，拒绝启动。")
        node = proxies[name]
        node_type = str(node.get("type", "")).lower()
        chain.append(name)
        if name.upper() in {"DIRECT", "REJECT", "PASS", "COMPATIBLE"} or node_type in DIRECT_TYPES:
            raise GuardError("当前代理策略包含直连或无效节点，拒绝启动。")
        if node.get("all") is not None:
            # Selector groups are explicitly chosen by the user. Auto-switching
            # and load-balancing groups cannot guarantee the same exit per host.
            if node_type != "selector" or not node.get("now"):
                raise GuardError("当前策略为自动切换或负载均衡，无法确认固定出口，拒绝启动。")
            name = node["now"]
            if name not in node["all"]:
                raise GuardError("代理策略的当前节点无效。")
            continue
        if node_type not in NODE_TYPES:
            raise GuardError("当前代理节点类型无法核验，拒绝启动。")
        if node.get("alive") is False:
            raise GuardError("当前代理节点不可用，拒绝启动。")
        return tuple(chain), node_type


def validate_runtime(runtime, proxies, require_tun=True, rules=None, dedicated=False, route_name="GLOBAL"):
    if runtime.get("mode") not in {"global", "rule"}:
        raise GuardError("Clash 处于直连或未知模式，拒绝运行。")
    if runtime.get("mode") == "rule" and not dedicated:
        raise GuardError("规则模式需要 Claude 专用的 127.0.0.1:17897 代理入口。")
    if dedicated:
        if not rules or rules[0].get("type") != "InPort" or str(rules[0].get("payload")) != "17897" or rules[0].get("proxy") != route_name:
            raise GuardError("Claude 专用入口的首条强制代理规则缺失或被修改。")
    if runtime.get("mixed-port") != 7897:
        raise GuardError("Clash 运行端口与系统代理不一致，拒绝启动。")
    tun = runtime.get("tun") or {}
    if require_tun and (tun.get("enable") is not True or tun.get("auto-route") is not True):
        raise GuardError("Clash TUN 或自动路由未开启，无法核验原生连接的出口，拒绝启动。")
    return resolve_proxy_chain(proxies, route_name if dedicated else "GLOBAL")


def validate_live_route(config, controller, runtime, proxies):
    dedicated = proxy_port(config) == 17897
    rules = controller.get("/rules", timeout=config.get("controller_timeout_seconds", 6))["rules"] if dedicated else None
    route_name = config.get("rule_proxy_name", "GLOBAL")
    chain = validate_runtime(runtime, proxies, config["require_tun"], rules, dedicated, route_name)
    if dedicated:
        try:
            programs = json.loads((ROOT / "firewall-manifest.json").read_text(encoding="utf-8-sig"))["programs"]
        except (OSError, ValueError, KeyError) as exc:
            raise GuardError("无法核验 Claude 程序的备用代理路由。") from exc
        if not programs or len(rules) < len(programs) + 1:
            raise GuardError("Claude 程序的备用代理路由不完整。")
        for program, rule in zip(programs, rules[1:]):
            if rule.get("type") != "ProcessPath" or str(rule.get("payload", "")).casefold() != str(program).casefold() or rule.get("proxy") != route_name:
                raise GuardError("Claude 程序的备用代理路由缺失或被覆盖。")
    if dedicated and not listener_owned_by(17897, controller.server_pid):
        raise GuardError("Claude 专用代理端口不属于已核验的 Clash 进程。")
    if dedicated:
        expected_paths = {str(path).casefold() for path in programs}
        connections = controller.get("/connections", timeout=config.get("controller_timeout_seconds", 6))["connections"]
        for connection in connections:
            metadata = connection.get("metadata") or {}
            protected = (str(metadata.get("inboundPort")) == "17897" or
                         metadata.get("inboundName") == "ClaudeNetworkGuard" or
                         str(metadata.get("processPath", "")).casefold() in expected_paths)
            if not protected:
                continue
            chains = connection.get("chains") or []
            if chains and (any(str(name).upper() == "DIRECT" for name in chains) or chain[0][-1] not in chains):
                raise GuardError("检测到 Claude 相关连接绕过选定代理节点，拒绝继续运行。")
            if not chains and (connection.get("upload", 0) or connection.get("download", 0)):
                raise GuardError("Claude 相关连接已有流量但无法确认其代理路线。")
    return chain


def proxy_exit_ip(host, path, timeout, port=7897):
    # Explicit CONNECT; environment NO_PROXY, PAC and redirect rules are ignored.
    # There is no direct connection or direct-IP comparison request.
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout,
                                       context=ssl.create_default_context())
    conn.set_tunnel(host, 443)
    try:
        conn.request("GET", path, headers={"Host": host, "Connection": "close",
                                          "User-Agent": "Claude-Prelaunch-Guard/1.0"})
        response = conn.getresponse()
        if response.status != 200:
            raise GuardError("代理出口查询失败或发生重定向，拒绝启动。")
        text = response.read(129).decode("ascii").strip()
        if len(text) > 128:
            raise GuardError("代理出口查询返回无效结果。")
        address = ipaddress.ip_address(text)
        if address.version != 4 or not address.is_global:
            raise GuardError("代理出口不是有效的公网 IPv4 地址。")
        return str(address)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise GuardError("代理出口查询超时或失败，拒绝启动。") from exc
    finally:
        conn.close()


def proxy_connectivity(host, path, timeout, port=7897):
    # TLS certificate validation and CONNECT are mandatory. No redirects,
    # alternative proxy or direct connection are attempted after a failure.
    if (host, path) not in CONNECTIVITY_CHECKS:
        raise GuardError("不允许的连通复核地址。")
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout,
                                       context=ssl.create_default_context())
    conn.set_tunnel(host, 443)
    try:
        conn.request("GET", path, headers={"Host": host, "Connection": "close",
                                          "User-Agent": "Claude-Prelaunch-Guard/1.0"})
        response = conn.getresponse()
        if host == "www.apple.com":
            if response.status != 200 or b"<TITLE>Success</TITLE>" not in response.read(1025):
                raise ProbeUnavailable("HTTPS 连通复核未取得预期响应。")
        elif response.status != 204:
            raise ProbeUnavailable("HTTPS 连通复核未取得预期响应。")
        return True
    finally:
        conn.close()


KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]
KERNEL.CloseHandle.restype = wintypes.BOOL
KERNEL.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
KERNEL.OpenThread.restype = wintypes.HANDLE
KERNEL.CancelSynchronousIo.argtypes = [wintypes.HANDLE]
KERNEL.CancelSynchronousIo.restype = wintypes.BOOL
KERNEL.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
KERNEL.GetNamedPipeServerProcessId.restype = wintypes.BOOL


class TcpOwnerRow(ctypes.Structure):
    _fields_ = [(name, wintypes.DWORD) for name in ("state", "local_address", "local_port", "remote_address", "remote_port", "pid")]


def listener_owned_by(port, pid):
    if not pid:
        return False
    api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                    wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    api.restype = wintypes.DWORD
    size = wintypes.DWORD()
    api(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if not 4 <= size.value <= 4 * 1024 * 1024:
        raise GuardError("无法读取本机代理监听端口。")
    buffer = ctypes.create_string_buffer(size.value)
    if api(buffer, ctypes.byref(size), False, socket.AF_INET, 3, 0) != 0:
        raise GuardError("无法核验本机代理监听端口。")
    count = wintypes.DWORD.from_buffer(buffer).value
    if 4 + count * ctypes.sizeof(TcpOwnerRow) > size.value:
        raise GuardError("代理监听端口表无效。")
    matches = []
    for index in range(count):
        row = TcpOwnerRow.from_buffer(buffer, 4 + index * ctypes.sizeof(TcpOwnerRow))
        if socket.ntohs(row.local_port & 0xFFFF) == port:
            matches.append(row.pid == pid and row.local_address == int.from_bytes(socket.inet_aton("127.0.0.1"), "little"))
    return bool(matches) and all(matches)
KERNEL.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
KERNEL.CreateToolhelp32Snapshot.restype = wintypes.HANDLE


class ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]


for function in (KERNEL.Process32FirstW, KERNEL.Process32NextW):
    function.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    function.restype = wintypes.BOOL


def claude_pids():
    snapshot = KERNEL.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise GuardError("无法读取 Claude 进程状态。")
    try:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = []
        ok = KERNEL.Process32FirstW(snapshot, ctypes.byref(entry))
        if not ok and ctypes.get_last_error() != 18:
            raise GuardError("无法枚举 Claude 进程。")
        while ok:
            if entry.szExeFile.lower() == "claude.exe":
                found.append(entry.th32ProcessID)
            ok = KERNEL.Process32NextW(snapshot, ctypes.byref(entry))
        return found
    finally:
        KERNEL.CloseHandle(snapshot)


def running_claude():
    return bool(claude_pids())


class BasicJobLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                 "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class ExtendedJobLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", BasicJobLimits), ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


KERNEL.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
KERNEL.CreateJobObjectW.restype = wintypes.HANDLE
KERNEL.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
KERNEL.SetInformationJobObject.restype = wintypes.BOOL
KERNEL.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
KERNEL.IsProcessInJob.restype = wintypes.BOOL
KERNEL.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
KERNEL.AssignProcessToJobObject.restype = wintypes.BOOL
KERNEL.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
KERNEL.TerminateJobObject.restype = wintypes.BOOL
KERNEL.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
KERNEL.CreateMutexW.restype = wintypes.HANDLE


class MonitorMutex:
    def __init__(self):
        ctypes.set_last_error(0)
        self.handle = KERNEL.CreateMutexW(None, False, "Local\\ClaudeNetworkGuard-v1")
        error = ctypes.get_last_error()
        if not self.handle:
            raise GuardError("无法创建后台监控锁。")
        if error == 183:
            self.close()
            raise GuardError("Claude 网络保护已经在运行，无需重复启动。")

    def close(self):
        if self.handle:
            KERNEL.CloseHandle(self.handle)
            self.handle = None


class ProcessJob:
    """Windows kills assigned processes when the guard's last job handle closes."""
    def __init__(self):
        self.handle = KERNEL.CreateJobObjectW(None, None)
        if not self.handle:
            raise GuardError("无法创建 Claude 进程保护。")
        limits = ExtendedJobLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not KERNEL.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise GuardError("无法启用监控退出时自动关闭 Claude 的保护。")

    def attach(self, pids):
        for pid in pids:
            process = KERNEL.OpenProcess(0x0100 | 0x0001 | 0x0400, False, pid)
            if not process:
                if ctypes.get_last_error() == 87:  # Process already exited.
                    continue
                raise GuardError("无法接管 Claude 进程，不能保持后台保护。")
            try:
                assigned = wintypes.BOOL()
                if not KERNEL.IsProcessInJob(process, self.handle, ctypes.byref(assigned)):
                    raise GuardError("无法核验 Claude 进程保护。")
                if not assigned.value and not KERNEL.AssignProcessToJobObject(self.handle, process):
                    # A process can finish naturally between enumeration and assignment.
                    if pid not in claude_pids():
                        continue
                    raise GuardError("无法给 Claude 绑定后台保护。")
            finally:
                KERNEL.CloseHandle(process)

    def terminate(self):
        if self.handle:
            KERNEL.TerminateJobObject(self.handle, 1)

    def close(self):
        if self.handle:
            KERNEL.CloseHandle(self.handle)
            self.handle = None


def check_firewall(raw=False):
    try:
        executable = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                 "-File", str(ROOT / "check-firewall.ps1")],
                                capture_output=True, timeout=4, creationflags=subprocess.CREATE_NO_WINDOW)
        data = json.loads(result.stdout.decode("utf-8-sig"))
        if raw and result.returncode in (0, 1) and isinstance(data.get("ok"), bool):
            return data
        if result.returncode != 0 or data.get("ok") is not True:
            raise GuardError("防火墙直连限制尚未生效或已失效。请完成管理员安装后重试。")
        return data
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise GuardError("无法核验防火墙直连限制，拒绝保持 Claude 运行。") from exc


class FirewallWatcher:
    def __init__(self, checker=None, clock=time.monotonic, event_writer=None, recovery_checker=None):
        self.checker, self.clock = checker, clock
        self.event_writer = event_writer or record
        self.ready = threading.Event()
        self.stop_event = threading.Event()
        self.restart_event = threading.Event()
        self.lock = threading.Lock()
        self.recovery_lock = threading.Lock()
        self.last_result = self.last_time = None
        self.process = None
        self.query_unavailable = False
        self.policy_fault = None
        self.last_phase = "starting"
        self.verified_once = False
        self.recovery_checker = recovery_checker or (lambda: check_firewall(raw=True))
        threading.Thread(target=self.worker, daemon=True).start()

    def publish(self, result):
        with self.lock:
            self.last_result, self.last_time = result, self.clock()
        self.ready.set()

    def accept(self, data):
        if data.get("kind") == "progress":
            phase = data.get("phase")
            if phase not in {"profiles", "self-test", "rules", "programs", "validate"}:
                raise ValueError("Invalid firewall verification phase")
            self.last_phase = phase  # A heartbeat is not a successful policy check.
            return
        if self.policy_fault is not None:
            return  # A detected policy failure stays fatal until relaunch.
        if data.get("ok") is True:
            self.verified_once = True
            self.last_phase = "complete"
            if self.query_unavailable:
                self.event_writer("firewall-check-recovered", "防火墙核验工具已恢复，规则仍有效。")
            self.query_unavailable = False
            self.publish((True, data))
            return
        if data.get("ok") is not False:
            raise ValueError("Invalid firewall verification response")
        code = data.get("code", "unknown")
        if code == "checker_exception":
            if not self.query_unavailable:
                self.event_writer("firewall-check-unavailable", "防火墙核验工具读取异常，正在重试。",
                                  diagnostics=[{"error_category": str(data.get("error_category", "unknown"))[:120]}])
            self.query_unavailable = True
            with self.lock:
                last = self.last_result
            # An unreadable query does not extend the latest successful check.
            # The strict five-second freshness limit still applies.
            if last and last[0]:
                return
            self.publish((False, GuardError("防火墙核验工具无法读取规则，尚未取得有效核验结果。")))
            return
        reasons = {"profile_disabled": "Windows 防火墙被关闭。",
                   "policy_overridden": "防火墙规则被系统策略覆盖。",
                   "self_test_missing": "防火墙安装验证记录缺失。",
                   "self_test_failed": "防火墙安装验证未通过。",
                   "rule_missing": "防火墙规则缺失，或出现尚未覆盖的新程序。",
                   "rule_invalid": "防火墙规则被修改，直连限制不完整。"}
        message = reasons.get(code, "防火墙核验返回未知异常，无法保持保护。")
        self.event_writer("firewall-policy-fault", message, diagnostics=[{"error_category": code}])
        self.policy_fault = GuardError(message)
        self.publish((False, self.policy_fault))

    def worker(self):
        if self.checker is not None:
            while not self.stop_event.is_set():
                try:
                    self.publish((True, self.checker()))
                except Exception as exc:
                    self.publish((False, exc))
                self.stop_event.wait(1)
            return
        while not self.stop_event.is_set():
            process = None
            self.restart_event.clear()
            try:
                executable = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
                process = subprocess.Popen([str(executable), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                            "-File", str(ROOT / "check-firewall.ps1"), "-Watch"],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                           creationflags=subprocess.CREATE_NO_WINDOW)
                self.process = process
                while not self.stop_event.is_set() and not self.restart_event.is_set():
                    line = process.stdout.readline(16385)
                    if self.stop_event.is_set() or self.restart_event.is_set():
                        break
                    if not line or len(line) > 16384:
                        raise GuardError("防火墙核验进程已退出或返回无效响应。")
                    self.accept(json.loads(line.decode("utf-8-sig")))
            except Exception as exc:
                if not self.stop_event.is_set() and not self.restart_event.is_set():
                    self.event_writer("firewall-checker-stopped", "防火墙核验进程异常结束。",
                                      diagnostics=[{"error_category": type(exc).__name__}])
                    self.publish((False, GuardError("防火墙核验进程异常，无法持续确认保护。")))
                    # Only a successful independent recheck may authorize restart.
                    if not self.verified_once or not self.restart_event.wait(5):
                        return
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    if process.stdout:
                        process.stdout.close()

    def check(self):
        if not self.ready.wait(10):
            raise GuardError("防火墙核验进程未能及时启动。")
        with self.lock:
            result, timestamp = self.last_result, self.last_time
        if self.policy_fault is not None:
            raise self.policy_fault
        if result and result[0] and self.clock() - timestamp <= 5:
            return result[1]
        if not self.verified_once:
            message = str(result[1]) if result and isinstance(result[1], GuardError) else "防火墙核验失败。"
            raise GuardError(message) from (result[1] if result else None)
        with self.recovery_lock:
            with self.lock:
                result, timestamp = self.last_result, self.last_time
            if self.policy_fault is not None:
                raise self.policy_fault
            if result and result[0] and self.clock() - timestamp <= 5:
                return result[1]
            process = self.process
            self.event_writer("firewall-verifier-rechecking", "常驻核验器未及时回报，独立复核实际防火墙规则。",
                              diagnostics=[{"phase": self.last_phase,
                                            "age_seconds": round(self.clock() - timestamp, 2),
                                            "checker_pid": getattr(process, "pid", None)}])
            failure = None
            try:
                self.accept(self.recovery_checker())
            except Exception as exc:
                failure = exc
            if self.policy_fault is not None:
                raise self.policy_fault
            with self.lock:
                result, timestamp = self.last_result, self.last_time
            if not result or not result[0] or self.clock() - timestamp > 5:
                raise GuardError("防火墙核验超过 5 秒未更新，独立复核也未通过，无法持续确认保护。") from failure
            self.restart_event.set()
            if process is not None and process.poll() is None:
                process.terminate()  # Only this watcher's checker; no firewall changes.
            self.event_writer("firewall-verifier-recovered", "独立核验通过，已恢复常驻检查；直连限制仍有效。")
            return result[1]

    def close(self):
        self.stop_event.set()
        self.restart_event.set()
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()


def force_close_claude():
    """Kill all Claude image instances and their process trees, never the proxy."""
    if not claude_pids():
        return True
    try:
        subprocess.run([str(Path(os.environ["WINDIR"]) / "System32/taskkill.exe"),
                        "/F", "/T", "/IM", "claude.exe"], capture_output=True,
                       timeout=4, creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        pass
    # Job termination is asynchronous: wait for teardown before kill-failed.
    deadline = time.monotonic() + 2
    while claude_pids():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def local_proxy_alive(port=7897):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        raise GuardError("本地代理端口已断开。") from None


class ParallelProxyProbe:
    def __init__(self, timeout, endpoints, probe, clock):
        self.clock = clock
        self.deadline = clock() + timeout
        self.started = clock()
        self.endpoints = endpoints
        self.results = queue.Queue()
        self.values = []
        self.outcomes = []
        self.completed = 0

        def worker(host, path):
            started = clock()
            try:
                value = probe(host, path, timeout)
                ok, category = True, None
            except Exception as exc:
                ok, value = False, None
                # Only exception classes are logged, never IPs, response
                # bodies, credentials or raw exception messages.
                category = type(exc.__cause__ or exc).__name__
            outcome = {"endpoint": host, "ok": ok,
                       "seconds": round(clock() - started, 2)}
            if category:
                outcome["error_category"] = category
            self.results.put((ok, value, outcome))

        # Daemon probes never block local proxy/policy/firewall monitoring.
        for host, path in endpoints:
            threading.Thread(target=worker, args=(host, path), daemon=True).start()

    def drain(self):
        while True:
            try:
                ok, value, outcome = self.results.get_nowait()
            except queue.Empty:
                break
            self.completed += 1
            self.outcomes.append(outcome)
            if ok:
                self.values.append(value)

    def diagnostics(self):
        outcomes = list(self.outcomes)
        completed = {entry["endpoint"] for entry in outcomes}
        for host, _ in self.endpoints:
            if host not in completed:
                outcomes.append({"endpoint": host, "ok": False,
                                 "seconds": round(self.clock() - self.started, 2),
                                 "error_category": "pending-or-deadline"})
        return outcomes


class ExitProbe(ParallelProxyProbe):
    def __init__(self, timeout, probe=proxy_exit_ip, clock=time.monotonic, expected_ip=None, port=7897):
        self.expected_ip = expected_ip
        if probe is proxy_exit_ip:
            probe = lambda host, path, seconds: proxy_exit_ip(host, path, seconds, port=port)
        super().__init__(timeout, IP_CHECKS, probe, clock)

    def poll(self):
        self.drain()
        if self.expected_ip and any(address != self.expected_ip for address in self.values):
            raise GuardError("运行期间代理出口 IP 已改变。")
        if len(set(self.values)) > 1:
            raise GuardError("运行中的代理出口 IP 不一致。")
        if len(self.values) >= 2:
            return self.values[0]
        if len(self.values) + len(IP_CHECKS) - self.completed < 2:
            raise ProbeUnavailable("出口查询服务未能取得至少两个一致结果。", self.diagnostics())
        if self.clock() >= self.deadline:
            raise ProbeUnavailable("出口查询服务超过本轮截止时间。", self.diagnostics())
        return None


class ConnectivityProbe(ParallelProxyProbe):
    def __init__(self, timeout, probe=proxy_connectivity, clock=time.monotonic, port=7897):
        if probe is proxy_connectivity:
            probe = lambda host, path, seconds: proxy_connectivity(host, path, seconds, port=port)
        super().__init__(timeout, CONNECTIVITY_CHECKS, probe, clock)

    def poll(self):
        self.drain()
        # One certificate-validated, expected HTTPS response proves the proxy
        # is still carrying Internet traffic. Other services can be down.
        if True in self.values:
            return True
        if self.completed == len(self.endpoints) or self.clock() >= self.deadline:
            return False
        return None


def monitor_status(status, pids=None, message=None):
    try:
        state = {"status": status, "guard_pid": os.getpid(),
                 "updated_at": datetime.datetime.now().astimezone().isoformat(),
                 "protected_processes": pids or []}
        if message:
            state["message"] = message
        temporary = ROOT / "monitor-state.tmp"
        temporary.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        temporary.replace(ROOT / "monitor-state.json")
    except OSError:
        pass


class RouteRecheck:
    """One fresh route snapshot with a shared deadline for all API reads."""
    def __init__(self, controller, seconds, clock=time.monotonic):
        self.controller, self.clock = controller, clock
        self.deadline = clock() + seconds

    @property
    def server_pid(self):
        return self.controller.server_pid

    def get(self, path, **kwargs):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise ControllerUnavailable("独立路由复核已超时。")
        result = self.controller.get(path, timeout=remaining)
        if self.clock() >= self.deadline:
            raise ControllerUnavailable("独立路由复核已超时。")
        return result


class NetworkMonitor:
    def __init__(self, config, controller, baseline, job, clock=time.monotonic,
                 process_reader=claude_pids, state_reader=system_proxy_state,
                 port_check=None, probe_factory=ExitProbe, state_writer=monitor_status,
                 firewall_checker=check_firewall, connectivity_factory=ConnectivityProbe,
                 event_writer=None):
        self.config, self.controller, self.baseline, self.job = config, controller, baseline, job
        self.clock, self.process_reader = clock, process_reader
        self.state_reader = state_reader
        self.port_check = port_check or (lambda: local_proxy_alive(proxy_port(config)))
        self.probe_factory, self.state_writer = probe_factory, state_writer
        self.firewall_checker = firewall_checker
        self.connectivity_factory = connectivity_factory
        self.event_writer = event_writer or record
        self.saw_processes = False
        self.start_deadline = clock() + 10
        self.next_runtime = self.next_probe = self.next_status = 0
        self.probe = None
        self.connectivity_probe = None
        self.next_connectivity = None
        self.failed_connectivity_rounds = 0
        self.exit_degraded = False
        self.last_runtime_ok = clock()
        self.runtime_degraded = False

    def read_route(self, controller):
        timeout = self.config["controller_timeout_seconds"]
        runtime = controller.get("/configs", timeout=timeout)
        proxies = controller.get("/proxies", timeout=timeout)["proxies"]
        return validate_live_route(self.config, controller, runtime, proxies)

    def step(self):
        pids = self.process_reader()
        if pids:
            self.saw_processes = True
            self.job.attach(pids)
        elif self.saw_processes:
            return False  # User fully exited Claude normally.
        elif self.clock() > self.start_deadline:
            raise GuardError("Claude 未能在保护下正常启动。")
        validate_system_proxy(self.state_reader())
        self.port_check()
        now = self.clock()
        if now >= self.next_runtime:
            self.firewall_checker()
            chain = None
            try:
                chain = self.read_route(self.controller)
            except ControllerUnavailable:
                if not self.runtime_degraded:
                    self.event_writer("controller-check-unavailable", "Clash 本地接口暂不可读，正在有限重试。")
                self.runtime_degraded = True
                if self.clock() - self.last_runtime_ok > 5:
                    self.event_writer("controller-route-rechecking", "路由核验未及时回报，重新读取完整代理路线。",
                                      diagnostics=[{"age_seconds": round(self.clock() - self.last_runtime_ok, 2)}])
                    self.firewall_checker()
                    self.port_check()
                    try:
                        chain = self.read_route(RouteRecheck(self.controller, 4, self.clock))
                    except ControllerUnavailable as exc:
                        raise GuardError("Clash 路由核验超过 5 秒未更新，独立复核也未通过，无法确认代理路线。") from exc
                self.next_runtime = self.clock() + self.config["watch_interval_seconds"]
            if chain is not None:
                if list(chain[0]) != self.baseline["chain"]:
                    raise GuardError("运行期间所选代理节点发生变化。")
                if self.runtime_degraded:
                    self.event_writer("controller-check-recovered", "Clash 路由核验已恢复，代理路线保持有效。")
                self.runtime_degraded = False
                self.last_runtime_ok = self.clock()
                self.next_runtime = self.clock() + self.config["runtime_check_interval_seconds"]
        if self.probe is not None:
            try:
                address = self.probe.poll()
            except ProbeUnavailable as exc:
                self.event_writer("remote-check-degraded",
                                  "出口查询暂不可用，开始独立 HTTPS 连通复核。",
                                  diagnostics=exc.diagnostics)
                self.probe = None
                self.next_probe = float("inf")
                self.next_connectivity = self.clock()
                self.exit_degraded = True
                address = None
            if address is not None:
                if address != self.baseline["exit_ip"]:
                    raise GuardError("运行期间代理出口 IP 已改变。")
                if self.exit_degraded:
                    self.event_writer("remote-check-recovered", "出口查询已恢复，出口与启动时一致。")
                self.exit_degraded = False
                self.probe = None
                self.next_probe = self.clock() + self.config["remote_check_interval_seconds"]
        if self.connectivity_probe is not None:
            reachable = self.connectivity_probe.poll()
            if reachable is not None:
                diagnostics = self.connectivity_probe.diagnostics()
                self.connectivity_probe = None
                if reachable:
                    self.event_writer("remote-check-healthy",
                                      "独立 HTTPS 复核通过，继续保持 Claude 和防火墙保护。",
                                      diagnostics=diagnostics)
                    self.failed_connectivity_rounds = 0
                    self.next_connectivity = None
                    self.next_probe = self.clock() + self.config["remote_check_interval_seconds"]
                else:
                    self.failed_connectivity_rounds += 1
                    self.event_writer("upstream-recheck-failed",
                                      f"独立 HTTPS 复核第 {self.failed_connectivity_rounds}/2 轮全部失败。",
                                      diagnostics=diagnostics)
                    if self.failed_connectivity_rounds >= 2:
                        raise GuardError("出口查询异常，且连续两轮独立 HTTPS 复核均失败，按代理上游不可用处理。")
                    self.next_connectivity = self.clock() + self.config["upstream_retry_delay_seconds"]
        if (self.connectivity_probe is None and self.next_connectivity is not None
                and self.clock() >= self.next_connectivity):
            self.connectivity_probe = self.connectivity_factory(self.config["connectivity_timeout_seconds"], port=proxy_port(self.config))
        if self.probe is None and self.clock() >= self.next_probe:
            self.probe = self.probe_factory(self.config["remote_timeout_seconds"],
                                            expected_ip=self.baseline["exit_ip"], port=proxy_port(self.config))
        if self.clock() >= self.next_status:
            message = None
            if self.exit_degraded:
                message = ("出口查询暂不可用，正在独立 HTTPS 复核；防火墙保护仍有效。"
                           if self.next_connectivity is not None else
                           "出口查询暂不可用，独立 HTTPS 连通复核通过；防火墙保护仍有效。")
            self.state_writer("active", pids, message=message)
            self.next_status = self.clock() + 2
        return True


def supervise(monitor, close_claude=force_close_claude, sleeper=time.sleep):
    try:
        while monitor.step():
            sleeper(monitor.config["watch_interval_seconds"])
    except BaseException:
        # Terminate the owned process tree before displaying any dialog or
        # writing logs; a reporting failure cannot postpone the kill action.
        try:
            monitor.job.terminate()
        finally:
            close_claude()
        raise


def preflight(config, controller, state_reader=system_proxy_state, ip_probe=proxy_exit_ip,
              running_check=running_claude, network_only=False):
    if not network_only and running_check():
        raise GuardError("Claude 已在运行。请先从托盘彻底退出，再通过此快捷方式启动。")
    initial_system = state_reader()
    validate_system_proxy(initial_system)
    runtime = controller.get("/configs")
    proxies = controller.get("/proxies")["proxies"]
    chain = validate_live_route(config, controller, runtime, proxies)
    # TCP connectivity here stays on loopback; the first Internet requests only
    # happen after global non-DIRECT routing is established.
    exit_probe = ExitProbe(config["request_timeout_seconds"], probe=ip_probe, port=proxy_port(config))
    while True:
        address = exit_probe.poll()
        if address is not None:
            break
        time.sleep(0.05)
    allowed = config.get("allowed_exit_ips", [])
    if allowed and address not in allowed:
        raise GuardError("当前出口 IP 不在你配置的允许列表中，拒绝启动。")
    # Re-read the live kernel and Windows proxy immediately before launch.
    final_system = state_reader()
    validate_system_proxy(final_system)
    final_runtime = controller.get("/configs")
    final_chain = validate_live_route(config, controller, final_runtime, controller.get("/proxies")["proxies"])
    if final_chain != chain or final_system != initial_system:
        raise GuardError("检查期间代理设置或节点发生变化，拒绝启动。")
    if not network_only and running_check():
        raise GuardError("检查期间 Claude 已被其他入口启动，请先退出后重试。")
    return {"proxy": config["proxy_url"], "exit_ip": address, "chain": list(chain[0]),
            "mode": final_runtime["mode"], "tun": True}


def claude_binary(config):
    configured = Path(config["claude_executable"])
    # Launch the actual application, not Squirrel's shell-dispatched stub.
    # Shell dispatch can escape the parent's Windows Job.
    versions = []
    for directory in configured.parent.glob("app-*"):
        binary = directory / "claude.exe"
        try:
            version = tuple(int(part) for part in directory.name[4:].split("."))
        except ValueError:
            continue
        required_assets = (directory / "resources/app.asar", directory / "icudtl.dat", directory / "resources.pak")
        if binary.is_file() and all(asset.is_file() for asset in required_assets):
            versions.append((version, binary))
    if not versions:
        raise GuardError("未找到完整的 Claude 程序，可能有更新尚未完成。请先修复安装。")
    return max(versions)[1]


class StartupInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class ProcessInformation(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


KERNEL.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                  ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.LPCWSTR,
                                  ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInformation)]
KERNEL.CreateProcessW.restype = wintypes.BOOL
KERNEL.ResumeThread.argtypes = [wintypes.HANDLE]
KERNEL.ResumeThread.restype = wintypes.DWORD
KERNEL.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
KERNEL.TerminateProcess.restype = wintypes.BOOL


def start_suspended(executable, arguments, env, cwd, job):
    startup = StartupInfo()
    startup.cb = ctypes.sizeof(startup)
    process = ProcessInformation()
    command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(executable)] + arguments))
    environment = ctypes.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in
                                              sorted(env.items(), key=lambda item: item[0].upper())) + "\0\0")
    if not KERNEL.CreateProcessW(str(executable), command, None, None, False, 0x4 | 0x400,
                                  environment, str(cwd), ctypes.byref(startup), ctypes.byref(process)):
        raise GuardError("无法创建受保护的 Claude 进程。")
    try:
        # No application instruction, network request or child process can run
        # before assignment to the kill-on-close Job succeeds.
        job.attach([process.dwProcessId])
        if KERNEL.ResumeThread(process.hThread) == 0xFFFFFFFF:
            raise GuardError("无法恢复受保护的 Claude 进程。")
        return process.dwProcessId
    except BaseException:
        KERNEL.TerminateProcess(process.hProcess, 1)
        raise
    finally:
        KERNEL.CloseHandle(process.hThread)
        KERNEL.CloseHandle(process.hProcess)


def launch(config, job=None):
    executable = claude_binary(config) if job is not None else Path(config["claude_executable"])
    if not executable.is_file():
        raise GuardError("未找到 Claude 桌面版程序。")
    env = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env[name] = config["proxy_url"]
    for name in ("NO_PROXY", "no_proxy"):
        env[name] = "localhost,127.0.0.1,::1"
    arguments = ["--proxy-server=" + config["proxy_url"], "--proxy-bypass-list=" + LOCAL_BYPASS, "--disable-quic"]
    if job is not None:
        return start_suspended(executable, arguments, env, executable.parent, job)
    return subprocess.Popen([str(executable)] + arguments,
                            cwd=str(executable.parent), env=env, close_fds=True)


def record(status, message, details=None, diagnostics=None):
    try:
        entry = {"time": datetime.datetime.now().astimezone().isoformat(),
                 "status": status, "message": message}
        if details:
            # Never record exit IP, node credentials or Claude account data.
            entry["proxy"] = details["proxy"]
            entry["mode"] = details["mode"]
        if diagnostics:
            entry["diagnostics"] = diagnostics
        with (ROOT / "guard.log").open("a", encoding="utf-8") as output:
            output.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="核验启动条件，不启动 Claude")
    parser.add_argument("--check-network", action="store_true", help="仅检查网络，不启动或关闭 Claude")
    parser.add_argument("--monitor-existing", action="store_true", help="给已运行的 Claude 接上后台保护")
    args = parser.parse_args()
    job = mutex = firewall_watcher = None
    protected = False
    try:
        config = load_config()
        checking = args.check or args.check_network
        if not checking:
            mutex = MonitorMutex()
        if args.monitor_existing and not checking:
            raise GuardError("已有实例不能安全接管。请彻底退出 Claude，再使用受保护的快捷方式重新启动。")
        controller = Controller(config)
        firewall_watcher = FirewallWatcher()
        firewall_watcher.check()
        details = preflight(config, controller, network_only=args.check_network or args.monitor_existing)
        if args.check or args.check_network:
            print(json.dumps({"ok": True, "launched": False, **details}, ensure_ascii=True))
            return 0
        job = ProcessJob()
        launch(config, job)
        protected = True
        record("monitor-starting", "网络检查通过，开始后台网络保护。", details)
        monitor = NetworkMonitor(config, controller, details, job, firewall_checker=firewall_watcher.check)
        supervise(monitor)
        monitor_status("stopped")
        record("stopped", "Claude 已正常退出，后台保护结束。")
        return 0
    except BaseException as exc:
        message = str(exc) if isinstance(exc, GuardError) else "启动器检查失败，已阻止启动。请查看配置和代理状态。"
        if protected:
            if job:
                job.terminate()
            closed = force_close_claude()
            monitor_status("killed" if closed else "kill-failed", message=message)
            record("killed" if closed else "kill-failed", message)
            message += "\n\n" + ("已强制关闭 Claude 及其子进程。" if closed else "已发出强制关闭指令，但仍检测到 Claude 进程。")
        else:
            record("blocked", message)
        if args.check or args.check_network:
            print(json.dumps({"ok": False, "launched": False, "error": message}, ensure_ascii=True))
        else:
            if not protected:
                message += "\n\nClaude 未通过本启动器启动。"
            ctypes.windll.user32.MessageBoxW(None, message, "Claude 网络保护", 0x10)
        return 1
    finally:
        if job:
            job.close()
        if mutex:
            mutex.close()
        if firewall_watcher:
            firewall_watcher.close()


if __name__ == "__main__":
    sys.exit(main())
