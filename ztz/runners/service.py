"""
Background service management for the ZTZ proxy (`ztz service install|uninstall|status`).

Installs `ztz proxy` as a per-user service, no admin rights required:
- Linux:   systemd user unit   ~/.config/systemd/user/ztz-proxy.service
- macOS:   launchd LaunchAgent ~/Library/LaunchAgents/com.zerotrustzone.proxy.plist
- Windows: Task Scheduler logon task "ZeroTrustZone Proxy" (hidden, pythonw.exe)

The proxy logs to ~/.ztz/logs/proxy.log. Ollama / LM Studio configuration is never
touched: moving the backend to the upstream port is left to the user.
"""

import os
import plistlib
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence
from xml.sax.saxutils import escape

UNIT_NAME = "ztz-proxy.service"
LAUNCHD_LABEL = "com.zerotrustzone.proxy"
TASK_NAME = "ZeroTrustZone Proxy"


def current_platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if os.name == "nt":
        return "windows"
    return sys.platform


@dataclass
class ServiceConfig:
    host: str = "127.0.0.1"
    port: int = 11434
    upstream_port: int = 11435
    trust_store: Optional[str] = None
    no_cache: bool = False
    log_file: str = field(default_factory=lambda: os.path.normpath(os.path.expanduser("~/.ztz/logs/proxy.log")))

    def proxy_args(self) -> List[str]:
        # The service runs from an arbitrary cwd, so every path must be absolute.
        args = ["-m", "ztz", "proxy", "--host", self.host, "--port", str(self.port),
                "--upstream-port", str(self.upstream_port), "--log-file", os.path.abspath(self.log_file)]
        if self.trust_store:
            args += ["--trust-store", os.path.abspath(self.trust_store)]
        if self.no_cache:
            args.append("--no-cache")
        return args


def python_executable(platform: str) -> str:
    exe = sys.executable
    if platform == "windows":
        # pythonw has no console window, so the logon task stays invisible.
        pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(pythonw):
            return pythonw
    return exe


def service_file(platform: str) -> str:
    if platform == "linux":
        return os.path.normpath(os.path.expanduser(f"~/.config/systemd/user/{UNIT_NAME}"))
    if platform == "darwin":
        return os.path.normpath(os.path.expanduser(f"~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist"))
    if platform == "windows":
        return os.path.normpath(os.path.expanduser("~/.ztz/service/ztz-proxy.xml"))
    raise ValueError(f"Unsupported platform for 'ztz service': {platform}")


def render(platform: str, cfg: ServiceConfig, python: str) -> bytes:
    """Service definition file contents for platform."""
    argv = [python] + cfg.proxy_args()
    if platform == "linux":
        return (
            "[Unit]\n"
            "Description=ZeroTrustZone pre-flight proxy (Ollama / LM Studio)\n"
            "After=network.target\n\n"
            "[Service]\n"
            f"ExecStart={' '.join(_systemd_quote(a) for a in argv)}\n"
            "Restart=on-failure\n"
            "RestartSec=5\n\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        ).encode("utf-8")
    if platform == "darwin":
        return plistlib.dumps({
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": argv,
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
        })
    if platform == "windows":
        user = os.environ.get("USERNAME", "")
        domain = os.environ.get("USERDOMAIN", "")
        user_id = escape(f"{domain}\\{user}" if domain else user)
        return (
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            "  <RegistrationInfo><Description>ZeroTrustZone pre-flight proxy</Description></RegistrationInfo>\n"
            f"  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user_id}</UserId></LogonTrigger></Triggers>\n"
            '  <Principals><Principal id="Author">'
            f"<UserId>{user_id}</UserId><LogonType>InteractiveToken</LogonType>"
            "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n"
            "  <Settings>\n"
            "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
            "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
            "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
            "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
            "    <Hidden>true</Hidden>\n"
            "    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>\n"
            "  </Settings>\n"
            '  <Actions Context="Author"><Exec>'
            f"<Command>{escape(python)}</Command>"
            f"<Arguments>{escape(subprocess.list2cmdline(cfg.proxy_args()))}</Arguments>"
            "</Exec></Actions>\n"
            "</Task>\n"
        ).encode("utf-16")
    raise ValueError(f"Unsupported platform for 'ztz service': {platform}")


def _systemd_quote(arg: str) -> str:
    if arg and all(c.isalnum() or c in "-_./:=@+," for c in arg):
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _launchd_domain() -> str:
    return f"gui/{os.getuid()}"


def install_commands(platform: str, path: str, start: bool = True) -> List[List[str]]:
    if platform == "linux":
        cmds = [["systemctl", "--user", "daemon-reload"]]
        cmds.append(["systemctl", "--user", "enable"] + (["--now"] if start else []) + [UNIT_NAME])
        return cmds
    if platform == "darwin":
        # bootout first so re-installing replaces a loaded agent; its failure is ignored.
        return [["launchctl", "bootout", _launchd_domain(), path],
                ["launchctl", "bootstrap", _launchd_domain(), path]]
    if platform == "windows":
        cmds = [["schtasks", "/Create", "/TN", TASK_NAME, "/XML", path, "/F"]]
        if start:
            cmds.append(["schtasks", "/Run", "/TN", TASK_NAME])
        return cmds
    raise ValueError(platform)


def uninstall_commands(platform: str, path: str) -> List[List[str]]:
    if platform == "linux":
        return [["systemctl", "--user", "disable", "--now", UNIT_NAME]]
    if platform == "darwin":
        return [["launchctl", "bootout", _launchd_domain(), path]]
    if platform == "windows":
        return [["schtasks", "/End", "/TN", TASK_NAME], ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]]
    raise ValueError(platform)


def status_command(platform: str) -> List[str]:
    if platform == "linux":
        return ["systemctl", "--user", "status", UNIT_NAME, "--no-pager"]
    if platform == "darwin":
        return ["launchctl", "print", f"{_launchd_domain()}/{LAUNCHD_LABEL}"]
    if platform == "windows":
        return ["schtasks", "/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST"]
    raise ValueError(platform)


# Steps whose failure is expected (nothing to stop / not loaded yet).
_TOLERATED = {("launchctl", "bootout"), ("schtasks", "/End")}

Runner = Callable[[Sequence[str]], int]


def _display(cmd: Sequence[str]) -> str:
    return subprocess.list2cmdline(cmd) if os.name == "nt" else shlex.join(cmd)


def _run(cmd: Sequence[str]) -> int:
    return subprocess.run(list(cmd), check=False, shell=False).returncode


def _run_all(cmds: List[List[str]], runner: Runner) -> int:
    for cmd in cmds:
        try:
            rc = runner(cmd)
        except FileNotFoundError:
            print(f"[ERROR] '{cmd[0]}' not found; run manually: {_display(cmd)}", file=sys.stderr)
            return 1
        if rc != 0 and tuple(cmd[:2]) not in _TOLERATED:
            print(f"[ERROR] Command failed ({rc}): {_display(cmd)}", file=sys.stderr)
            return rc
    return 0


def install(cfg: ServiceConfig, platform: Optional[str] = None, start: bool = True,
            dry_run: bool = False, runner: Runner = _run) -> int:
    platform = platform or current_platform()
    path = service_file(platform)
    content = render(platform, cfg, python_executable(platform))
    cmds = install_commands(platform, path, start)

    if dry_run:
        print(f"# Would write {path}:")
        print(content.decode("utf-16" if platform == "windows" else "utf-8"))
        for cmd in cmds:
            print(f"# Would run: {_display(cmd)}")
        return 0

    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(cfg.log_file)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)
    rc = _run_all(cmds, runner)
    if rc != 0:
        return rc

    print(f"[SUCCESS] ZTZ proxy service installed: {path}")
    print(f"          Logs: {os.path.abspath(cfg.log_file)}")
    print(f"[ACTION]  Point your backend at the upstream port so ZTZ can own {cfg.port}, e.g. for Ollama:")
    print(f"          OLLAMA_HOST=127.0.0.1:{cfg.upstream_port}  (then restart Ollama)")
    return 0


def uninstall(platform: Optional[str] = None, runner: Runner = _run) -> int:
    platform = platform or current_platform()
    path = service_file(platform)
    if not os.path.exists(path):
        print(f"[ZTZ] No ZTZ service installed ({path} not found).")
        return 0
    rc = _run_all(uninstall_commands(platform, path), runner)
    if rc != 0:
        return rc
    os.remove(path)
    if platform == "linux":
        _run_all([["systemctl", "--user", "daemon-reload"]], runner)
    print(f"[SUCCESS] ZTZ proxy service removed ({path}).")
    return 0


def status(platform: Optional[str] = None, runner: Runner = _run) -> int:
    platform = platform or current_platform()
    path = service_file(platform)
    if not os.path.exists(path):
        print(f"[ZTZ] Not installed ({path} not found). Run 'ztz service install'.")
        return 3
    print(f"[ZTZ] Service file: {path}")
    try:
        return runner(status_command(platform))
    except FileNotFoundError:
        print(f"[ERROR] '{status_command(platform)[0]}' not found.", file=sys.stderr)
        return 1
