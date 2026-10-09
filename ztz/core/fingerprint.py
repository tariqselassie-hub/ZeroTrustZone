"""
Cross-platform anonymous hardware fingerprinting for ZTZ.
Binds attestation cache rows to this machine (see ztz.core.cache).
Generates an irreversible, deterministic hardware hash without collecting personally identifiable information.
"""

import os
import sys
import hashlib
import platform
import subprocess

def _get_windows_guid() -> str:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return str(guid).strip()
    except Exception:
        # Fallback to processor info from environment
        return os.environ.get("PROCESSOR_IDENTIFIER", "WIN_GENERIC_CPU")

def _get_linux_machine_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    content = f.read().strip()
                    if content:
                        return content
            except Exception:
                continue
    return "LINUX_GENERIC_NODE"

def _get_macos_uuid() -> str:
    try:
        cmd = ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
        output = subprocess.check_output(cmd).decode("utf-8")
        for line in output.splitlines():
            if "IOPlatformUUID" in line:
                return line.split("=")[-1].replace('"', '').strip()
    except Exception:
        pass
    return "MACOS_GENERIC_UUID"

class HardwareFingerprint:
    """Computes deterministic, non-reversible platform fingerprint."""

    @staticmethod
    def get_raw_components() -> str:
        system = platform.system()
        if system == "Windows":
            primary_id = _get_windows_guid()
            secondary_id = os.environ.get("PROCESSOR_IDENTIFIER", "CPU_DEFAULT")
        elif system == "Linux":
            primary_id = _get_linux_machine_id()
            secondary_id = platform.node()
        elif system == "Darwin":
            primary_id = _get_macos_uuid()
            secondary_id = platform.node()
        else:
            primary_id = platform.node()
            secondary_id = platform.machine()

        return f"{system}:{primary_id}:{secondary_id}"

    @classmethod
    def compute_fingerprint(cls, salt: str = "ztz:v1:fingerprint:") -> str:
        raw = cls.get_raw_components()
        payload = (salt + raw).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
