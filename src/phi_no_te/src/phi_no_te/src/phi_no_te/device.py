from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from .network import read_traffic_counters


def _getprop(name: str) -> str | None:
    executable = shutil.which("getprop")
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, name],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
        value = result.stdout.strip()
        return value or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def detect_capabilities() -> dict[str, Any]:
    termux_path = "/data/data/com.termux/files/usr"
    is_termux = bool(
        os.environ.get("TERMUX_VERSION")
        or termux_path in os.environ.get("PREFIX", "")
        or Path(termux_path).exists()
    )
    android_release = _getprop("ro.build.version.release")
    android_sdk = _getprop("ro.build.version.sdk")
    is_android = bool(android_release or Path("/system/build.prop").exists())
    traffic = read_traffic_counters()
    ip_path = shutil.which("ip")
    try:
        dns_available = importlib.util.find_spec("dns") is not None
    except (ImportError, ValueError):
        dns_available = False
    capabilities = [
        {"name": "Termux", "status": "detected" if is_termux else "not_detected"},
        {"name": "Android", "status": "detected" if is_android else "not_detected"},
        {"name": "Perintah ip", "status": "detected" if ip_path else "not_detected"},
        {
            "name": "Antarmuka sysfs",
            "status": "detected" if Path("/sys/class/net").is_dir() else "not_detected",
        },
        {
            "name": "Penghitung trafik RX/TX",
            "status": "detected" if traffic.get("status") == "ok" else "unavailable",
        },
        {"name": "Lookup DNS dnspython", "status": "detected" if dns_available else "not_detected"},
        {"name": "IPv6 socket", "status": "detected" if socket.has_ipv6 else "not_detected"},
    ]
    mode = "Termux" if is_termux else ("Android (non-Termux)" if is_android else platform.system())
    return {
        "status": "ok",
        "detected_at": __import__("datetime").datetime.now().astimezone().isoformat(),
        "mode": mode,
        "android_release": android_release,
        "android_sdk": android_sdk,
        "python_version": platform.python_version(),
        "system": platform.platform(),
        "capabilities": capabilities,
  }
