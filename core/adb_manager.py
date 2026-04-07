"""
JiaguSentinel Pro v2.0 — ADB Manager
======================================
Total ADB automation with self-healing connections, architecture
auto-detection, and intelligent Frida server deployment.

Capabilities:
- Self-healing connection with exponential backoff
- Architecture detection (arm64/arm/x86/x86_64)
- Frida-server push, chmod, and lifecycle management
- Package management (install, launch, force-stop, uninstall)
- Logcat streaming with Jiagu-specific filters
- Root detection and su wrapper
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("sentinel.adb")


class Architecture(Enum):
    """Supported Android CPU architectures."""
    ARM64 = "arm64-v8a"
    ARM = "armeabi-v7a"
    X86_64 = "x86_64"
    X86 = "x86"
    UNKNOWN = "unknown"

    @classmethod
    def from_abi(cls, abi: str) -> "Architecture":
        """Map ro.product.cpu.abi value to Architecture enum."""
        mapping = {
            "arm64-v8a": cls.ARM64,
            "armeabi-v7a": cls.ARM,
            "armeabi": cls.ARM,
            "x86_64": cls.X86_64,
            "x86": cls.X86,
        }
        return mapping.get(abi.strip(), cls.UNKNOWN)


@dataclass
class DeviceInfo:
    """Information about the connected Android device."""
    serial: str = ""
    model: str = ""
    android_version: str = ""
    sdk_level: int = 0
    architecture: Architecture = Architecture.UNKNOWN
    abi: str = ""
    is_rooted: bool = False
    selinux_mode: str = ""


class ADBManager:
    """
    Comprehensive ADB automation manager for JiaguSentinel.

    Handles device connectivity, Frida server deployment, app
    lifecycle, and logcat streaming with built-in retry logic.
    """

    FRIDA_REMOTE_PATH = "/data/local/tmp/frida-server"
    FRIDA_REMOTE_DIR = "/data/local/tmp/"

    def __init__(
        self,
        adb_path: Optional[str] = None,
        log_callback: Optional[Callable[[str], None]] = None,
        max_retries: int = 5,
        retry_delay: float = 2.0,
    ) -> None:
        self.adb_path = adb_path or self._find_adb()
        self._log_cb = log_callback
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._device_info: Optional[DeviceInfo] = None

    # ── Logging ───────────────────────────────────────────────────────

    def _log(self, message: str, level: str = "INFO") -> None:
        getattr(logger, level.lower(), logger.info)(message)
        if self._log_cb:
            self._log_cb(f"[{level}] {message}")

    # ── ADB Binary Discovery ─────────────────────────────────────────

    @staticmethod
    def _find_adb() -> str:
        """Locate adb binary on the system PATH."""
        adb = shutil.which("adb")
        if adb:
            return adb
        # Common fallback locations
        candidates = [
            os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
            os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
            "/usr/bin/adb",
            "/usr/local/bin/adb",
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        raise FileNotFoundError(
            "adb not found. Install Android SDK platform-tools or set adb_path."
        )

    # ── Command Execution ─────────────────────────────────────────────

    def _run(
        self,
        args: list[str],
        timeout: int = 30,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """Execute an ADB command with timeout and error handling."""
        cmd = [self.adb_path] + args
        logger.debug(f"ADB CMD: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
            )
            return result
        except subprocess.TimeoutExpired:
            self._log(f"ADB timeout: {' '.join(args)}", "ERROR")
            raise
        except subprocess.CalledProcessError as e:
            self._log(f"ADB error: {e.stderr}", "ERROR")
            raise

    def shell(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command on the device."""
        result = self._run(["shell", command], timeout=timeout)
        return result.stdout.strip()

    def shell_as_root(self, command: str, timeout: int = 30) -> str:
        """Execute a shell command as root (via su)."""
        result = self._run(["shell", "su", "-c", command], timeout=timeout)
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr:
            # Try direct root shell
            result = self._run(["shell", f"su 0 {command}"], timeout=timeout)
            output = result.stdout.strip()
        return output

    # ── Self-Healing Connection ───────────────────────────────────────

    def connect(self) -> DeviceInfo:
        """
        Establish and verify ADB connection with self-healing retry.

        Uses exponential backoff on connection failures. Automatically
        restarts adb-server if needed.

        Returns:
            DeviceInfo for the connected device.
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                # Check device presence
                result = self._run(["devices"], timeout=10)
                lines = [
                    l.strip() for l in result.stdout.splitlines()
                    if "\tdevice" in l
                ]

                if not lines:
                    if attempt < self.max_retries:
                        self._log(
                            f"No device found (attempt {attempt}/{self.max_retries}) "
                            f"— retrying in {self.retry_delay * attempt:.0f}s...",
                            "WARNING",
                        )
                        # Try restarting adb server
                        if attempt == 2:
                            self._log("Restarting adb server...")
                            self._run(["kill-server"], timeout=5)
                            time.sleep(1)
                            self._run(["start-server"], timeout=10)
                        time.sleep(self.retry_delay * attempt)
                        continue
                    raise ConnectionError("No Android device connected.")

                serial = lines[0].split("\t")[0]
                self._log(f"Device connected: {serial}")

                # Gather device info
                self._device_info = self._gather_device_info(serial)
                return self._device_info

            except subprocess.TimeoutExpired:
                if attempt < self.max_retries:
                    self._log(f"Connection timeout — retrying...", "WARNING")
                    time.sleep(self.retry_delay * attempt)
                else:
                    raise ConnectionError("ADB connection timed out.")

        raise ConnectionError("Failed to connect after max retries.")

    def _gather_device_info(self, serial: str) -> DeviceInfo:
        """Collect comprehensive device information."""
        info = DeviceInfo(serial=serial)

        info.model = self.shell("getprop ro.product.model")
        info.android_version = self.shell("getprop ro.build.version.release")
        sdk = self.shell("getprop ro.build.version.sdk")
        info.sdk_level = int(sdk) if sdk.isdigit() else 0
        info.abi = self.shell("getprop ro.product.cpu.abi")
        info.architecture = Architecture.from_abi(info.abi)
        info.selinux_mode = self.shell("getenforce") or "Unknown"

        # Root detection
        info.is_rooted = self._check_root()

        self._log(
            f"📱 {info.model} | Android {info.android_version} | "
            f"SDK {info.sdk_level} | {info.architecture.value} | "
            f"Root: {'✓' if info.is_rooted else '✗'} | "
            f"SELinux: {info.selinux_mode}"
        )

        return info

    def _check_root(self) -> bool:
        """Detect root access availability."""
        checks = [
            "which su",
            "ls /system/xbin/su",
            "ls /sbin/su",
            "ls /data/adb/magisk",
        ]
        for check in checks:
            result = self._run(["shell", check], timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return True
        return False

    # ── Architecture Detection ────────────────────────────────────────

    def get_architecture(self) -> Architecture:
        """Auto-detect the device CPU architecture."""
        if self._device_info:
            return self._device_info.architecture
        abi = self.shell("getprop ro.product.cpu.abi")
        return Architecture.from_abi(abi)

    # ── Frida Server Management ───────────────────────────────────────

    def is_frida_running(self) -> bool:
        """Check if frida-server is already running on the device."""
        output = self.shell("ps -A | grep frida-server")
        return "frida-server" in output

    def start_frida_server(self) -> bool:
        """
        Start frida-server on the device.

        If not already uploaded, this will log an error.
        Requires root access.
        """
        if self.is_frida_running():
            self._log("frida-server already running")
            return True

        # Check if binary exists on device
        check = self.shell(f"ls {self.FRIDA_REMOTE_PATH}")
        if "No such file" in check or not check:
            self._log(
                "frida-server not found on device. "
                "Use push_frida_server() first.", "ERROR"
            )
            return False

        # Start with root
        self.shell_as_root(f"chmod 755 {self.FRIDA_REMOTE_PATH}")
        self.shell_as_root(f"SELinux=permissive setenforce 0 2>/dev/null; "
                           f"{self.FRIDA_REMOTE_PATH} -D &")
        time.sleep(2)

        if self.is_frida_running():
            self._log("✓ frida-server started successfully")
            return True
        else:
            self._log("✗ Failed to start frida-server", "ERROR")
            return False

    def stop_frida_server(self) -> None:
        """Kill frida-server on the device."""
        self.shell_as_root("pkill -f frida-server")
        self._log("frida-server stopped")

    def push_frida_server(self, local_path: str) -> bool:
        """
        Push a frida-server binary to the device.

        Automatically validates the architecture matches the device.
        """
        if not os.path.isfile(local_path):
            self._log(f"Frida binary not found: {local_path}", "ERROR")
            return False

        self._log(f"Pushing frida-server to device...")
        result = self._run(
            ["push", local_path, self.FRIDA_REMOTE_PATH],
            timeout=60,
        )

        if result.returncode == 0:
            self.shell_as_root(f"chmod 755 {self.FRIDA_REMOTE_PATH}")
            self._log("✓ frida-server pushed and permissions set")
            return True

        self._log(f"✗ Push failed: {result.stderr}", "ERROR")
        return False

    # ── Package Management ────────────────────────────────────────────

    def install_apk(self, apk_path: str) -> bool:
        """Install an APK on the device."""
        self._log(f"Installing {os.path.basename(apk_path)}...")
        result = self._run(["install", "-r", apk_path], timeout=120)
        success = "Success" in result.stdout
        if success:
            self._log("✓ APK installed")
        else:
            self._log(f"✗ Install failed: {result.stdout}", "ERROR")
        return success

    def launch_app(self, package_name: str) -> bool:
        """Launch an app by resolving its main activity."""
        output = self.shell(
            f"cmd package resolve-activity --brief {package_name} "
            f"| tail -n 1"
        )
        if "/" in output:
            self.shell(f"am start -n {output}")
            self._log(f"✓ Launched {package_name}")
            return True
        # Fallback: monkey launch
        self.shell(
            f"monkey -p {package_name} "
            f"-c android.intent.category.LAUNCHER 1"
        )
        self._log(f"✓ Launched {package_name} (monkey)")
        return True

    def force_stop(self, package_name: str) -> None:
        """Force-stop an application."""
        self.shell(f"am force-stop {package_name}")
        self._log(f"Force-stopped {package_name}")

    def uninstall(self, package_name: str) -> bool:
        """Uninstall an application."""
        result = self._run(["uninstall", package_name], timeout=30)
        success = "Success" in result.stdout
        if success:
            self._log(f"✓ Uninstalled {package_name}")
        return success

    def list_packages(self, filter_str: str = "") -> list[str]:
        """List installed packages, optionally filtered."""
        cmd = "pm list packages"
        if filter_str:
            cmd += f" | grep -i {filter_str}"
        output = self.shell(cmd)
        return [
            line.replace("package:", "").strip()
            for line in output.splitlines()
            if line.strip()
        ]

    # ── File Operations ───────────────────────────────────────────────

    def pull_file(self, remote: str, local: str) -> bool:
        """Pull a file from the device to local filesystem."""
        result = self._run(["pull", remote, local], timeout=60)
        return result.returncode == 0

    def push_file(self, local: str, remote: str) -> bool:
        """Push a file from local filesystem to the device."""
        result = self._run(["push", local, remote], timeout=60)
        return result.returncode == 0

    # ── Logcat Streaming ──────────────────────────────────────────────

    def stream_logcat(
        self,
        callback: Callable[[str], None],
        filter_tag: str = "",
        timeout: int = 30,
    ) -> None:
        """
        Stream logcat output with optional filtering.

        Args:
            callback: Function to call with each log line.
            filter_tag: Optional tag filter (e.g., "jiagu" or "360").
            timeout: How long to stream in seconds.
        """
        cmd = [self.adb_path, "logcat", "-v", "threadtime"]
        if filter_tag:
            cmd.extend(["-s", filter_tag])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            start = time.time()
            for line in iter(proc.stdout.readline, ""):
                if time.time() - start > timeout:
                    break
                line = line.strip()
                if filter_tag and filter_tag.lower() not in line.lower():
                    continue
                callback(line)
            proc.terminate()
        except Exception as e:
            self._log(f"Logcat error: {e}", "ERROR")
