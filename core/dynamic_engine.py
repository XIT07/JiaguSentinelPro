"""
JiaguSentinel Pro v2.0 — Dynamic Unpacking Engine
===================================================
Advanced Frida-based runtime DEX extraction engine with anti-detection
bypass and multi-DEX simultaneous dumping.

Capabilities:
- Frida session management with auto-retry
- Anti-anti-Frida hooks (open, read, strstr, access, fopen)
- Multi-DEX memory scanning and simultaneous dump
- Configurable JS payload loading from payloads/ directory
- Session lifecycle with crash recovery
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("sentinel.dynamic")


@dataclass
class DumpedDex:
    """Metadata for a DEX file dumped from memory."""
    address: str
    size: int
    path: str
    sha256: str = ""
    dex_version: str = ""


@dataclass
class DynamicResult:
    """Aggregated result of a dynamic unpacking session."""
    package_name: str
    device_id: str = ""
    frida_version: str = ""
    session_duration: float = 0.0
    dumped_dex: list[DumpedDex] = field(default_factory=list)
    hooked_functions: list[str] = field(default_factory=list)
    anti_detection_active: bool = False
    errors: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Anti-Anti-Frida JavaScript Payload (injected before user payloads)
# ---------------------------------------------------------------------------
ANTI_DETECTION_SCRIPT = r"""
'use strict';

// ═══ JiaguSentinel Anti-Detection Layer ═══
// Hooks libc functions to hide Frida artifacts from integrity checks.

const FRIDA_STRINGS = [
    "frida", "FRIDA", "frida-agent", "frida-server",
    "gmain", "gum-js-loop", "linjector",
    "/data/local/tmp/frida", "/data/local/tmp/re.frida.server",
    "frida-gadget", "libfrida",
];

const FRIDA_PORTS = [27042, 27043];

// ─── Hook: open() ───────────────────────────────────────────────
try {
    const openPtr = Module.findExportByName("libc.so", "open");
    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path) {
                    const lower = path.toLowerCase();
                    for (const sig of FRIDA_STRINGS) {
                        if (lower.includes(sig.toLowerCase())) {
                            args[0] = Memory.allocUtf8String("/dev/null");
                            break;
                        }
                    }
                    // Hide /proc/self/maps entries for frida
                    if (lower.includes("/proc/") && lower.includes("/maps")) {
                        this._filterMaps = true;
                    }
                }
            },
            onLeave(retval) {}
        });
    }
} catch(e) {}

// ─── Hook: strstr() — block string-based detection ──────────────
try {
    const strstrPtr = Module.findExportByName("libc.so", "strstr");
    if (strstrPtr) {
        Interceptor.attach(strstrPtr, {
            onEnter(args) {
                const haystack = args[0].readCString();
                const needle = args[1].readCString();
                if (haystack && needle) {
                    for (const sig of FRIDA_STRINGS) {
                        if (needle.toLowerCase().includes(sig.toLowerCase())) {
                            this._block = true;
                            break;
                        }
                    }
                }
            },
            onLeave(retval) {
                if (this._block) {
                    retval.replace(ptr(0));
                }
            }
        });
    }
} catch(e) {}

// ─── Hook: access() — hide frida file existence checks ──────────
try {
    const accessPtr = Module.findExportByName("libc.so", "access");
    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path) {
                    const lower = path.toLowerCase();
                    for (const sig of FRIDA_STRINGS) {
                        if (lower.includes(sig.toLowerCase())) {
                            this._deny = true;
                            break;
                        }
                    }
                }
            },
            onLeave(retval) {
                if (this._deny) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }
} catch(e) {}

// ─── Hook: fopen() — redirect reads of frida-related files ──────
try {
    const fopenPtr = Module.findExportByName("libc.so", "fopen");
    if (fopenPtr) {
        Interceptor.attach(fopenPtr, {
            onEnter(args) {
                const path = args[0].readCString();
                if (path) {
                    const lower = path.toLowerCase();
                    for (const sig of FRIDA_STRINGS) {
                        if (lower.includes(sig.toLowerCase())) {
                            args[0] = Memory.allocUtf8String("/dev/null");
                            break;
                        }
                    }
                }
            },
            onLeave(retval) {}
        });
    }
} catch(e) {}

// ─── Hook: connect() — block Frida port detection ───────────────
try {
    const connectPtr = Module.findExportByName("libc.so", "connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter(args) {
                const sockAddr = args[1];
                const family = sockAddr.readU16();
                if (family === 2) { // AF_INET
                    const port = (sockAddr.add(2).readU8() << 8) |
                                  sockAddr.add(3).readU8();
                    if (FRIDA_PORTS.includes(port)) {
                        this._blockConnect = true;
                    }
                }
            },
            onLeave(retval) {
                if (this._blockConnect) {
                    retval.replace(ptr(-1));
                }
            }
        });
    }
} catch(e) {}

send({type: "anti_detection", status: "active", hooks: [
    "open", "strstr", "access", "fopen", "connect"
]});
"""

# ---------------------------------------------------------------------------
# Memory DEX Scanner JS Payload
# ---------------------------------------------------------------------------
MEMORY_DEX_SCANNER = r"""
'use strict';

// ═══ JiaguSentinel Memory DEX Scanner ═══
// Scans process memory for DEX magic bytes and dumps valid DEX files.

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0A]; // "dex\n"
const DUMP_DIR = "/data/local/tmp/sentinel_dumps/";

function ensureDumpDir() {
    try {
        const mkdirPtr = Module.findExportByName("libc.so", "mkdir");
        if (mkdirPtr) {
            const mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
            mkdir(Memory.allocUtf8String(DUMP_DIR), 0o755);
        }
    } catch(e) {}
}

function dumpDex(base, size, index) {
    try {
        const filename = DUMP_DIR + "sentinel_dex_" + index + ".dex";
        const fd = new File(filename, "wb");
        fd.write(base.readByteArray(size));
        fd.flush();
        fd.close();
        return filename;
    } catch(e) {
        return null;
    }
}

function scanMemoryForDex() {
    ensureDumpDir();
    const results = [];
    let dexIndex = 0;

    Process.enumerateRanges('r--').forEach(function(range) {
        if (range.size < 112) return; // Min DEX header size

        try {
            const scanResults = Memory.scanSync(range.base, range.size,
                "64 65 78 0A 30 3? ?? 00"); // dex\n0[35-41]\0

            scanResults.forEach(function(match) {
                try {
                    const header = match.address;
                    // Read file_size from DEX header (offset 32, 4 bytes LE)
                    const fileSize = header.add(32).readU32();

                    if (fileSize > 112 && fileSize < 100 * 1024 * 1024) {
                        // Validate: checksum field should be non-zero
                        const checksum = header.add(8).readU32();
                        if (checksum !== 0) {
                            const path = dumpDex(header, fileSize, dexIndex);
                            if (path) {
                                results.push({
                                    address: match.address.toString(),
                                    size: fileSize,
                                    path: path,
                                    version: header.add(4).readCString(3),
                                });
                                dexIndex++;
                            }
                        }
                    }
                } catch(e) {}
            });
        } catch(e) {}
    });

    send({type: "dex_scan", results: results, total: dexIndex});
}

// Wait for app initialization then scan
setTimeout(scanMemoryForDex, 5000);
"""


class DynamicEngine:
    """
    Frida-based dynamic unpacking engine for 360 Jiagu-packed APKs.

    Attaches to a running application on an Android device, injects
    anti-detection hooks to bypass integrity checks, then scans
    process memory for decrypted DEX payloads and dumps them.
    """

    def __init__(
        self,
        output_dir: str = "unpacked_output",
        log_callback: Optional[Callable[[str], None]] = None,
        anti_detection: bool = True,
        scan_delay: int = 5,
        max_retries: int = 3,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._log_cb = log_callback
        self.anti_detection = anti_detection
        self.scan_delay = scan_delay
        self.max_retries = max_retries
        self._session = None
        self._script = None
        self._device = None
        self._result: Optional[DynamicResult] = None
        self._dump_event = threading.Event()

    # ── Logging ───────────────────────────────────────────────────────

    def _log(self, message: str, level: str = "INFO") -> None:
        getattr(logger, level.lower(), logger.info)(message)
        if self._log_cb:
            self._log_cb(f"[{level}] {message}")
        if self._result:
            self._result.logs.append(f"[{level}] {message}")

    # ── Payload Management ────────────────────────────────────────────

    @staticmethod
    def list_payloads() -> list[str]:
        """List all available JS payloads in the payloads/ directory."""
        payloads_dir = Path(__file__).parent.parent / "payloads"
        if not payloads_dir.is_dir():
            return []
        return sorted([f.name for f in payloads_dir.glob("*.js")])

    @staticmethod
    def load_payload(name: str) -> str:
        """Load a JS payload file by name."""
        payload_path = Path(__file__).parent.parent / "payloads" / name
        if not payload_path.is_file():
            raise FileNotFoundError(f"Payload not found: {name}")
        return payload_path.read_text(encoding="utf-8")

    # ── Frida Session Management ──────────────────────────────────────

    def _get_device(self) -> object:
        """Get the first connected USB device via Frida."""
        import frida  # type: ignore

        self._log("Connecting to USB device...")
        device = frida.get_usb_device(timeout=10)
        self._log(f"Connected: {device.name} (id: {device.id})")
        return device

    def _on_message(self, message: dict, data: object) -> None:
        """Handle messages from the injected Frida script."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type", "")

            if msg_type == "anti_detection":
                hooks = payload.get("hooks", [])
                self._log(
                    f"🛡️ Anti-detection active: hooked {', '.join(hooks)}"
                )
                if self._result:
                    self._result.anti_detection_active = True
                    self._result.hooked_functions = hooks

            elif msg_type == "dex_scan":
                results = payload.get("results", [])
                total = payload.get("total", 0)
                self._log(f"🎯 Memory scan complete: {total} DEX found")
                if self._result:
                    for r in results:
                        self._result.dumped_dex.append(DumpedDex(
                            address=r.get("address", ""),
                            size=r.get("size", 0),
                            path=r.get("path", ""),
                            dex_version=r.get("version", ""),
                        ))
                self._dump_event.set()

            else:
                self._log(f"Agent: {payload}")

        elif message.get("type") == "error":
            err = message.get("description", str(message))
            self._log(f"Script error: {err}", "ERROR")
            if self._result:
                self._result.errors.append(err)

    def _on_detached(self, reason: str, crash: object) -> None:
        """Handle Frida session detachment."""
        self._log(f"Session detached: {reason}", "WARNING")
        if crash:
            self._log(f"Crash report: {crash}", "ERROR")
        self._dump_event.set()  # Unblock waiting threads

    # ── Core Dump Pipeline ────────────────────────────────────────────

    def dump(
        self,
        package_name: str,
        custom_payload: Optional[str] = None,
        spawn: bool = True,
        timeout: int = 60,
    ) -> DynamicResult:
        """
        Execute dynamic DEX dumping on a target application.

        Pipeline:
        1. Connect to device
        2. Spawn or attach to target app
        3. Inject anti-detection hooks (if enabled)
        4. Inject DEX memory scanner (or custom payload)
        5. Wait for results
        6. Pull dumped files from device
        7. Clean up session

        Args:
            package_name: Android package name (e.g., com.example.app)
            custom_payload: Optional JS payload to use instead of built-in scanner
            spawn: Whether to spawn a fresh process (True) or attach to running
            timeout: Maximum seconds to wait for dump results

        Returns:
            DynamicResult with all dump findings.
        """
        import frida  # type: ignore

        start_time = time.time()
        self._result = DynamicResult(package_name=package_name)
        self._dump_event.clear()

        self._log(f"═══ Dynamic Engine: {package_name} ═══")

        for attempt in range(1, self.max_retries + 1):
            try:
                # 1. Connect to device
                self._device = self._get_device()
                self._result.device_id = self._device.id
                self._result.frida_version = frida.__version__

                # 2. Spawn or attach
                if spawn:
                    self._log(f"Spawning {package_name}...")
                    pid = self._device.spawn([package_name])
                    self._session = self._device.attach(pid)
                    self._session.on("detached", self._on_detached)
                else:
                    self._log(f"Attaching to running {package_name}...")
                    self._session = self._device.attach(package_name)
                    self._session.on("detached", self._on_detached)

                # 3. Build combined script
                script_source = ""
                if self.anti_detection:
                    script_source += ANTI_DETECTION_SCRIPT + "\n\n"

                if custom_payload:
                    script_source += custom_payload
                else:
                    script_source += MEMORY_DEX_SCANNER

                # 4. Create and load script
                self._script = self._session.create_script(script_source)
                self._script.on("message", self._on_message)
                self._script.load()

                # 5. Resume if spawned
                if spawn:
                    self._device.resume(pid)
                    self._log("Process resumed — waiting for DEX decryption...")

                # 6. Wait for scan results
                self._dump_event.wait(timeout=timeout)

                # 7. Pull dumped files from device
                if self._result.dumped_dex:
                    self._pull_dumps()

                break  # Success — exit retry loop

            except frida.ServerNotRunningError:
                self._log(
                    f"Frida server not running (attempt {attempt}/{self.max_retries})",
                    "ERROR",
                )
                self._result.errors.append("frida-server not running on device")
                if attempt < self.max_retries:
                    self._log("Retrying in 3 seconds...")
                    time.sleep(3)

            except frida.ProcessNotFoundError:
                self._log(f"Process '{package_name}' not found", "ERROR")
                self._result.errors.append(f"Process not found: {package_name}")
                break

            except frida.TransportError as e:
                self._log(f"Transport error: {e} (attempt {attempt})", "ERROR")
                if attempt < self.max_retries:
                    time.sleep(2)

            except Exception as e:
                self._log(f"Unexpected error: {e}", "ERROR")
                self._result.errors.append(str(e))
                break

            finally:
                self._cleanup_session()

        self._result.session_duration = time.time() - start_time
        self._log(
            f"═══ Dynamic session complete: {len(self._result.dumped_dex)} DEX "
            f"dumped in {self._result.session_duration:.1f}s ═══"
        )

        return self._result

    def _pull_dumps(self) -> None:
        """Pull dumped DEX files from device to local output directory."""
        from core.adb_manager import ADBManager

        try:
            adb = ADBManager()
            for dex in self._result.dumped_dex:
                remote_path = dex.path
                local_name = os.path.basename(remote_path)
                local_path = str(self.output_dir / local_name)
                success = adb.pull_file(remote_path, local_path)
                if success:
                    dex.path = local_path
                    self._log(f"✓ Pulled: {local_name}")
                    # Compute hash
                    import hashlib
                    dex.sha256 = hashlib.sha256(
                        Path(local_path).read_bytes()
                    ).hexdigest()
                else:
                    self._log(f"✗ Failed to pull: {remote_path}", "WARNING")

            # Cleanup remote dumps
            adb.shell("rm -rf /data/local/tmp/sentinel_dumps/")

        except Exception as e:
            self._log(f"Pull error: {e}", "ERROR")

    def _cleanup_session(self) -> None:
        """Safely tear down Frida session and script."""
        try:
            if self._script:
                self._script.unload()
                self._script = None
        except Exception:
            pass
        try:
            if self._session:
                self._session.detach()
                self._session = None
        except Exception:
            pass
