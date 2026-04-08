"""
JiaguSentinel Pro v2.0 — Static Analysis Engine
=================================================
Advanced heuristic scanning engine for 360 Jiagu-protected APKs.

Capabilities:
- Multi-signature DEX byte-pattern matching (v035–v041)
- LIEF-based ELF analysis for libjiagu*.so binaries
- Shannon entropy heatmap generation
- Multi-layer decompression (zlib, gzip, LZMA, XOR brute-force)
- YARA rule matching for embedded payloads
"""

from __future__ import annotations

import gzip
import hashlib
import io
import logging
import lzma
import math
import os
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("sentinel.static")

# ---------------------------------------------------------------------------
# DEX magic bytes for all known ART versions
# ---------------------------------------------------------------------------
DEX_SIGNATURES: list[bytes] = [
    b"dex\n035\x00",
    b"dex\n036\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
    b"dex\n040\x00",
    b"dex\n041\x00",
]

# Compact magic prefix used for fast scanning
DEX_MAGIC_PREFIX: bytes = b"dex\n"

# Known Jiagu native library patterns
JIAGU_LIB_PATTERNS: list[str] = [
    "libjiagu",
    "libjiagu_x86",
    "libjiagu_64",
    "libDexHelper",
    "libprotectClass",
    "libqihoo",
]

# Suspicious ELF section names commonly seen in packers
PACKER_SECTIONS: list[str] = [
    ".jiagu",
    ".packed",
    ".shell",
    ".protect",
    ".crypt",
    ".vmp",
    ".qihoo",
]


@dataclass
class FileAnalysis:
    """Analysis result for a single file inside the APK."""
    filename: str
    file_size: int
    compressed_size: int
    entropy: float
    is_jiagu_lib: bool = False
    contains_dex: bool = False
    dex_offset: int = -1
    extracted_path: Optional[str] = None
    sha256: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class StaticResult:
    """Aggregated result of a full static analysis run."""
    apk_path: str
    apk_sha256: str = ""
    total_files: int = 0
    jiagu_detected: bool = False
    jiagu_libraries: list[str] = field(default_factory=list)
    extracted_dex: list[str] = field(default_factory=list)
    file_analyses: list[FileAnalysis] = field(default_factory=list)
    entropy_map: dict[str, float] = field(default_factory=dict)
    packer_sections: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class StaticEngine:
    """
    Heuristic static analysis engine for 360 Jiagu-packed APKs.

    Performs deep inspection of APK contents without executing the
    application, using entropy analysis, byte-pattern matching, and
    multi-layer decompression to locate hidden DEX payloads.
    """

    def __init__(
        self,
        output_dir: str = "results_JiaguSentinel",
        log_callback: Optional[Callable[[str], None]] = None,
        xor_bruteforce: bool = True,
        max_xor_key_len: int = 1,
    ) -> None:
        # Base root — actual session subfolder is created per scan() call.
        self._base_output_dir = Path(output_dir)
        self.output_dir = self._base_output_dir  # will be overridden in scan()
        self._log_cb = log_callback
        self.xor_bruteforce = xor_bruteforce
        self.max_xor_key_len = max_xor_key_len
        self._yara_rules = self._load_yara_rules()

    # ── Logging ───────────────────────────────────────────────────────

    def _log(self, message: str, level: str = "INFO") -> None:
        """Emit a log message to both the logger and optional callback."""
        getattr(logger, level.lower(), logger.info)(message)
        if self._log_cb:
            self._log_cb(f"[{level}] {message}")

    # ── YARA Rules ────────────────────────────────────────────────────

    def _load_yara_rules(self) -> object | None:
        """Load YARA rules if yara-python is available."""
        try:
            import yara  # type: ignore

            rules_dir = Path(__file__).parent.parent / "rules"
            if rules_dir.is_dir():
                rule_files = {
                    f.stem: str(f) for f in rules_dir.glob("*.yar")
                }
                if rule_files:
                    compiled = yara.compile(filepaths=rule_files)
                    self._log(f"Loaded {len(rule_files)} YARA rules")
                    return compiled
            # Inline fallback rule for generic packer detection
            return yara.compile(source="""
                rule Jiagu360_Packer {
                    meta:
                        description = "Detects 360 Jiagu packer artifacts"
                    strings:
                        $lib1 = "libjiagu" ascii
                        $lib2 = "libprotectClass" ascii
                        $lib3 = "com.qihoo.util" ascii
                        $str1 = "StubApplication" ascii
                        $str2 = "com.stub.StubApp" ascii
                    condition:
                        any of them
                }
            """)
        except ImportError:
            self._log("yara-python not installed — YARA scanning disabled", "WARNING")
            return None

    # ── Entropy Calculation ───────────────────────────────────────────

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence (0.0–8.0)."""
        if not data:
            return 0.0
        length = len(data)
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def entropy_heatmap(data: bytes, block_size: int = 4096) -> list[tuple[int, float]]:
        """
        Generate a block-level entropy map.

        Returns a list of (offset, entropy) tuples, one per block.
        High-entropy regions (>7.5) likely contain encrypted/compressed payloads.
        """
        heatmap: list[tuple[int, float]] = []
        for offset in range(0, len(data), block_size):
            block = data[offset : offset + block_size]
            ent = StaticEngine.calculate_entropy(block)
            heatmap.append((offset, ent))
        return heatmap

    # ── DEX Extraction Methods ────────────────────────────────────────

    def _find_dex_signatures(self, data: bytes) -> list[int]:
        """Scan for all DEX magic byte offsets in raw data."""
        offsets: list[int] = []
        search_start = 0
        while True:
            idx = data.find(DEX_MAGIC_PREFIX, search_start)
            if idx == -1:
                break
            # Validate: next bytes should form a valid version string
            header_slice = data[idx : idx + 8]
            if any(header_slice.startswith(sig) for sig in DEX_SIGNATURES):
                # Extra validation: check DEX file_size field at offset 32
                if len(data) >= idx + 36:
                    dex_file_size = struct.unpack_from("<I", data, idx + 32)[0]
                    if 0 < dex_file_size <= len(data) - idx:
                        offsets.append(idx)
                    else:
                        offsets.append(idx)  # Still record even if size seems off
                else:
                    offsets.append(idx)
            search_start = idx + 1
        return offsets

    def _extract_dex_at_offset(
        self, data: bytes, offset: int, source_name: str, idx: int = 0
    ) -> Optional[str]:
        """Extract a DEX file from raw data at the given offset, keeping the original filename."""
        dex_data = data[offset:]
        # Read file_size from the DEX header for precise extraction
        if len(dex_data) >= 36:
            file_size = struct.unpack_from("<I", dex_data, 32)[0]
            if 0 < file_size <= len(dex_data):
                dex_data = dex_data[:file_size]

        # Use the original basename (e.g. "classes.dex") and only suffix for duplicates
        base = Path(source_name).name  # e.g. "classes.dex" or "libjiagu.so"
        if not base.endswith(".dex"):
            base = base + ".dex"
        # Disambiguate multiple DEX found in same source file
        if idx > 0:
            stem, ext = os.path.splitext(base)
            base = f"{stem}_{idx}{ext}"          # e.g. classes_1.dex

        out_path = self.output_dir / base
        # Avoid clobbering existing files with same name from different sources
        counter = 1
        while out_path.exists():
            stem, ext = os.path.splitext(base)
            out_path = self.output_dir / f"{stem}_{counter}{ext}"
            counter += 1

        out_path.write_bytes(dex_data)
        self._log(
            f"✓ Extracted DEX from '{source_name}' at offset "
            f"{hex(offset)} → {out_path.name} ({len(dex_data):,} bytes)"
        )
        return str(out_path)

    def _try_decompress(self, data: bytes) -> Optional[bytes]:
        """Attempt multi-layer decompression: zlib → gzip → LZMA."""
        # Zlib (raw deflate & zlib-wrapped)
        for wbits in [15, -15, 31]:
            try:
                result = zlib.decompress(data, wbits)
                if result:
                    return result
            except zlib.error:
                continue

        # Gzip
        try:
            result = gzip.decompress(data)
            if result:
                return result
        except (gzip.BadGzipFile, OSError):
            pass

        # LZMA / XZ
        try:
            result = lzma.decompress(data)
            if result:
                return result
        except lzma.LZMAError:
            pass

        return None

    def _xor_bruteforce_scan(self, data: bytes) -> Optional[bytes]:
        """
        Single-byte XOR brute-force to uncover hidden DEX payloads.

        Only checks the first 8 bytes against known DEX signatures
        for each key, making this O(256 * 8) — extremely fast.
        """
        if not self.xor_bruteforce or len(data) < 8:
            return None

        target_prefix = DEX_SIGNATURES[0][:4]  # b"dex\n"

        for key in range(1, 256):
            decoded_header = bytes(b ^ key for b in data[:4])
            if decoded_header == target_prefix:
                self._log(f"XOR key found: {hex(key)} — decoding full payload")
                return bytes(b ^ key for b in data)
        return None

    # ── LIEF ELF Analysis ─────────────────────────────────────────────

    def _analyze_elf(self, data: bytes, filename: str) -> list[str]:
        """
        Deep analysis of native ELF libraries using LIEF.

        Extracts section entropy, symbols, and detects packer-specific
        sections (e.g., .jiagu, .vmp, .packed).
        """
        notes: list[str] = []
        try:
            import lief  # type: ignore

            binary = lief.parse(data)
            if binary is None:
                return notes

            # Section analysis
            for section in binary.sections:
                sec_entropy = self.calculate_entropy(bytes(section.content))
                if section.name in PACKER_SECTIONS:
                    notes.append(
                        f"⚠ Packer section '{section.name}' "
                        f"(entropy: {sec_entropy:.2f}, size: {section.size:,})"
                    )
                elif sec_entropy > 7.0 and section.size > 1024:
                    notes.append(
                        f"High-entropy section '{section.name}' "
                        f"({sec_entropy:.2f}) — possible encrypted payload"
                    )

            # Symbol table inspection
            exported_funcs = [
                sym.name for sym in binary.exported_functions
                if sym.name
            ]
            suspicious_syms = [
                s for s in exported_funcs
                if any(kw in s.lower() for kw in [
                    "decrypt", "unpack", "jiagu", "shell", "protect",
                    "dexload", "attach", "inject", "hook",
                ])
            ]
            if suspicious_syms:
                notes.append(
                    f"Suspicious exports: {', '.join(suspicious_syms[:10])}"
                )

            # Relocation analysis
            reloc_count = sum(
                1 for _ in binary.relocations
            ) if hasattr(binary, "relocations") else 0
            if reloc_count > 500:
                notes.append(
                    f"High relocation count ({reloc_count}) — "
                    "possible runtime self-modification"
                )

        except ImportError:
            self._log("LIEF not installed — ELF analysis disabled", "WARNING")
        except Exception as e:
            notes.append(f"ELF analysis error: {e}")

        return notes

    # ── YARA Matching ─────────────────────────────────────────────────

    def _yara_scan(self, data: bytes, filename: str) -> list[str]:
        """Run YARA rules against file data."""
        notes: list[str] = []
        if self._yara_rules is None:
            return notes
        try:
            matches = self._yara_rules.match(data=data)
            for match in matches:
                notes.append(f"YARA hit: {match.rule} — {match.meta.get('description', '')}")
        except Exception as e:
            logger.debug(f"YARA scan error on {filename}: {e}")
        return notes

    # ── Main Scan Pipeline ────────────────────────────────────────────

    def scan(self, apk_path: str) -> StaticResult:
        """
        Execute the full static analysis pipeline on an APK file.

        Creates a session output directory:
            results_JiaguSentinel/<apk_stem>_YYYYMMDD_HHMMSS/

        Pipeline:
        1. Create session output directory
        2. Compute APK hash
        3. Enumerate all entries in the ZIP
        4. For each entry: entropy scan → DEX pattern match →
           decompress → XOR bruteforce → LIEF ELF inspect → YARA scan
        5. Aggregate results into StaticResult

        Args:
            apk_path: Path to the APK file to analyze.

        Returns:
            StaticResult with all findings.
        """
        # ── Create session output directory ───────────────────────────
        apk_stem = Path(apk_path).stem          # e.g. "vcamultra"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = self._base_output_dir / f"{apk_stem}_{timestamp}"
        session_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = session_dir           # redirect all writes here
        self._log(f"Session output: {session_dir}")

        self._log(f"═══ Static Analysis: {os.path.basename(apk_path)} ═══")
        result = StaticResult(apk_path=apk_path)

        # Compute APK-level hash
        try:
            apk_bytes = Path(apk_path).read_bytes()
            result.apk_sha256 = hashlib.sha256(apk_bytes).hexdigest()
            self._log(f"APK SHA256: {result.apk_sha256}")
        except Exception as e:
            result.errors.append(f"Hash computation failed: {e}")

        # Open and enumerate
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                entries = apk.infolist()
                result.total_files = len(entries)
                self._log(f"Total entries: {result.total_files}")

                for entry in entries:
                    self._analyze_entry(apk, entry, result)

        except zipfile.BadZipFile:
            result.errors.append("Invalid or corrupted ZIP/APK file.")
            self._log("FATAL: Invalid ZIP structure", "ERROR")
        except Exception as e:
            result.errors.append(str(e))
            self._log(f"Scan error: {e}", "ERROR")

        # Summary
        self._log(
            f"═══ Scan Complete: {len(result.extracted_dex)} DEX extracted, "
            f"{len(result.jiagu_libraries)} Jiagu libs found ═══"
        )
        if not result.extracted_dex:
            self._log(
                "No DEX extracted statically. The payload is likely "
                "AES/custom encrypted — use Dynamic Engine for memory dump.",
                "WARNING",
            )

        return result

    def _analyze_entry(
        self, apk: zipfile.ZipFile, entry: zipfile.ZipInfo, result: StaticResult
    ) -> None:
        """Analyze a single entry inside the APK archive."""
        filename = entry.filename
        data = apk.read(filename)

        analysis = FileAnalysis(
            filename=filename,
            file_size=entry.file_size,
            compressed_size=entry.compress_size,
            entropy=self.calculate_entropy(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

        result.entropy_map[filename] = analysis.entropy

        # ─── Jiagu library detection ───
        if any(pattern in filename.lower() for pattern in JIAGU_LIB_PATTERNS):
            analysis.is_jiagu_lib = True
            result.jiagu_detected = True
            result.jiagu_libraries.append(filename)
            self._log(f"🔴 Jiagu library detected: {filename}")

            # ELF deep analysis
            if filename.endswith(".so"):
                elf_notes = self._analyze_elf(data, filename)
                analysis.notes.extend(elf_notes)
                result.packer_sections.extend(
                    n for n in elf_notes if "Packer section" in n
                )
                for note in elf_notes:
                    self._log(f"  └─ {note}")

        # ─── Skip manifest/resource files for DEX search ───
        if filename.lower().endswith((".xml", ".arsc", ".png", ".jpg", ".webp")):
            result.file_analyses.append(analysis)
            return

        # ─── High-entropy file analysis ───
        if entry.file_size > 50000 and analysis.entropy > 6.5:
            self._log(
                f"⚡ High entropy: {filename} "
                f"(H={analysis.entropy:.2f}, {entry.file_size:,} bytes)"
            )

            # Generate entropy heatmap
            heatmap = self.entropy_heatmap(data)
            hot_blocks = [(off, ent) for off, ent in heatmap if ent > 7.5]
            if hot_blocks:
                analysis.notes.append(
                    f"Entropy hotspots: {len(hot_blocks)}/{len(heatmap)} blocks >7.5"
                )

            # Method 1: Direct DEX signature scan
            dex_offsets = self._find_dex_signatures(data)
            if dex_offsets:
                for i, offset in enumerate(dex_offsets):
                    path = self._extract_dex_at_offset(data, offset, filename, i)
                    if path:
                        analysis.contains_dex = True
                        analysis.dex_offset = offset
                        analysis.extracted_path = path
                        result.extracted_dex.append(path)

            # Method 2: Multi-layer decompression
            if not analysis.contains_dex:
                decompressed = self._try_decompress(data)
                if decompressed:
                    dex_offsets = self._find_dex_signatures(decompressed)
                    if dex_offsets:
                        for i, offset in enumerate(dex_offsets):
                            path = self._extract_dex_at_offset(
                                decompressed, offset, f"decomp_{filename}", i
                            )
                            if path:
                                analysis.contains_dex = True
                                analysis.dex_offset = offset
                                analysis.extracted_path = path
                                result.extracted_dex.append(path)
                                analysis.notes.append(
                                    "DEX found after decompression"
                                )

            # Method 3: XOR brute-force
            if not analysis.contains_dex and self.xor_bruteforce:
                xor_result = self._xor_bruteforce_scan(data)
                if xor_result:
                    dex_offsets = self._find_dex_signatures(xor_result)
                    if dex_offsets:
                        for i, offset in enumerate(dex_offsets):
                            path = self._extract_dex_at_offset(
                                xor_result, offset, f"xor_{filename}", i
                            )
                            if path:
                                analysis.contains_dex = True
                                analysis.extracted_path = path
                                result.extracted_dex.append(path)
                                analysis.notes.append(
                                    "DEX found after XOR decryption"
                                )

        # ─── YARA scan ───
        yara_notes = self._yara_scan(data, filename)
        analysis.notes.extend(yara_notes)

        result.file_analyses.append(analysis)
