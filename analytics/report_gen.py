"""
JiaguSentinel Pro v2.0 — Report Generator
===========================================
Generates comprehensive forensic reports in JSON and Markdown formats
aggregating static analysis, dynamic dumps, and malware scoring results.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("sentinel.report")


class ReportGenerator:
    """
    Forensic report generator for JiaguSentinel analysis sessions.

    Aggregates outputs from StaticEngine, DynamicEngine, and
    MalwareScorer into a unified, timestamped report.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._log_cb = log_callback

    def _log(self, message: str, level: str = "INFO") -> None:
        getattr(logger, level.lower(), logger.info)(message)
        if self._log_cb:
            self._log_cb(f"[{level}] {message}")

    # ── Report Data Assembly ──────────────────────────────────────────

    def _build_report_data(
        self,
        apk_path: str,
        static_result: Optional[Any] = None,
        dynamic_result: Optional[Any] = None,
        malware_reports: Optional[list[Any]] = None,
    ) -> dict:
        """Assemble all analysis results into a unified data structure."""
        timestamp = datetime.now(timezone.utc).isoformat()
        apk_name = os.path.basename(apk_path)

        report: dict = {
            "meta": {
                "tool": "JiaguSentinel Pro",
                "version": "2.0.0",
                "timestamp": timestamp,
                "apk_file": apk_name,
                "apk_path": str(apk_path),
            },
            "static_analysis": {},
            "dynamic_analysis": {},
            "malware_analysis": [],
            "summary": {},
        }

        # ─── Static Results ───
        if static_result:
            report["static_analysis"] = {
                "apk_sha256": getattr(static_result, "apk_sha256", ""),
                "total_files": getattr(static_result, "total_files", 0),
                "jiagu_detected": getattr(static_result, "jiagu_detected", False),
                "jiagu_libraries": getattr(static_result, "jiagu_libraries", []),
                "extracted_dex_count": len(getattr(static_result, "extracted_dex", [])),
                "extracted_dex_paths": getattr(static_result, "extracted_dex", []),
                "packer_sections": getattr(static_result, "packer_sections", []),
                "entropy_map": {
                    k: v for k, v in getattr(static_result, "entropy_map", {}).items()
                    if v > 6.0  # Only include high-entropy entries
                },
                "errors": getattr(static_result, "errors", []),
            }

        # ─── Dynamic Results ───
        if dynamic_result:
            report["dynamic_analysis"] = {
                "package_name": getattr(dynamic_result, "package_name", ""),
                "device_id": getattr(dynamic_result, "device_id", ""),
                "frida_version": getattr(dynamic_result, "frida_version", ""),
                "session_duration": getattr(dynamic_result, "session_duration", 0),
                "anti_detection_active": getattr(
                    dynamic_result, "anti_detection_active", False
                ),
                "hooked_functions": getattr(dynamic_result, "hooked_functions", []),
                "dumped_dex": [
                    {
                        "address": d.address,
                        "size": d.size,
                        "path": d.path,
                        "sha256": d.sha256,
                    }
                    for d in getattr(dynamic_result, "dumped_dex", [])
                ],
                "errors": getattr(dynamic_result, "errors", []),
            }

        # ─── Malware Reports ───
        if malware_reports:
            for mr in malware_reports:
                entry = {
                    "dex_path": getattr(mr, "dex_path", ""),
                    "dex_sha256": getattr(mr, "dex_sha256", ""),
                    "dex_size": getattr(mr, "dex_size", 0),
                    "threat_score": getattr(mr, "threat_score", 0),
                    "threat_level": getattr(mr, "threat_level", "UNKNOWN")
                    if isinstance(getattr(mr, "threat_level", None), str)
                    else getattr(mr, "threat_level", None).value
                    if hasattr(getattr(mr, "threat_level", None), "value")
                    else "UNKNOWN",
                    "category_scores": getattr(mr, "category_scores", {}),
                    "network_indicators": getattr(mr, "network_indicators", {}),
                    "indicators_count": len(getattr(mr, "indicators", [])),
                    "top_indicators": [
                        {
                            "category": ind.category,
                            "indicator": ind.indicator,
                            "description": ind.description,
                            "weight": ind.weight,
                        }
                        for ind in sorted(
                            getattr(mr, "indicators", []),
                            key=lambda x: x.weight,
                            reverse=True,
                        )[:15]
                    ],
                }
                report["malware_analysis"].append(entry)

        # ─── Summary ───
        max_threat = 0.0
        max_level = "CLEAN"
        if malware_reports:
            for mr in malware_reports:
                score = getattr(mr, "threat_score", 0)
                if score > max_threat:
                    max_threat = score
                    lvl = getattr(mr, "threat_level", None)
                    max_level = lvl.value if hasattr(lvl, "value") else str(lvl)

        total_dex = len(getattr(static_result, "extracted_dex", []) if static_result else [])
        total_dex += len(getattr(dynamic_result, "dumped_dex", []) if dynamic_result else [])

        report["summary"] = {
            "jiagu_packed": getattr(static_result, "jiagu_detected", False)
            if static_result else False,
            "total_dex_extracted": total_dex,
            "highest_threat_score": max_threat,
            "threat_level": max_level,
            "verdict": self._verdict(max_threat),
        }

        return report

    @staticmethod
    def _verdict(score: float) -> str:
        if score < 15:
            return "No significant threats detected."
        elif score < 35:
            return "Low-risk indicators found. Manual review recommended."
        elif score < 60:
            return "Medium-risk: suspicious APIs and/or network indicators present."
        elif score < 80:
            return "HIGH RISK: Multiple malware indicators detected."
        else:
            return "CRITICAL: Strong malware indicators. Treat as hostile."

    # ── JSON Output ───────────────────────────────────────────────────

    def generate_json(
        self,
        apk_path: str,
        static_result: Optional[Any] = None,
        dynamic_result: Optional[Any] = None,
        malware_reports: Optional[list[Any]] = None,
    ) -> str:
        """Generate a JSON forensic report and save to disk."""
        data = self._build_report_data(
            apk_path, static_result, dynamic_result, malware_reports
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        apk_name = Path(apk_path).stem
        filename = f"report_{apk_name}_{timestamp}.json"
        out_path = self.output_dir / filename

        out_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self._log(f"✓ JSON report saved: {out_path}")
        return str(out_path)

    # ── Markdown Output ───────────────────────────────────────────────

    def generate_markdown(
        self,
        apk_path: str,
        static_result: Optional[Any] = None,
        dynamic_result: Optional[Any] = None,
        malware_reports: Optional[list[Any]] = None,
    ) -> str:
        """Generate a Markdown forensic report and save to disk."""
        data = self._build_report_data(
            apk_path, static_result, dynamic_result, malware_reports
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        apk_name = Path(apk_path).stem
        filename = f"report_{apk_name}_{timestamp}.md"
        out_path = self.output_dir / filename

        md = self._render_markdown(data)
        out_path.write_text(md, encoding="utf-8")
        self._log(f"✓ Markdown report saved: {out_path}")
        return str(out_path)

    def _render_markdown(self, data: dict) -> str:
        """Render the report data structure into Markdown."""
        meta = data["meta"]
        summary = data["summary"]
        static = data["static_analysis"]
        dynamic = data["dynamic_analysis"]
        malware = data["malware_analysis"]

        lines: list[str] = []
        lines.append(f"# 🛡️ JiaguSentinel Forensic Report")
        lines.append(f"")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **APK** | `{meta['apk_file']}` |")
        lines.append(f"| **Timestamp** | {meta['timestamp']} |")
        lines.append(f"| **Tool Version** | {meta['version']} |")
        lines.append(f"")

        # ─── Summary ───
        threat_emoji = {
            "CLEAN": "🟢", "LOW": "🟡", "MEDIUM": "🟠",
            "HIGH": "🔴", "CRITICAL": "🔥",
        }
        emoji = threat_emoji.get(summary["threat_level"], "❓")

        lines.append(f"## {emoji} Summary")
        lines.append(f"")
        lines.append(f"- **Jiagu Packed:** {'Yes' if summary['jiagu_packed'] else 'No'}")
        lines.append(f"- **DEX Extracted:** {summary['total_dex_extracted']}")
        lines.append(
            f"- **Threat Score:** {summary['highest_threat_score']}/100 "
            f"[{summary['threat_level']}]"
        )
        lines.append(f"- **Verdict:** {summary['verdict']}")
        lines.append(f"")

        # ─── Static Analysis ───
        if static:
            lines.append(f"## 🔬 Static Analysis")
            lines.append(f"")
            lines.append(f"- **SHA256:** `{static.get('apk_sha256', 'N/A')}`")
            lines.append(f"- **Total Files:** {static.get('total_files', 0)}")
            lines.append(
                f"- **Jiagu Libraries:** "
                f"{', '.join(static.get('jiagu_libraries', [])) or 'None'}"
            )
            lines.append(f"- **DEX Extracted:** {static.get('extracted_dex_count', 0)}")
            if static.get("packer_sections"):
                lines.append(f"- **Packer Sections:** {', '.join(static['packer_sections'])}")
            if static.get("errors"):
                lines.append(f"- **Errors:** {len(static['errors'])}")
            lines.append(f"")

            # Entropy map
            entropy_map = static.get("entropy_map", {})
            if entropy_map:
                lines.append(f"### Entropy Hotspots")
                lines.append(f"")
                lines.append(f"| File | Entropy |")
                lines.append(f"|------|---------|")
                for fname, ent in sorted(
                    entropy_map.items(), key=lambda x: x[1], reverse=True
                )[:20]:
                    bar = "█" * int(ent) + "░" * (8 - int(ent))
                    lines.append(f"| `{fname}` | {ent:.2f} {bar} |")
                lines.append(f"")

        # ─── Dynamic Analysis ───
        if dynamic:
            lines.append(f"## ⚡ Dynamic Analysis")
            lines.append(f"")
            lines.append(f"- **Package:** `{dynamic.get('package_name', 'N/A')}`")
            lines.append(f"- **Device:** `{dynamic.get('device_id', 'N/A')}`")
            lines.append(f"- **Frida Version:** {dynamic.get('frida_version', 'N/A')}")
            lines.append(
                f"- **Anti-Detection:** "
                f"{'Active ✓' if dynamic.get('anti_detection_active') else 'Off'}"
            )
            lines.append(
                f"- **Session Duration:** {dynamic.get('session_duration', 0):.1f}s"
            )
            dumped = dynamic.get("dumped_dex", [])
            lines.append(f"- **DEX Dumped:** {len(dumped)}")
            if dumped:
                lines.append(f"")
                lines.append(f"| # | Address | Size | SHA256 |")
                lines.append(f"|---|---------|------|--------|")
                for i, d in enumerate(dumped):
                    lines.append(
                        f"| {i+1} | `{d['address']}` | "
                        f"{d['size']:,} | `{d['sha256'][:12]}...` |"
                    )
            lines.append(f"")

        # ─── Malware Analysis ───
        if malware:
            lines.append(f"## 🦠 Malware Analysis")
            lines.append(f"")
            for i, mr in enumerate(malware):
                emoji_m = threat_emoji.get(mr["threat_level"], "❓")
                lines.append(f"### DEX #{i+1}: `{Path(mr['dex_path']).name}`")
                lines.append(f"")
                lines.append(
                    f"- **Score:** {mr['threat_score']}/100 "
                    f"{emoji_m} [{mr['threat_level']}]"
                )
                lines.append(f"- **SHA256:** `{mr['dex_sha256']}`")
                lines.append(f"- **Size:** {mr['dex_size']:,} bytes")
                lines.append(f"")

                # Category breakdown
                if mr.get("category_scores"):
                    lines.append(f"**Category Breakdown:**")
                    lines.append(f"")
                    lines.append(f"| Category | Score |")
                    lines.append(f"|----------|-------|")
                    for cat, sc in sorted(
                        mr["category_scores"].items(),
                        key=lambda x: x[1],
                        reverse=True,
                    ):
                        lines.append(f"| {cat} | {sc:.1f} |")
                    lines.append(f"")

                # Top indicators
                top = mr.get("top_indicators", [])
                if top:
                    lines.append(f"**Top Indicators:**")
                    lines.append(f"")
                    lines.append(f"| Indicator | Category | Weight | Description |")
                    lines.append(f"|-----------|----------|--------|-------------|")
                    for ind in top[:10]:
                        lines.append(
                            f"| `{ind['indicator'][:40]}` | {ind['category']} | "
                            f"{ind['weight']:.1f} | {ind['description']} |"
                        )
                    lines.append(f"")

                # Network indicators
                net = mr.get("network_indicators", {})
                if any(v for v in net.values()):
                    lines.append(f"**Network Indicators:**")
                    lines.append(f"")
                    if net.get("ips"):
                        lines.append(f"- IPs: {', '.join(f'`{ip}`' for ip in net['ips'][:10])}")
                    if net.get("urls"):
                        lines.append(f"- URLs: {len(net['urls'])} found")
                        for url in net["urls"][:5]:
                            lines.append(f"  - `{url[:80]}`")
                    if net.get("domains"):
                        lines.append(
                            f"- Domains: {', '.join(f'`{d}`' for d in net['domains'][:10])}"
                        )
                    lines.append(f"")

        # ─── Footer ───
        lines.append(f"---")
        lines.append(f"*Generated by JiaguSentinel Pro v2.0 — "
                      f"For authorized security research only.*")

        return "\n".join(lines)
