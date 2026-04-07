"""
JiaguSentinel Pro v2.0 — GUI Interface
========================================
Modern CustomTkinter dark-mode UI with tabbed interface for static
analysis, dynamic unpacking, malware scoring, and report generation.

Features:
- Four-tab layout (Static / Dynamic / Analytics / Report)
- Payload Gallery dropdown populated from payloads/ folder
- Real-time log terminal with color-coded severity
- Threaded execution — GUI never blocks
- Progress indicators for each engine phase
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentinel.gui")


def launch_gui() -> None:
    """Launch the JiaguSentinel GUI application."""
    try:
        import customtkinter as ctk
    except ImportError:
        print("[ERROR] customtkinter not installed. Run: pip install customtkinter")
        return

    from tkinter import filedialog, messagebox

    # ── Theme Configuration ───────────────────────────────────────

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    COLORS = {
        "bg_dark": "#0a0a0f",
        "bg_medium": "#12121a",
        "bg_light": "#1a1a2e",
        "accent": "#00d4ff",
        "accent_dim": "#0077aa",
        "success": "#00ff88",
        "warning": "#ffaa00",
        "error": "#ff4444",
        "text": "#e0e0e0",
        "text_dim": "#888888",
        "terminal_bg": "#050510",
        "terminal_fg": "#00ff41",
    }

    # ── Application Window ────────────────────────────────────────

    class SentinelApp(ctk.CTk):
        """Main application window for JiaguSentinel Pro."""

        def __init__(self) -> None:
            super().__init__()

            self.title("JiaguSentinel Pro v2.0")
            self.geometry("1100x750")
            self.minsize(900, 600)

            self.grid_columnconfigure(0, weight=1)
            self.grid_rowconfigure(1, weight=1)

            self._apk_path: str = ""
            self._output_dir: str = "unpacked_output"
            self._is_running: bool = False

            self._build_header()
            self._build_tabs()
            self._build_footer()

        # ── Header ────────────────────────────────────────────────

        def _build_header(self) -> None:
            header_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_light"], corner_radius=0)
            header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
            header_frame.grid_columnconfigure(1, weight=1)

            logo_label = ctk.CTkLabel(
                header_frame,
                text="🛡️ JIAGU SENTINEL PRO",
                font=("Segoe UI", 24, "bold"),
                text_color=COLORS["accent"],
            )
            logo_label.grid(row=0, column=0, padx=20, pady=15)

            version_label = ctk.CTkLabel(
                header_frame,
                text="v2.0 | Advanced APK Unpacker & Malware Forensics",
                font=("Segoe UI", 12),
                text_color=COLORS["text_dim"],
            )
            version_label.grid(row=0, column=1, padx=10, pady=15, sticky="w")

        # ── Tabbed Interface ──────────────────────────────────────

        def _build_tabs(self) -> None:
            self.tabview = ctk.CTkTabview(
                self,
                fg_color=COLORS["bg_medium"],
                segmented_button_fg_color=COLORS["bg_light"],
                segmented_button_selected_color=COLORS["accent_dim"],
                segmented_button_unselected_color=COLORS["bg_dark"],
            )
            self.tabview.grid(row=1, column=0, padx=15, pady=(5, 10), sticky="nsew")

            # Create tabs
            tab_static = self.tabview.add("🔬 Static Analysis")
            tab_dynamic = self.tabview.add("⚡ Dynamic Dump")
            tab_analytics = self.tabview.add("🦠 Analytics")
            tab_report = self.tabview.add("📄 Report")

            self._build_static_tab(tab_static)
            self._build_dynamic_tab(tab_dynamic)
            self._build_analytics_tab(tab_analytics)
            self._build_report_tab(tab_report)

        # ── Static Tab ────────────────────────────────────────────

        def _build_static_tab(self, parent: ctk.CTkFrame) -> None:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_rowconfigure(2, weight=1)

            # APK selection
            file_frame = ctk.CTkFrame(parent, fg_color="transparent")
            file_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            file_frame.grid_columnconfigure(0, weight=1)

            self.apk_entry = ctk.CTkEntry(
                file_frame,
                placeholder_text="Select APK file...",
                font=("Consolas", 13),
                height=38,
            )
            self.apk_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")

            browse_btn = ctk.CTkButton(
                file_frame,
                text="📂 BROWSE",
                command=self._browse_apk,
                width=120,
                height=38,
                font=("Segoe UI", 13, "bold"),
            )
            browse_btn.grid(row=0, column=1)

            # Options
            opts_frame = ctk.CTkFrame(parent, fg_color="transparent")
            opts_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

            self.xor_var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(
                opts_frame,
                text="XOR Brute-Force",
                variable=self.xor_var,
                font=("Segoe UI", 12),
            ).pack(side="left", padx=10)

            self.entropy_var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(
                opts_frame,
                text="Entropy Heatmap",
                variable=self.entropy_var,
                font=("Segoe UI", 12),
            ).pack(side="left", padx=10)

            self.static_start_btn = ctk.CTkButton(
                opts_frame,
                text="▶ START SCAN",
                command=self._run_static_scan,
                fg_color=COLORS["accent_dim"],
                hover_color=COLORS["accent"],
                width=150,
                height=35,
                font=("Segoe UI", 13, "bold"),
            )
            self.static_start_btn.pack(side="right", padx=10)

            # Log terminal
            self.static_log = ctk.CTkTextbox(
                parent,
                font=("Consolas", 12),
                fg_color=COLORS["terminal_bg"],
                text_color=COLORS["terminal_fg"],
                corner_radius=8,
            )
            self.static_log.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        # ── Dynamic Tab ───────────────────────────────────────────

        def _build_dynamic_tab(self, parent: ctk.CTkFrame) -> None:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_rowconfigure(3, weight=1)

            # Package input
            pkg_frame = ctk.CTkFrame(parent, fg_color="transparent")
            pkg_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            pkg_frame.grid_columnconfigure(0, weight=1)

            self.pkg_entry = ctk.CTkEntry(
                pkg_frame,
                placeholder_text="Package name (e.g., com.example.app)",
                font=("Consolas", 13),
                height=38,
            )
            self.pkg_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")

            # Payload gallery
            payload_frame = ctk.CTkFrame(parent, fg_color="transparent")
            payload_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

            ctk.CTkLabel(
                payload_frame,
                text="Payload:",
                font=("Segoe UI", 12),
            ).pack(side="left", padx=(10, 5))

            self.payloads = self._discover_payloads()
            self.payload_var = ctk.StringVar(value=self.payloads[0] if self.payloads else "None")
            self.payload_menu = ctk.CTkOptionMenu(
                payload_frame,
                values=self.payloads or ["No payloads found"],
                variable=self.payload_var,
                width=250,
                font=("Consolas", 12),
            )
            self.payload_menu.pack(side="left", padx=5)

            refresh_btn = ctk.CTkButton(
                payload_frame,
                text="🔄",
                width=35,
                command=self._refresh_payloads,
            )
            refresh_btn.pack(side="left", padx=5)

            # Options
            dyn_opts = ctk.CTkFrame(parent, fg_color="transparent")
            dyn_opts.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

            self.anti_detect_var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(
                dyn_opts,
                text="Anti-Detection Hooks",
                variable=self.anti_detect_var,
                font=("Segoe UI", 12),
            ).pack(side="left", padx=10)

            self.spawn_var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(
                dyn_opts,
                text="Spawn (vs Attach)",
                variable=self.spawn_var,
                font=("Segoe UI", 12),
            ).pack(side="left", padx=10)

            self.dynamic_start_btn = ctk.CTkButton(
                dyn_opts,
                text="▶ START DUMP",
                command=self._run_dynamic_dump,
                fg_color="#cc5500",
                hover_color="#ff6600",
                width=150,
                height=35,
                font=("Segoe UI", 13, "bold"),
            )
            self.dynamic_start_btn.pack(side="right", padx=10)

            # Log terminal
            self.dynamic_log = ctk.CTkTextbox(
                parent,
                font=("Consolas", 12),
                fg_color=COLORS["terminal_bg"],
                text_color=COLORS["terminal_fg"],
                corner_radius=8,
            )
            self.dynamic_log.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

        # ── Analytics Tab ─────────────────────────────────────────

        def _build_analytics_tab(self, parent: ctk.CTkFrame) -> None:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_rowconfigure(1, weight=1)

            ctrl_frame = ctk.CTkFrame(parent, fg_color="transparent")
            ctrl_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
            ctrl_frame.grid_columnconfigure(0, weight=1)

            self.dex_entry = ctk.CTkEntry(
                ctrl_frame,
                placeholder_text="Select extracted DEX file for analysis...",
                font=("Consolas", 13),
                height=38,
            )
            self.dex_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")

            browse_dex_btn = ctk.CTkButton(
                ctrl_frame,
                text="📂 BROWSE DEX",
                command=self._browse_dex,
                width=130,
                height=38,
            )
            browse_dex_btn.grid(row=0, column=1, padx=(0, 10))

            self.analyze_btn = ctk.CTkButton(
                ctrl_frame,
                text="▶ ANALYZE",
                command=self._run_analysis,
                fg_color="#880088",
                hover_color="#aa00aa",
                width=120,
                height=38,
                font=("Segoe UI", 13, "bold"),
            )
            self.analyze_btn.grid(row=0, column=2)

            self.analytics_log = ctk.CTkTextbox(
                parent,
                font=("Consolas", 12),
                fg_color=COLORS["terminal_bg"],
                text_color=COLORS["terminal_fg"],
                corner_radius=8,
            )
            self.analytics_log.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # ── Report Tab ────────────────────────────────────────────

        def _build_report_tab(self, parent: ctk.CTkFrame) -> None:
            parent.grid_columnconfigure(0, weight=1)
            parent.grid_rowconfigure(1, weight=1)

            ctrl_frame = ctk.CTkFrame(parent, fg_color="transparent")
            ctrl_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

            self.report_json_btn = ctk.CTkButton(
                ctrl_frame,
                text="📊 Generate JSON Report",
                command=lambda: self._generate_report("json"),
                width=200,
                height=38,
            )
            self.report_json_btn.pack(side="left", padx=10)

            self.report_md_btn = ctk.CTkButton(
                ctrl_frame,
                text="📝 Generate Markdown Report",
                command=lambda: self._generate_report("markdown"),
                width=220,
                height=38,
            )
            self.report_md_btn.pack(side="left", padx=10)

            open_folder_btn = ctk.CTkButton(
                ctrl_frame,
                text="📁 Open Reports Folder",
                command=self._open_reports_folder,
                fg_color=COLORS["bg_light"],
                width=180,
                height=38,
            )
            open_folder_btn.pack(side="right", padx=10)

            self.report_log = ctk.CTkTextbox(
                parent,
                font=("Consolas", 12),
                fg_color=COLORS["terminal_bg"],
                text_color=COLORS["terminal_fg"],
                corner_radius=8,
            )
            self.report_log.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        # ── Footer ────────────────────────────────────────────────

        def _build_footer(self) -> None:
            footer = ctk.CTkFrame(self, fg_color=COLORS["bg_light"], height=30, corner_radius=0)
            footer.grid(row=2, column=0, sticky="ew")

            self.status_label = ctk.CTkLabel(
                footer,
                text="Ready",
                font=("Segoe UI", 11),
                text_color=COLORS["text_dim"],
            )
            self.status_label.pack(side="left", padx=15, pady=5)

            ctk.CTkLabel(
                footer,
                text="JiaguSentinel Pro v2.0 | MIT License",
                font=("Segoe UI", 10),
                text_color=COLORS["text_dim"],
            ).pack(side="right", padx=15, pady=5)

        # ── Payload Discovery ─────────────────────────────────────

        def _discover_payloads(self) -> list[str]:
            payloads_dir = Path(__file__).parent.parent / "payloads"
            if payloads_dir.is_dir():
                return sorted([f.name for f in payloads_dir.glob("*.js")])
            return []

        def _refresh_payloads(self) -> None:
            self.payloads = self._discover_payloads()
            self.payload_menu.configure(
                values=self.payloads or ["No payloads found"]
            )
            if self.payloads:
                self.payload_var.set(self.payloads[0])

        # ── File Browsing ─────────────────────────────────────────

        def _browse_apk(self) -> None:
            path = filedialog.askopenfilename(
                filetypes=[("APK Files", "*.apk"), ("All Files", "*.*")]
            )
            if path:
                self.apk_entry.delete(0, "end")
                self.apk_entry.insert(0, path)
                self._apk_path = path

        def _browse_dex(self) -> None:
            path = filedialog.askopenfilename(
                filetypes=[("DEX Files", "*.dex"), ("All Files", "*.*")]
            )
            if path:
                self.dex_entry.delete(0, "end")
                self.dex_entry.insert(0, path)

        # ── Thread-Safe Logging ───────────────────────────────────

        def _append_log(self, widget: ctk.CTkTextbox, message: str) -> None:
            widget.insert("end", message + "\n")
            widget.see("end")

        def _set_status(self, text: str) -> None:
            self.status_label.configure(text=text)

        # ── Static Scan ───────────────────────────────────────────

        def _run_static_scan(self) -> None:
            apk = self.apk_entry.get()
            if not apk or not os.path.isfile(apk):
                from tkinter import messagebox
                messagebox.showwarning("Error", "Select a valid APK file.")
                return

            self.static_log.delete("1.0", "end")
            self.static_start_btn.configure(state="disabled")
            self._set_status("Running static analysis...")

            def worker():
                try:
                    from core.static_engine import StaticEngine
                    engine = StaticEngine(
                        output_dir=self._output_dir,
                        log_callback=lambda m: self.after(
                            0, self._append_log, self.static_log, m
                        ),
                        xor_bruteforce=self.xor_var.get(),
                    )
                    result = engine.scan(apk)
                    self.after(0, self._set_status,
                              f"Static scan complete: {len(result.extracted_dex)} DEX extracted")
                    self._static_result = result
                except Exception as e:
                    self.after(0, self._append_log, self.static_log,
                              f"[ERROR] {e}")
                finally:
                    self.after(0, lambda: self.static_start_btn.configure(state="normal"))

            threading.Thread(target=worker, daemon=True).start()

        # ── Dynamic Dump ──────────────────────────────────────────

        def _run_dynamic_dump(self) -> None:
            pkg = self.pkg_entry.get()
            if not pkg:
                from tkinter import messagebox
                messagebox.showwarning("Error", "Enter a package name.")
                return

            self.dynamic_log.delete("1.0", "end")
            self.dynamic_start_btn.configure(state="disabled")
            self._set_status("Running dynamic dump...")

            def worker():
                try:
                    from core.dynamic_engine import DynamicEngine
                    engine = DynamicEngine(
                        output_dir=self._output_dir,
                        log_callback=lambda m: self.after(
                            0, self._append_log, self.dynamic_log, m
                        ),
                        anti_detection=self.anti_detect_var.get(),
                    )
                    # Load selected payload
                    custom_payload = None
                    selected = self.payload_var.get()
                    if selected and selected != "None" and selected != "No payloads found":
                        try:
                            custom_payload = engine.load_payload(selected)
                        except FileNotFoundError:
                            pass

                    result = engine.dump(
                        package_name=pkg,
                        custom_payload=custom_payload,
                        spawn=self.spawn_var.get(),
                    )
                    self._dynamic_result = result
                    self.after(0, self._set_status,
                              f"Dynamic dump complete: {len(result.dumped_dex)} DEX dumped")
                except ImportError:
                    self.after(0, self._append_log, self.dynamic_log,
                              "[ERROR] frida-tools not installed. Run: pip install frida-tools")
                except Exception as e:
                    self.after(0, self._append_log, self.dynamic_log,
                              f"[ERROR] {e}")
                finally:
                    self.after(0, lambda: self.dynamic_start_btn.configure(state="normal"))

            threading.Thread(target=worker, daemon=True).start()

        # ── Malware Analysis ──────────────────────────────────────

        def _run_analysis(self) -> None:
            dex_path = self.dex_entry.get()
            if not dex_path or not os.path.isfile(dex_path):
                from tkinter import messagebox
                messagebox.showwarning("Error", "Select a valid DEX file.")
                return

            self.analytics_log.delete("1.0", "end")
            self.analyze_btn.configure(state="disabled")
            self._set_status("Running malware analysis...")

            def worker():
                try:
                    from analytics.malware_scorer import MalwareScorer
                    scorer = MalwareScorer(
                        log_callback=lambda m: self.after(
                            0, self._append_log, self.analytics_log, m
                        )
                    )
                    report = scorer.analyze(dex_path)
                    self._malware_reports = [report]
                    self.after(0, self._set_status,
                              f"Analysis complete: Score {report.threat_score}/100 "
                              f"[{report.threat_level.value}]")
                except Exception as e:
                    self.after(0, self._append_log, self.analytics_log,
                              f"[ERROR] {e}")
                finally:
                    self.after(0, lambda: self.analyze_btn.configure(state="normal"))

            threading.Thread(target=worker, daemon=True).start()

        # ── Report Generation ─────────────────────────────────────

        def _generate_report(self, fmt: str) -> None:
            apk = self.apk_entry.get() or "unknown.apk"
            self.report_log.delete("1.0", "end")
            self._set_status(f"Generating {fmt} report...")

            def worker():
                try:
                    from analytics.report_gen import ReportGenerator
                    gen = ReportGenerator(
                        log_callback=lambda m: self.after(
                            0, self._append_log, self.report_log, m
                        )
                    )
                    static_r = getattr(self, "_static_result", None)
                    dynamic_r = getattr(self, "_dynamic_result", None)
                    malware_r = getattr(self, "_malware_reports", None)

                    if fmt == "json":
                        path = gen.generate_json(apk, static_r, dynamic_r, malware_r)
                    else:
                        path = gen.generate_markdown(apk, static_r, dynamic_r, malware_r)

                    self.after(0, self._set_status, f"Report saved: {path}")
                except Exception as e:
                    self.after(0, self._append_log, self.report_log,
                              f"[ERROR] {e}")

            threading.Thread(target=worker, daemon=True).start()

        # ── Utilities ─────────────────────────────────────────────

        def _open_reports_folder(self) -> None:
            path = os.path.abspath("reports")
            os.makedirs(path, exist_ok=True)
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])

    # ── Launch ────────────────────────────────────────────────────

    app = SentinelApp()
    app.mainloop()
