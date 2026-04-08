"""
JiaguSentinel Pro v2.0 — GUI Interface (Compact Fluent Design)
===============================================================
Compact, tab-driven dark UI inspired by Microsoft PC Manager.

Layout:
  ┌────────┬─────────────────────────────────────────┐
  │Sidebar │  Page Title                              │
  │ 70px   │  ┌─[Tab1]─[Tab2]─[Tab3]──────────────┐  │
  │        │  │  Cards / forms (no scroll needed)  │  │
  │        │  └──────────────────────────────────── ┘  │
  ├────────┴─────────────────────────────────────────┤
  │  ▪ System Terminal  (fixed 130px)                │
  └─────────────────────────────────────────────────┘

Design tokens: BG #0f0f0f | Card #1e1e1e | Accent #00a2ed
"""

from __future__ import annotations

import os
import platform
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional
import logging

logger = logging.getLogger("sentinel.gui")


# ── Design Tokens ─────────────────────────────────────────────────────────────

class T:
    BG           = "#0f0f0f"
    SIDEBAR      = "#141414"
    CARD         = "#1e1e1e"
    CARD_HOVER   = "#242424"
    BORDER       = "#2c2c2c"
    ACCENT       = "#00a2ed"
    ACCENT_HOVER = "#0091d4"
    ACCENT_DIM   = "#003d57"
    SUCCESS      = "#00c853"
    WARNING      = "#ffab00"
    ERROR        = "#ff5252"
    TEXT_H1      = "#f0f0f0"
    TEXT_BODY    = "#a0a0a0"
    TEXT_MUTED   = "#555555"
    TERMINAL_BG  = "#070707"
    TERMINAL_FG  = "#00e676"

    # Compact typography
    F_PAGE    = ("Segoe UI", 17, "bold")
    F_CARD_H  = ("Segoe UI", 12, "bold")
    F_CARD_D  = ("Segoe UI", 10)
    F_BTN     = ("Segoe UI", 11, "bold")
    F_NAV     = ("Segoe UI",  9)
    F_LABEL   = ("Segoe UI", 11)
    F_MONO    = ("Consolas", 13)   # terminal / entry — larger for readability
    F_MUTED   = ("Segoe UI",  9)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _card(parent, **kw):
    import customtkinter as ctk
    return ctk.CTkFrame(parent,
        fg_color=T.CARD, corner_radius=10,
        border_width=1, border_color=T.BORDER, **kw)

def _accent_btn(parent, text, cmd, w=88, h=30, **kw):
    import customtkinter as ctk
    defaults = dict(fg_color=T.ACCENT, hover_color=T.ACCENT_HOVER,
                    text_color="#fff", font=T.F_BTN,
                    corner_radius=7, width=w, height=h)
    defaults.update(kw)
    return ctk.CTkButton(parent, text=text, command=cmd, **defaults)

def _ghost_btn(parent, text, cmd, w=80, h=28, **kw):
    import customtkinter as ctk
    defaults = dict(fg_color="transparent", hover_color=T.CARD_HOVER,
                    text_color=T.TEXT_BODY, font=T.F_BTN,
                    corner_radius=7, border_width=1, border_color=T.BORDER,
                    width=w, height=h)
    defaults.update(kw)
    return ctk.CTkButton(parent, text=text, command=cmd, **defaults)

def _lbl(parent, text, font=None, color=None, **kw):
    import customtkinter as ctk
    return ctk.CTkLabel(parent, text=text,
        font=font or T.F_LABEL, text_color=color or T.TEXT_BODY, **kw)

def _section(parent, text):
    import customtkinter as ctk
    return ctk.CTkLabel(parent, text=text.upper(),
        font=("Segoe UI", 8, "bold"), text_color=T.TEXT_MUTED)


def _scroll_tab(tab) -> "ctk.CTkScrollableFrame":
    """Wrap a CTkTabview tab with a scrollable frame that fills it."""
    import customtkinter as ctk
    sf = ctk.CTkScrollableFrame(
        tab,
        fg_color="transparent",
        scrollbar_button_color=T.BORDER,
        scrollbar_button_hover_color=T.ACCENT_DIM,
    )
    sf.pack(fill="both", expand=True)
    sf.grid_columnconfigure(0, weight=1)
    return sf


# ── Compact Tool Row ──────────────────────────────────────────────────────────

class ToolRow:
    """
    Slim horizontal tool card:  icon │ title + desc │ [btn]
    Height ≈ 52px — fits several on screen without scrolling.
    """
    def __init__(self, parent, icon, title, desc, btn_text="Run ›", cmd=None):
        import customtkinter as ctk
        f = _card(parent)
        f.pack(fill="x", pady=3)
        f.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(f, text=icon, font=("Segoe UI Emoji", 18),
                     text_color=T.ACCENT, width=38).grid(
            row=0, column=0, rowspan=2, padx=(12, 6), pady=8, sticky="ns")

        ctk.CTkLabel(f, text=title, font=T.F_CARD_H, text_color=T.TEXT_H1,
                     anchor="w").grid(row=0, column=1, sticky="sw", padx=4, pady=(6, 1))
        ctk.CTkLabel(f, text=desc, font=T.F_CARD_D, text_color=T.TEXT_BODY,
                     anchor="w").grid(row=1, column=1, sticky="nw", padx=4, pady=(0, 6))

        if cmd:
            self.btn = _accent_btn(f, btn_text, cmd, w=70, h=28)
            self.btn.grid(row=0, column=2, rowspan=2, padx=10, pady=8)
        self.frame = f


# ── Sidebar Button ────────────────────────────────────────────────────────────

class NavBtn:
    """Compact icon-above-label sidebar button (70px wide)."""
    def __init__(self, parent, icon, label, cmd):
        import customtkinter as ctk
        self.active = False
        self._cmd = cmd

        self.f = ctk.CTkFrame(parent, fg_color="transparent",
                               corner_radius=8, cursor="hand2")
        self.f.pack(fill="x", padx=6, pady=2)

        self._ico = ctk.CTkLabel(self.f, text=icon,
                                  font=("Segoe UI Emoji", 18), text_color=T.TEXT_MUTED)
        self._ico.pack(pady=(7, 0))
        self._lbl = ctk.CTkLabel(self.f, text=label,
                                  font=T.F_NAV, text_color=T.TEXT_MUTED)
        self._lbl.pack(pady=(1, 7))

        for w in (self.f, self._ico, self._lbl):
            w.bind("<Button-1>", lambda _=None: self._cmd())
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

    def _on_enter(self, _=None):
        if not self.active:
            self.f.configure(fg_color=T.CARD)

    def _on_leave(self, _=None):
        if not self.active:
            self.f.configure(fg_color="transparent")

    def set_active(self, v: bool):
        self.active = v
        if v:
            self.f.configure(fg_color=T.ACCENT_DIM)
            self._ico.configure(text_color=T.ACCENT)
            self._lbl.configure(text_color=T.ACCENT, font=("Segoe UI", 9, "bold"))
        else:
            self.f.configure(fg_color="transparent")
            self._ico.configure(text_color=T.TEXT_MUTED)
            self._lbl.configure(text_color=T.TEXT_MUTED, font=T.F_NAV)


# ══════════════════════════════════════════════════════════════════════════════
# VIEW: HOME
# ══════════════════════════════════════════════════════════════════════════════

class HomeView:
    def __init__(self, parent, app: "App"):
        import customtkinter as ctk
        self.app = app
        self.frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        self._build()

    def _build(self):
        import customtkinter as ctk
        p = self.frame

        # Page header (fixed, no scroll)
        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.pack(fill="x", padx=18, pady=(14, 6))
        _lbl(hdr, "Home", T.F_PAGE, T.TEXT_H1, anchor="w").pack(side="left")
        _accent_btn(hdr, "▶  Quick Scan", self.app.run_quick_scan,
                    w=130, h=36).pack(side="right")

        # Hero status strip
        strip = ctk.CTkFrame(p, fg_color=T.CARD, corner_radius=10,
                             border_width=1, border_color=T.BORDER)
        strip.pack(fill="x", padx=18, pady=(0, 10))
        strip.grid_columnconfigure((0, 1, 2), weight=1, uniform="s")

        stat_data = [
            ("📄", "APK", lambda: Path(self.app._apk_path).name
                           if self.app._apk_path else "None", T.ACCENT),
            ("📦", "DEX Found",
             lambda: str(len(self.app._extracted_dex)), T.SUCCESS),
            ("🔥", "Threat",
             lambda: f"{self.app._threat_score:.0f}/100", T.WARNING),
        ]
        self._stat_vals: list = []
        for col, (icon, label, fn, color) in enumerate(stat_data):
            cf = ctk.CTkFrame(strip, fg_color="transparent")
            cf.grid(row=0, column=col, padx=10, pady=10, sticky="ew")
            ctk.CTkLabel(cf, text=icon, font=("Segoe UI Emoji", 20),
                         text_color=color).pack(side="left", padx=(0, 8))
            vf = ctk.CTkFrame(cf, fg_color="transparent")
            vf.pack(side="left", anchor="w")
            v = ctk.CTkLabel(vf, text=fn(), font=("Segoe UI", 12, "bold"),
                              text_color=T.TEXT_H1, anchor="w")
            v.pack(anchor="w")
            ctk.CTkLabel(vf, text=label, font=T.F_CARD_D,
                         text_color=T.TEXT_BODY, anchor="w").pack(anchor="w")
            self._stat_vals.append((v, fn))

        # Tabview
        tabs = ctk.CTkTabview(p, fg_color=T.CARD,
                              segmented_button_fg_color=T.SIDEBAR,
                              segmented_button_selected_color=T.ACCENT_DIM,
                              segmented_button_unselected_color=T.SIDEBAR,
                              corner_radius=10,
                              border_width=1, border_color=T.BORDER)
        tabs.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        t1 = tabs.add("Target APK")
        t2 = tabs.add("Session Log")

        # Wrap tabs in scrollable frames
        s1 = _scroll_tab(t1)
        s2 = _scroll_tab(t2)

        # — Tab 1: Target APK —
        s1.grid_columnconfigure(0, weight=1)
        _lbl(s1, "Select the APK to unpack:", color=T.TEXT_BODY).grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 4))
        rf = ctk.CTkFrame(s1, fg_color="transparent")
        rf.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
        rf.grid_columnconfigure(0, weight=1)
        self.apk_entry = ctk.CTkEntry(rf,
            placeholder_text="Browse or drag an APK file…",
            fg_color="#111", border_color=T.BORDER, text_color=T.TEXT_H1,
            font=T.F_MONO, height=34, corner_radius=8)
        self.apk_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        _accent_btn(rf, "Browse", self.app.browse_apk, w=100, h=34).grid(row=0, column=1)

        _lbl(s1, "Output folder:", color=T.TEXT_BODY).grid(
            row=2, column=0, sticky="w", padx=12, pady=(6, 4))
        self.out_entry = ctk.CTkEntry(s1,
            fg_color="#111", border_color=T.BORDER, text_color=T.TEXT_H1,
            font=T.F_MONO, height=32, corner_radius=8)
        self.out_entry.insert(0, self.app._output_dir)
        self.out_entry.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 10))

        # — Tab 2: Session Log (quick view) —
        self.mini_log = ctk.CTkTextbox(s2, fg_color="#0a0a0a",
            text_color=T.TERMINAL_FG, font=T.F_MONO,
            corner_radius=0, border_width=0, height=120)
        self.mini_log.pack(fill="both", expand=True)

    def refresh_stats(self):
        for v, fn in self._stat_vals:
            v.configure(text=fn())

    def set_apk(self, path: str):
        self.apk_entry.delete(0, "end")
        self.apk_entry.insert(0, path)

    def append_mini(self, msg: str):
        self.mini_log.insert("end", f"» {msg}\n")
        self.mini_log.see("end")


# ══════════════════════════════════════════════════════════════════════════════
# VIEW: PROTECTION (Static Analysis)
# ══════════════════════════════════════════════════════════════════════════════

class ProtectionView:
    def __init__(self, parent, app: "App"):
        import customtkinter as ctk
        self.app = app
        self.frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        self._build()

    def _build(self):
        import customtkinter as ctk
        p = self.frame

        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.pack(fill="x", padx=18, pady=(14, 6))
        _lbl(hdr, "Protection", T.F_PAGE, T.TEXT_H1, anchor="w").pack(side="left")
        self.scan_btn = _accent_btn(hdr, "▶  Scan", self.app.run_static_scan,
                                    w=110, h=36)
        self.scan_btn.pack(side="right")

        tabs = ctk.CTkTabview(p, fg_color=T.CARD,
                              segmented_button_fg_color=T.SIDEBAR,
                              segmented_button_selected_color=T.ACCENT_DIM,
                              segmented_button_unselected_color=T.SIDEBAR,
                              corner_radius=10,
                              border_width=1, border_color=T.BORDER)
        tabs.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        t_dex  = tabs.add("DEX Scan")
        t_heur = tabs.add("Heuristics")
        t_elf  = tabs.add("ELF / YARA")

        # Each tab gets a scrollable wrapper
        s_dex  = _scroll_tab(t_dex)
        s_heur = _scroll_tab(t_heur)
        s_elf  = _scroll_tab(t_elf)

        # ── Tab: DEX Scan ─────────────────────────────────────────────
        ToolRow(s_dex, "🔍", "DEX Signature Scan",
                "Multi-version magic-byte scan (v035–v041) with header validation",
                "Scan ›", self.app.run_static_scan)
        ToolRow(s_dex, "🗂️", "Multi-DEX Detection",
                "Identify and extract all classes.dex segments inside the APK",
                "Scan ›", self.app.run_static_scan)
        ToolRow(s_dex, "📂", "Open Output Folder",
                "Browse extracted DEX files in the output directory",
                "Open ›", self.app.open_output_folder)

        # ── Tab: Heuristics ───────────────────────────────────────────
        opts_card = _card(s_heur)
        opts_card.pack(fill="x", pady=(4, 6))
        opts_card.grid_columnconfigure(1, weight=1)

        self.xor_var  = ctk.BooleanVar(value=True)
        self.zlib_var = ctk.BooleanVar(value=True)

        for row, (var, label, desc) in enumerate([
            (self.xor_var,  "XOR Brute-Force",       "Single-byte key scan for XOR-encrypted payloads"),
            (self.zlib_var, "Multi-Layer Decompress",  "zlib → gzip → LZMA decompression cascade"),
        ]):
            ctk.CTkCheckBox(opts_card, text="", variable=var,
                            fg_color=T.ACCENT, width=20).grid(
                row=row, column=0, padx=(12, 8), pady=6, sticky="w")
            ctk.CTkLabel(opts_card, text=label, font=T.F_CARD_H,
                         text_color=T.TEXT_H1, anchor="w").grid(
                row=row, column=1, sticky="w", pady=6)
            ctk.CTkLabel(opts_card, text=desc, font=T.F_CARD_D,
                         text_color=T.TEXT_BODY, anchor="w").grid(
                row=row, column=2, padx=(8, 12), pady=6, sticky="w")

        ToolRow(s_heur, "🌡️", "Entropy Heatmap",
                "Block-level Shannon entropy to pinpoint encrypted regions",
                "Map ›", self.app.run_static_scan)

        # ── Tab: ELF / YARA ──────────────────────────────────────────
        self.lief_var = ctk.BooleanVar(value=True)
        self.yara_var = ctk.BooleanVar(value=True)

        elf_card = _card(s_elf)
        elf_card.pack(fill="x", pady=(4, 4))
        elf_card.grid_columnconfigure(1, weight=1)

        for row, (var, label, desc) in enumerate([
            (self.lief_var, "LIEF ELF Analysis",
             "Section entropy & symbol inspection of libjiagu*.so"),
            (self.yara_var, "YARA Rule Matching",
             "Custom .yar signature scan against all APK entries"),
        ]):
            ctk.CTkCheckBox(elf_card, text="", variable=var,
                            fg_color=T.ACCENT, width=20).grid(
                row=row, column=0, padx=(12, 8), pady=7, sticky="w")
            ctk.CTkLabel(elf_card, text=label, font=T.F_CARD_H,
                         text_color=T.TEXT_H1, anchor="w").grid(
                row=row, column=1, sticky="w")
            ctk.CTkLabel(elf_card, text=desc, font=T.F_CARD_D,
                         text_color=T.TEXT_BODY, anchor="w").grid(
                row=row, column=2, padx=(8, 12), pady=7, sticky="w")

        ToolRow(s_elf, "📋", "Packer Section Detector",
                "Identify .jiagu, .vmp, .packed sections in native libraries",
                "Run ›", self.app.run_static_scan)


# ══════════════════════════════════════════════════════════════════════════════
# VIEW: ANALYSIS (Dynamic / Frida)
# ══════════════════════════════════════════════════════════════════════════════

class AnalysisView:
    def __init__(self, parent, app: "App"):
        import customtkinter as ctk
        self.app = app
        self.frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        self._build()

    def _build(self):
        import customtkinter as ctk
        p = self.frame

        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.pack(fill="x", padx=18, pady=(14, 6))
        _lbl(hdr, "Analysis", T.F_PAGE, T.TEXT_H1, anchor="w").pack(side="left")
        self.dump_btn = _accent_btn(
            hdr, "▶  Dump", self.app.run_dynamic_dump, w=110, h=36,
            fg_color="#bf4000", hover_color="#d95000")
        self.dump_btn.pack(side="right")

        tabs = ctk.CTkTabview(p, fg_color=T.CARD,
                              segmented_button_fg_color=T.SIDEBAR,
                              segmented_button_selected_color=T.ACCENT_DIM,
                              segmented_button_unselected_color=T.SIDEBAR,
                              corner_radius=10,
                              border_width=1, border_color=T.BORDER)
        tabs.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        t_pkg   = tabs.add("Package")
        t_frida = tabs.add("Frida Setup")
        t_mem   = tabs.add("Memory Dump")
        t_score = tabs.add("Malware Score")

        # ── Tab: Package ──────────────────────────────────────────────
        t_pkg.grid_columnconfigure(0, weight=1)

        _lbl(t_pkg, "Target package name:", color=T.TEXT_BODY).grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 3))
        self.pkg_entry = ctk.CTkEntry(t_pkg,
            placeholder_text="e.g.  com.suspicious.app",
            fg_color="#111", border_color=T.BORDER, text_color=T.TEXT_H1,
            font=T.F_MONO, height=34, corner_radius=8)
        self.pkg_entry.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))

        _lbl(t_pkg, "Payload script:", color=T.TEXT_BODY).grid(
            row=2, column=0, sticky="w", padx=12, pady=(4, 3))
        pf = ctk.CTkFrame(t_pkg, fg_color="transparent")
        pf.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 8))
        pf.grid_columnconfigure(0, weight=1)

        payloads = self._discover_payloads()
        self.payload_var = ctk.StringVar(value=payloads[0] if payloads else "dex_dump.js")
        ctk.CTkOptionMenu(pf, values=payloads or ["dex_dump.js"],
                          variable=self.payload_var,
                          fg_color=T.CARD_HOVER, button_color=T.ACCENT_DIM,
                          button_hover_color=T.ACCENT,
                          font=T.F_MONO, dropdown_font=T.F_MONO,
                          height=32).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(pf, text="🔄", width=32, height=32,
                      fg_color=T.BORDER, hover_color=T.CARD_HOVER,
                      command=self._refresh_payloads, corner_radius=7).grid(row=0, column=1)

        # ── Tab: Frida Setup ──────────────────────────────────────────
        self.anti_var  = ctk.BooleanVar(value=True)
        self.spawn_var = ctk.BooleanVar(value=True)

        # Scrollable wrapper so all rows are accessible on small screens
        frida_scroll = ctk.CTkScrollableFrame(
            t_frida, fg_color="transparent", corner_radius=0)
        frida_scroll.pack(fill="both", expand=True)

        frida_opts = _card(frida_scroll)
        frida_opts.pack(fill="x", pady=(4, 6))
        for row, (var, label, desc) in enumerate([
            (self.anti_var,  "Anti-Detection Hooks",
             "Hook open/strstr/access/fopen/connect to hide Frida"),
            (self.spawn_var, "Spawn Mode",
             "Spawn fresh process instead of attaching to running"),
        ]):
            ctk.CTkCheckBox(frida_opts, text="", variable=var,
                            fg_color=T.ACCENT, width=20).grid(
                row=row, column=0, padx=(12, 8), pady=7, sticky="w")
            ctk.CTkLabel(frida_opts, text=label, font=T.F_CARD_H,
                         text_color=T.TEXT_H1, anchor="w").grid(row=row, column=1, sticky="w")
            ctk.CTkLabel(frida_opts, text=desc, font=T.F_CARD_D,
                         text_color=T.TEXT_BODY, anchor="w").grid(
                row=row, column=2, padx=(8, 12), pady=7, sticky="w")

        ToolRow(frida_scroll, "📡", "Deploy frida-server",
                "Check device → download from GitHub → push to /data/local/tmp/",
                "Deploy ›", self.app.deploy_frida)
        ToolRow(frida_scroll, "▶", "Start frida-server",
                "Start frida-server process on the device (requires root)",
                "Start ›", self.app.start_frida)
        ToolRow(frida_scroll, "■", "Stop frida-server",
                "Kill the running frida-server process",
                "Stop ›", self.app.stop_frida)
        ToolRow(frida_scroll, "🔍", "Check frida-server",
                "Verify if frida-server exists and is running on device",
                "Check ›", self.app.check_frida)

        # ── Tab: Memory Dump ─────────────────────────────────────────
        ToolRow(t_mem, "🧠", "Memory DEX Dump",
                "Scan process memory for decrypted DEX magic bytes",
                "Dump ›", self.app.run_dynamic_dump)
        ToolRow(t_mem, "📥", "Pull Dump Files",
                "Pull sentinel_*.dex from /data/local/tmp/ to output directory",
                "Pull ›", self.app.run_dynamic_dump)
        ToolRow(t_mem, "🗑️", "Clean Remote Dumps",
                "Remove temporary dump files from /data/local/tmp/sentinel_dumps/",
                "Clean ›", self.app.clean_remote_dumps)

        # ── Tab: Malware Score ────────────────────────────────────────
        t_score.grid_columnconfigure(0, weight=1)

        sf = ctk.CTkFrame(t_score, fg_color="transparent")
        sf.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))
        sf.grid_columnconfigure(0, weight=1)

        self.dex_entry = ctk.CTkEntry(sf,
            placeholder_text="Select extracted .dex file…",
            fg_color="#111", border_color=T.BORDER,
            text_color=T.TEXT_H1, font=T.F_MONO, height=32, corner_radius=8)
        self.dex_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        _accent_btn(sf, "Browse", self._browse_dex, w=80, h=32).grid(row=0, column=1)

        _accent_btn(t_score, "🦠  Analyze DEX", self._score_selected,
                    w=150, h=34, fg_color="#7b00c8",
                    hover_color="#9500f0").grid(
            row=1, column=0, pady=8)

    def _discover_payloads(self):
        p = Path(__file__).parent.parent / "payloads"
        return sorted([f.name for f in p.glob("*.js")]) if p.is_dir() else []

    def _refresh_payloads(self):
        p = self._discover_payloads()
        # Update option menu values via configure
        pass  # OptionMenu widget auto refreshes on next access

    def _browse_dex(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            filetypes=[("DEX Files", "*.dex"), ("All", "*.*")])
        if path:
            self.dex_entry.delete(0, "end")
            self.dex_entry.insert(0, path)

    def _score_selected(self):
        path = self.dex_entry.get()
        if path and Path(path).is_file():
            self.app.run_malware_score(path)
        else:
            self.app._tlog("[WARNING] Select a valid DEX file.")


# ══════════════════════════════════════════════════════════════════════════════
# VIEW: TOOLBOX (ADB + Reports)
# ══════════════════════════════════════════════════════════════════════════════

class ToolboxView:
    def __init__(self, parent, app: "App"):
        import customtkinter as ctk
        self.app = app
        self.frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        self._build()

    def _build(self):
        import customtkinter as ctk
        p = self.frame

        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.pack(fill="x", padx=18, pady=(14, 6))
        _lbl(hdr, "Toolbox", T.F_PAGE, T.TEXT_H1, anchor="w").pack(side="left")

        tabs = ctk.CTkTabview(p, fg_color=T.CARD,
                              segmented_button_fg_color=T.SIDEBAR,
                              segmented_button_selected_color=T.ACCENT_DIM,
                              segmented_button_unselected_color=T.SIDEBAR,
                              corner_radius=10,
                              border_width=1, border_color=T.BORDER)
        tabs.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        t_adb     = tabs.add("ADB")
        t_reports = tabs.add("Reports")

        # Wrap both tabs in scrollable frames
        s_adb     = _scroll_tab(t_adb)
        s_reports = _scroll_tab(t_reports)

        # ── ADB ───────────────────────────────────────────────────────
        for icon, title, desc, btn, cmd in [
            ("📱", "Device Info",   "Model, ABI, SDK, root status, SELinux",    "Detect ›", self.app.get_device_info),
            ("🚀", "Launch App",    "Start the target app on the device",        "Launch ›", self.app.launch_app),
            ("⛔", "Force Stop",    "Kill the target app and clear state",        "Stop ›",   self.app.force_stop_app),
            ("📥", "Install APK",   "Push and install the selected APK",          "Install ›",self.app.install_apk),
            ("📋", "List Packages", "Show installed packages on device",          "List ›",   self.app.list_packages),
            ("📄", "Stream Logcat", "Live logcat filtered for Jiagu events",      "Stream ›", self.app.stream_logcat),
        ]:
            ToolRow(s_adb, icon, title, desc, btn, cmd)

        # ── Reports ───────────────────────────────────────────────────
        for icon, title, desc, btn, cmd in [
            ("📊", "JSON Report",     "Machine-readable forensic JSON report",     "Export ›", lambda: self.app.generate_report("json")),
            ("📝", "Markdown Report", "Human-readable Markdown report",             "Export ›", lambda: self.app.generate_report("markdown")),
            ("📁", "Output Folder",   "Open results folder in file explorer",       "Open ›",   self.app.open_output_folder),
        ]:
            ToolRow(s_reports, icon, title, desc, btn, cmd)


# ══════════════════════════════════════════════════════════════════════════════
# VIEW: SETTINGS
# ══════════════════════════════════════════════════════════════════════════════

class SettingsView:
    def __init__(self, parent, app: "App"):
        import customtkinter as ctk
        self.app = app
        self.frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        self._build()

    def _build(self):
        import customtkinter as ctk
        p = self.frame

        _lbl(p, "Settings", T.F_PAGE, T.TEXT_H1, anchor="w").pack(
            fill="x", padx=18, pady=(14, 10))

        tabs = ctk.CTkTabview(p, fg_color=T.CARD,
                              segmented_button_fg_color=T.SIDEBAR,
                              segmented_button_selected_color=T.ACCENT_DIM,
                              segmented_button_unselected_color=T.SIDEBAR,
                              corner_radius=10,
                              border_width=1, border_color=T.BORDER)
        tabs.pack(fill="both", expand=True, padx=18, pady=(0, 10))

        t_paths = tabs.add("Paths")
        t_about = tabs.add("About")

        # ── Paths ─────────────────────────────────────────────────────
        t_paths.grid_columnconfigure(1, weight=1)
        path_rows = [
            ("Output Dir",  "unpacked_output"),
            ("Reports Dir", "reports"),
            ("Frida Server", "/data/local/tmp/frida-server"),
        ]
        for row, (label, default) in enumerate(path_rows):
            _lbl(t_paths, label, color=T.TEXT_BODY).grid(
                row=row, column=0, padx=(12, 8), pady=8, sticky="w")
            e = ctk.CTkEntry(t_paths, fg_color="#111", border_color=T.BORDER,
                             text_color=T.TEXT_H1, font=T.F_MONO, height=30, corner_radius=7)
            e.insert(0, default)
            e.grid(row=row, column=1, padx=(0, 12), pady=8, sticky="ew")

        # ── About (scrollable) ────────────────────────────────────────
        about_scroll = ctk.CTkScrollableFrame(
            t_about, fg_color="transparent", corner_radius=0)
        about_scroll.pack(fill="both", expand=True)

        for text, font, color in [
            ("🛡️ JiaguSentinel Pro",        ("Segoe UI Emoji", 26), T.ACCENT),
            ("Version 2.0.0",               ("Segoe UI", 13, "bold"), T.TEXT_H1),
            ("Advanced APK Unpacker & Malware Forensics",
                                             T.F_LABEL, T.TEXT_BODY),
            ("MIT License — Authorized security research only.",
                                             T.F_CARD_D, T.TEXT_MUTED),
        ]:
            ctk.CTkLabel(about_scroll, text=text, font=font,
                         text_color=color, anchor="w").pack(
                anchor="w", padx=16, pady=4)

        # ── Author card ───────────────────────────────────────────────
        ctk.CTkFrame(about_scroll, height=1, fg_color=T.BORDER).pack(
            fill="x", padx=16, pady=(8, 12))

        # Centered profile: avatar → name → link (no card border)
        profile = ctk.CTkFrame(about_scroll, fg_color="transparent")
        profile.pack(anchor="center", pady=(4, 12))

        # Circle avatar placeholder (👤 emoji until image loads)
        self._avatar_lbl = ctk.CTkLabel(profile, text="👤",
                                         font=("Segoe UI Emoji", 36),
                                         width=60, height=60,
                                         corner_radius=30)
        self._avatar_lbl.pack()

        ctk.CTkLabel(profile, text="XIT07",
                     font=("Segoe UI", 12, "bold"),
                     text_color=T.TEXT_H1).pack(pady=(6, 1))

        def _open_profile(e=None):
            import webbrowser
            webbrowser.open("https://github.com/xit07")

        link = ctk.CTkLabel(profile, text="github.com/xit07",
                            font=("Segoe UI", 10),
                            text_color=T.ACCENT, cursor="hand2")
        link.pack()
        link.bind("<Button-1>", _open_profile)

        # Fetch GitHub avatar asynchronously, apply circular mask
        import threading as _threading
        def _load_avatar():
            try:
                import urllib.request
                from io import BytesIO
                from PIL import Image, ImageDraw
                import customtkinter as ctk_img

                SIZE = 60
                url = "https://avatars.githubusercontent.com/xit07?v=4"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    data = resp.read()

                img = Image.open(BytesIO(data)).convert("RGBA").resize(
                    (SIZE, SIZE), Image.LANCZOS)
                mask = Image.new("L", (SIZE, SIZE), 0)
                ImageDraw.Draw(mask).ellipse((0, 0, SIZE, SIZE), fill=255)
                circular = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
                circular.paste(img, mask=mask)

                ctkimg = ctk_img.CTkImage(
                    light_image=circular, dark_image=circular, size=(SIZE, SIZE))
                self._avatar_lbl.configure(image=ctkimg, text="")
                self._avatar_lbl._image = ctkimg  # prevent GC
            except Exception:
                pass  # keep emoji placeholder if fetch fails

        _threading.Thread(target=_load_avatar, daemon=True).start()




# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class App:
    """
    Root application — wires sidebar, views, and terminal together.

    Layout (grid at root):
      col 0: Sidebar (70px, full window height)
      col 1: Right pane (fills remaining) — inside it:
             status bar (24px, pack bottom)
             terminal   (130px, pack bottom)
             content    (fills remaining, pack top/fill)
    """

    MAX_LOG_LINES: int = 400

    def __init__(self, root):
        import customtkinter as ctk
        self._root = root
        root.title("JiaguSentinel Pro v2.0")
        root.geometry("850x600")
        root.minsize(720, 500)
        root.configure(fg_color=T.BG)

        # Root grid: sidebar (col0, fixed) + right pane (col1, expands)
        root.grid_columnconfigure(0, weight=0)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)

        # Status bar string vars
        self._sv_apk    = ctk.StringVar(value="No APK")
        self._sv_frida  = ctk.StringVar(value="Frida: —")
        self._sv_adb    = ctk.StringVar(value="ADB: —")
        self._sv_device = ctk.StringVar(value="—")

        # State
        self._apk_path      = ""
        self._output_dir    = "results_JiaguSentinel"
        self._extracted_dex: list = []
        self._threat_score  = 0.0
        self._static_result = None
        self._dynamic_result = None
        self._malware_reports: list = []

        # Right pane: holds status bar (bottom), terminal (bottom), content (fill)
        self._right = ctk.CTkFrame(root, fg_color=T.BG, corner_radius=0)
        self._right.grid(row=0, column=1, sticky="nsew")

        self._build_sidebar()          # grid col 0, full height
        self._build_status_bar()       # pack bottom inside _right
        self._build_terminal()         # pack bottom inside _right
        self._build_content()          # pack fill inside _right
        self._nav("home")

    # ── Status Bar (slim IDE-style, 24px) ─────────────────────────────────

    def _build_status_bar(self):
        """24px status strip at the very bottom of the right pane."""
        import customtkinter as ctk
        bar = ctk.CTkFrame(self._right, fg_color="#1a1a1a", height=24,
                           corner_radius=0, border_width=0)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)

        left = ctk.CTkFrame(bar, fg_color="transparent")
        left.pack(side="left", padx=(8, 0))

        # 📄 APK
        ctk.CTkLabel(left, text="📄", font=("Segoe UI", 9),
                     text_color=T.ACCENT).pack(side="left")
        ctk.CTkLabel(left, textvariable=self._sv_apk,
                     font=("Segoe UI", 9), text_color=T.TEXT_BODY
                     ).pack(side="left", padx=(2, 0))
        self._status_sep(left)

        # 🌐 ADB
        ctk.CTkLabel(left, text="🌐", font=("Segoe UI", 9),
                     text_color=T.ACCENT).pack(side="left")
        self._adb_dot = ctk.CTkLabel(left, text="●", font=("Segoe UI", 8),
                                      text_color=T.ERROR, width=10)
        self._adb_dot.pack(side="left", padx=(1, 0))
        ctk.CTkLabel(left, textvariable=self._sv_adb,
                     font=("Segoe UI", 9), text_color=T.TEXT_BODY
                     ).pack(side="left", padx=(2, 0))
        self._status_sep(left)

        # 💉 Frida
        ctk.CTkLabel(left, text="💉", font=("Segoe UI", 9),
                     text_color=T.ACCENT).pack(side="left")
        self._frida_dot = ctk.CTkLabel(left, text="●", font=("Segoe UI", 8),
                                        text_color=T.ERROR, width=10)
        self._frida_dot.pack(side="left", padx=(1, 0))
        ctk.CTkLabel(left, textvariable=self._sv_frida,
                     font=("Segoe UI", 9), text_color=T.TEXT_BODY
                     ).pack(side="left", padx=(2, 0))

        # Right — device
        right = ctk.CTkFrame(bar, fg_color="transparent")
        right.pack(side="right", padx=(0, 10))
        ctk.CTkLabel(right, text="📱", font=("Segoe UI", 9),
                     text_color=T.ACCENT).pack(side="left")
        ctk.CTkLabel(right, textvariable=self._sv_device,
                     font=("Segoe UI", 9), text_color=T.TEXT_BODY
                     ).pack(side="left", padx=(2, 0))

    @staticmethod
    def _status_sep(parent):
        """Thin pipe separator for the status bar."""
        import customtkinter as ctk
        ctk.CTkLabel(parent, text="│", font=("Segoe UI", 9),
                     text_color="#333333", width=14).pack(side="left")

    # ── Terminal (fixed 130px, above status bar) ──────────────────────────

    def _build_terminal(self):
        """Build the fixed-height terminal with header, clear button, and context menu."""
        import customtkinter as ctk

        tf = ctk.CTkFrame(self._right, fg_color="#0a0a0a", height=130,
                          corner_radius=0, border_width=1, border_color=T.BORDER)
        tf.pack(side="bottom", fill="x")
        tf.pack_propagate(False)
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(1, weight=1)

        # Header with Clear button
        hdr = ctk.CTkFrame(tf, fg_color="#101010", height=24, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        ctk.CTkLabel(hdr, text="● Terminal", font=("Segoe UI", 10, "bold"),
                     text_color=T.TERMINAL_FG).pack(side="left", padx=10, pady=2)
        ctk.CTkButton(hdr, text="Clear", width=42, height=18,
                      fg_color="transparent", hover_color=T.CARD_HOVER,
                      text_color=T.TEXT_MUTED, font=("Segoe UI", 9),
                      corner_radius=4, border_width=1, border_color=T.BORDER,
                      command=self._clear_term).pack(side="right", padx=6, pady=2)

        self._term = ctk.CTkTextbox(
            tf, fg_color=T.TERMINAL_BG, text_color=T.TERMINAL_FG,
            font=("Consolas", 12), corner_radius=0, border_width=0, wrap="none")
        self._term.grid(row=1, column=0, sticky="nsew")

        # Right-click context menu
        self._term_menu = ctk.CTkFrame(self._root, fg_color=T.CARD,
                                        corner_radius=0, border_width=0)
        self._term_menu_items: list = []
        self._build_term_ctx_menu()

        self._tlog("JiaguSentinel Pro v2.0 ready.")


    # ── Sidebar (70px, left) ──────────────────────────────────────────────

    def _build_sidebar(self):
        """70px sidebar using grid col 0 — spans the full window height."""
        import customtkinter as ctk

        sb = ctk.CTkFrame(self._root, width=70, fg_color=T.SIDEBAR,
                          corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.pack_propagate(False)

        ctk.CTkLabel(sb, text="🛡️",
                     font=("Segoe UI Emoji", 26)).pack(pady=(14, 2))
        ctk.CTkFrame(sb, height=1, fg_color=T.BORDER).pack(
            fill="x", padx=8, pady=6)

        nav = [
            ("🏠", "Home",       "home"),
            ("🛡️", "Protection", "protection"),
            ("⚡",  "Analysis",   "analysis"),
            ("🧰", "Toolbox",    "toolbox"),
        ]
        self._nav_btns: dict[str, NavBtn] = {}
        for icon, label, key in nav:
            btn = NavBtn(sb, icon, label, lambda k=key: self._nav(k))
            self._nav_btns[key] = btn

        ctk.CTkFrame(sb, height=1, fg_color=T.BORDER).pack(
            fill="x", padx=8, pady=6, side="bottom")
        s_btn = NavBtn(sb, "⚙️", "Settings", lambda: self._nav("settings"))
        s_btn.f.pack(side="bottom", fill="x", padx=6, pady=2)
        self._nav_btns["settings"] = s_btn

    # ── Content area (fills remaining space) ──────────────────────────────

    def _build_content(self):
        """Content area fills remaining space inside the right pane."""
        import customtkinter as ctk

        self._content = ctk.CTkFrame(self._right, fg_color=T.BG, corner_radius=0)
        self._content.pack(side="top", fill="both", expand=True)
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

        self._views: dict[str, object] = {
            "home":       HomeView(self._content, self),
            "protection": ProtectionView(self._content, self),
            "analysis":   AnalysisView(self._content, self),
            "toolbox":    ToolboxView(self._content, self),
            "settings":   SettingsView(self._content, self),
        }
        self._active = ""

    def _tlog(self, msg: str) -> None:
        """Thread-safe terminal append with auto-scroll and line-count limiting."""
        def _do():
            self._term.insert("end", f"» {msg}\n")
            self._term.see("end")
            # Trim to MAX_LOG_LINES to prevent memory / rendering slowdown
            lines = int(self._term.index("end-1c").split(".")[0])
            if lines > self.MAX_LOG_LINES:
                self._term.delete("1.0", f"{lines - self.MAX_LOG_LINES}.0")
            # Also mirror to Home > Session Log tab
            if hv := self._views.get("home"):
                try:
                    hv.append_mini(msg)
                except Exception:
                    pass
        try:
            self._root.after(0, _do)
        except Exception:
            pass

    def _clear_term(self):
        """Clear all text from the terminal."""
        self._term.delete("1.0", "end")

    def _build_term_ctx_menu(self):
        """Build a native right-click context menu for the terminal."""
        import tkinter as tk
        self._ctx_menu = tk.Menu(self._root, tearoff=0,
                                bg="#1e1e1e", fg="#d0d0d0",
                                activebackground=T.ACCENT,
                                activeforeground="#ffffff",
                                font=("Segoe UI", 9))
        self._ctx_menu.add_command(label="Select All",    command=self._term_select_all)
        self._ctx_menu.add_command(label="Copy Selected", command=self._term_copy_sel)
        self._ctx_menu.add_command(label="Copy All",      command=self._term_copy_all)

        # Bind right-click on the internal tkinter textbox widget
        inner = self._term._textbox
        inner.bind("<Button-3>", self._show_term_ctx)

    def _show_term_ctx(self, event):
        """Display the terminal context menu at cursor position."""
        try:
            self._ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx_menu.grab_release()

    def _term_select_all(self):
        """Select all text in the terminal."""
        self._term._textbox.tag_add("sel", "1.0", "end")

    def _term_copy_sel(self):
        """Copy selected text to clipboard."""
        try:
            sel = self._term._textbox.selection_get()
            self._root.clipboard_clear()
            self._root.clipboard_append(sel)
        except Exception:
            pass  # nothing selected

    def _term_copy_all(self):
        """Copy entire terminal content to clipboard."""
        text = self._term.get("1.0", "end").strip()
        self._root.clipboard_clear()
        self._root.clipboard_append(text)

    # ── Navigation ────────────────────────────────────────────────────────

    def _nav(self, key: str):
        if key == self._active:
            return
        if self._active in self._views:
            self._views[self._active].frame.grid_remove()
        if view := self._views.get(key):
            view.frame.grid(row=0, column=0, sticky="nsew")
        for k, b in self._nav_btns.items():
            b.set_active(k == key)
        self._active = key

    # ── File picking ──────────────────────────────────────────────────────

    def browse_apk(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            filetypes=[("APK Files", "*.apk"), ("All", "*.*")])
        if path:
            self._apk_path = path
            self._update_status(apk=Path(path).name)
            self._tlog(f"APK: {Path(path).name}")
            if h := self._views.get("home"):
                h.set_apk(path)
                self._root.after(0, h.refresh_stats)

    # ── Threaded workers ──────────────────────────────────────────────────

    def _thread(self, fn, *a):
        threading.Thread(target=fn, args=a, daemon=True).start()

    def run_quick_scan(self):
        if not self._apk_path:
            self.browse_apk()
        if self._apk_path:
            self._tlog("Quick Scan starting…")
            self._thread(self._static_worker)

    def run_static_scan(self):
        if not self._apk_path:
            self._tlog("[WARNING] Select an APK first (Home → Target APK).")
            return
        self._tlog(f"Static scan: {Path(self._apk_path).name}")
        self._thread(self._static_worker)

    def _static_worker(self):
        try:
            from core.static_engine import StaticEngine
            engine = StaticEngine(output_dir=self._output_dir,
                                  log_callback=self._tlog)
            r = engine.scan(self._apk_path)
            self._static_result = r
            self._extracted_dex = list(r.extracted_dex)
            if h := self._views.get("home"):
                self._root.after(0, h.refresh_stats)
        except Exception as e:
            self._tlog(f"[ERROR] Static: {e}")

    def run_dynamic_dump(self):
        av = self._views.get("analysis")
        pkg = av.pkg_entry.get().strip() if av else ""
        if not pkg:
            self._tlog("[WARNING] Enter package name in Analysis → Package tab.")
            return
        self._tlog(f"Dynamic dump: {pkg}")
        self._thread(self._dynamic_worker, av, pkg)

    def _dynamic_worker(self, av, pkg):
        try:
            from core.dynamic_engine import DynamicEngine
            engine = DynamicEngine(output_dir=self._output_dir,
                                   log_callback=self._tlog,
                                   anti_detection=av.anti_var.get() if av else True)
            payload = None
            if av:
                try:
                    payload = engine.load_payload(av.payload_var.get())
                except Exception:
                    pass
            r = engine.dump(pkg, custom_payload=payload,
                            spawn=av.spawn_var.get() if av else True)
            self._dynamic_result = r
            self._extracted_dex += [d.path for d in r.dumped_dex]
            if h := self._views.get("home"):
                self._root.after(0, h.refresh_stats)
        except Exception as e:
            self._tlog(f"[ERROR] Dynamic: {e}")

    def run_malware_score(self, path: str):
        self._tlog(f"Scoring: {Path(path).name}")
        self._thread(self._score_worker, path)

    def _score_worker(self, path):
        try:
            from analytics.malware_scorer import MalwareScorer
            r = MalwareScorer(log_callback=self._tlog).analyze(path)
            self._malware_reports.append(r)
            self._threat_score = max(self._threat_score, r.threat_score)
            if h := self._views.get("home"):
                self._root.after(0, h.refresh_stats)
        except Exception as e:
            self._tlog(f"[ERROR] Score: {e}")

    # (Status bar is now built in __init__ via _build_status_bar, above.)

    def _update_status(self, **kw):
        """Thread-safe status bar update. Accepts: apk, frida, adb, device."""
        def _do():
            if "apk" in kw:
                self._sv_apk.set(str(kw["apk"])[:38])
            if "frida" in kw:
                running = kw["frida"]
                self._sv_frida.set("Frida: Running" if running else "Frida: Stopped")
                self._frida_dot.configure(
                    text_color=T.SUCCESS if running else T.ERROR)
            if "adb" in kw:
                ok = kw["adb"]
                self._sv_adb.set("ADB: OK" if ok else "ADB: —")
                self._adb_dot.configure(
                    text_color=T.SUCCESS if ok else T.ERROR)
            if "device" in kw:
                self._sv_device.set(str(kw["device"])[:32])
        self._root.after(0, _do)

    # ── Button Loading Helper ─────────────────────────────────────────────

    def _run_with_loading(self, action_name, worker_fn):
        """Run worker_fn in a thread; log start/done to terminal."""
        self._tlog(f"{action_name}…")
        def _wrapped():
            try:
                worker_fn()
            finally:
                self._tlog(f"{action_name} — done.")
        self._thread(_wrapped)

    # ── Frida Management ──────────────────────────────────────────────────

    def _get_adb(self):
        from core.adb_manager import ADBManager
        adb = ADBManager(log_callback=self._tlog)
        info = adb.connect()
        self._update_status(adb=True, device=info.model)
        return adb

    def check_frida(self):
        self._run_with_loading("Check frida-server", self._check_frida_w)

    def _check_frida_w(self):
        try:
            adb = self._get_adb()
            exists = adb.check_frida_on_device()
            running = adb.is_frida_running()
            if running:
                self._tlog("✓ frida-server is RUNNING")
                self._update_status(frida=True)
            elif exists:
                self._tlog("✓ frida-server binary exists (not running)")
                self._update_status(frida=False)
            else:
                self._tlog(
                    "✗ frida-server NOT found on device.\n"
                    "  Click [Deploy] to auto-download, or download manually:\n"
                    "  https://github.com/frida/frida/releases")
                self._update_status(frida=False)
        except Exception as e:
            self._tlog(f"[ERROR] Check: {e}")
            self._update_status(adb=False)

    def deploy_frida(self):
        self._run_with_loading("Deploy frida-server", self._deploy_frida_w)

    def _deploy_frida_w(self):
        try:
            adb = self._get_adb()
            if adb.check_frida_on_device():
                self._tlog("✓ frida-server already on device")
            else:
                self._tlog("Downloading from GitHub…")
                if not adb.download_and_deploy_frida():
                    return
            self._update_status(frida=adb.is_frida_running())
        except Exception as e:
            self._tlog(f"[ERROR] Deploy: {e}")
            self._update_status(adb=False)

    def start_frida(self):
        self._run_with_loading("Start frida-server", self._start_frida_w)

    def _start_frida_w(self):
        try:
            adb = self._get_adb()
            ok = adb.start_frida_server()
            self._update_status(frida=ok)
        except Exception as e:
            self._tlog(f"[ERROR] Start: {e}")
            self._update_status(adb=False)

    def stop_frida(self):
        self._run_with_loading("Stop frida-server", self._stop_frida_w)

    def _stop_frida_w(self):
        try:
            adb = self._get_adb()
            adb.stop_frida_server()
            self._update_status(frida=False)
        except Exception as e:
            self._tlog(f"[ERROR] Stop: {e}")

    def clean_remote_dumps(self):
        self._tlog("Cleaning remote dumps…")
        self._thread(self._clean_worker)

    def _clean_worker(self):
        try:
            from core.adb_manager import ADBManager
            ADBManager(log_callback=self._tlog).shell(
                "rm -rf /data/local/tmp/sentinel_dumps/")
            self._tlog("Remote dumps removed.")
        except Exception as e:
            self._tlog(f"[ERROR] Clean: {e}")

    def get_device_info(self):
        self._thread(self._device_worker)

    def _device_worker(self):
        try:
            from core.adb_manager import ADBManager
            ADBManager(log_callback=self._tlog).connect()
        except Exception as e:
            self._tlog(f"[ERROR] Device: {e}")

    def launch_app(self):
        av = self._views.get("analysis")
        pkg = av.pkg_entry.get().strip() if av else ""
        if pkg:
            self._thread(lambda: __import__("core.adb_manager",
                fromlist=["ADBManager"]).ADBManager(
                    log_callback=self._tlog).launch_app(pkg))
        else:
            self._tlog("[WARNING] Set package name in Analysis → Package.")

    def force_stop_app(self):
        av = self._views.get("analysis")
        pkg = av.pkg_entry.get().strip() if av else ""
        if pkg:
            self._thread(lambda: __import__("core.adb_manager",
                fromlist=["ADBManager"]).ADBManager(
                    log_callback=self._tlog).force_stop(pkg))

    def install_apk(self):
        if not self._apk_path:
            self.browse_apk()
        if self._apk_path:
            self._thread(lambda: __import__("core.adb_manager",
                fromlist=["ADBManager"]).ADBManager(
                    log_callback=self._tlog).install_apk(self._apk_path))

    def list_packages(self):
        self._thread(self._list_worker)

    def _list_worker(self):
        try:
            from core.adb_manager import ADBManager
            pkgs = ADBManager(log_callback=self._tlog).list_packages()
            for p in pkgs:
                self._tlog(f"  {p}")
        except Exception as e:
            self._tlog(f"[ERROR] List: {e}")

    def stream_logcat(self):
        self._thread(self._logcat_worker)

    def _logcat_worker(self):
        try:
            from core.adb_manager import ADBManager
            ADBManager(log_callback=self._tlog).stream_logcat(
                self._tlog, filter_tag="jiagu", timeout=30)
        except Exception as e:
            self._tlog(f"[ERROR] Logcat: {e}")

    def generate_report(self, fmt: str):
        self._thread(self._report_worker, fmt)

    def _report_worker(self, fmt):
        try:
            from analytics.report_gen import ReportGenerator
            gen = ReportGenerator(log_callback=self._tlog)
            apk = self._apk_path or "unknown.apk"
            if fmt == "json":
                gen.generate_json(apk, self._static_result,
                                  self._dynamic_result, self._malware_reports)
            else:
                gen.generate_markdown(apk, self._static_result,
                                      self._dynamic_result, self._malware_reports)
        except Exception as e:
            self._tlog(f"[ERROR] Report: {e}")

    def open_output_folder(self):
        path = os.path.abspath(self._output_dir)
        os.makedirs(path, exist_ok=True)
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])


# ══════════════════════════════════════════════════════════════════════════════
# Entry-point
# ══════════════════════════════════════════════════════════════════════════════

def launch_gui() -> None:
    """Initialize and launch the compact JiaguSentinel Pro GUI."""
    try:
        import customtkinter as ctk
    except ImportError:
        print("[ERROR] customtkinter not installed — run: pip install customtkinter")
        return

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    App(root)
    root.mainloop()
