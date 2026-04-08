"""
JiaguSentinel Pro v2.0 — Intelligent Router
=============================================
Entry point that routes between CLI and GUI modes based on flags,
configures global logging, and validates the environment.

Usage:
    python main.py              # Launch GUI (default)
    python main.py --gui        # Force GUI mode
    python main.py --cli        # Launch CLI interactive menu
    python main.py --cli scan <apk>   # Direct CLI command
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────
PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Create Folder logs in root project ─────────────────────────────
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)


def setup_logging(log_file: str = "sentinel.log", level: str = "DEBUG") -> None:
    """
    Configure global logging to file and console.

    All modules use hierarchical loggers under 'sentinel.*'
    which feed into this root configuration.
    """
    log_path = LOGS_DIR / log_file

    # File handler — DEBUG level, full detail
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(name)-20s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    # Console handler — INFO level, compact
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        "%(levelname)-7s | %(message)s"
    ))

    # Root sentinel logger
    root_logger = logging.getLogger("sentinel")
    root_logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logging.getLogger("sentinel").info(
        f"JiaguSentinel Pro v2.0 initialized — log: {log_path}"
    )


def validate_environment() -> list[str]:
    """
    Check for required and optional dependencies.

    Returns a list of warning messages for missing optional deps.
    """
    warnings: list[str] = []

    # Required
    required = {
        "click": "CLI interface",
        "rich": "CLI terminal UI",
    }
    for pkg, purpose in required.items():
        try:
            __import__(pkg)
        except ImportError:
            print(f"[FATAL] Missing required package '{pkg}' ({purpose}).")
            print(f"        Run: pip install -r requirements.txt")
            sys.exit(1)

    # Optional
    optional = {
        "frida": "Dynamic engine (Frida runtime injection)",
        "lief": "ELF binary analysis (static engine)",
        "yara": "YARA rule matching (static engine)",
        "customtkinter": "GUI interface",
        "androguard": "Advanced APK metadata extraction",
    }
    for pkg, purpose in optional.items():
        try:
            __import__(pkg)
        except ImportError:
            warnings.append(f"Optional: '{pkg}' not installed ({purpose})")

    return warnings


def detect_display() -> bool:
    """Check if a graphical display is available."""
    if sys.platform == "win32":
        return True  # Windows always has a display
    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    return bool(display)


def main() -> None:
    """
    Intelligent router: parses --cli / --gui flags and launches
    the appropriate interface.

    Precedence:
    1. --cli flag → CLI mode
    2. --gui flag → GUI mode
    3. No flag + display available → GUI mode
    4. No flag + no display → CLI mode
    """
    setup_logging()
    logger = logging.getLogger("sentinel.main")

    # Environment check
    env_warnings = validate_environment()
    for w in env_warnings:
        logger.warning(w)

    # Parse mode from argv (before Click takes over)
    args = sys.argv[1:]

    if "--cli" in args:
        # Remove --cli flag and pass remaining args to Click
        args = [a for a in args if a != "--cli"]
        sys.argv = [sys.argv[0]] + args
        logger.info("Mode: CLI")
        from ui.cli_main import cli
        cli(obj={})

    elif "--gui" in args or not args:
        # GUI mode (default when no args)
        if not detect_display():
            logger.warning("No display detected — falling back to CLI")
            from ui.cli_main import cli
            cli(obj={})
            return

        try:
            logger.info("Mode: GUI")
            from ui.gui_main import launch_gui
            launch_gui()
        except ImportError as e:
            logger.error(f"GUI launch failed: {e}")
            logger.info("Falling back to CLI mode...")
            from ui.cli_main import cli
            cli(obj={})

    else:
        # If args were passed without --cli, assume CLI mode
        sys.argv = [sys.argv[0]] + args
        logger.info("Mode: CLI (auto-detected from arguments)")
        from ui.cli_main import cli
        cli(obj={})


if __name__ == "__main__":
    main()
