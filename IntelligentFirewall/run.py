#!/usr/bin/env python3
# run.py  —  ONE COMMAND to launch the full Intelligent Firewall
#
# Usage:
#   python run.py          → Launch GUI (default)
#   python run.py --cli    → Launch console-only mode (no GUI)
#   python run.py --test   → Run Stage 6 self-tests only

import sys
import os

# ─── Add all stage folders to path ────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
for folder in ["Stage1_PacketCapture", "Stage2_RuleEngine",
               "Stage3_4_NGFW_ML", "Stage5_EDR", "Stage6_ZeroTrust",
               "Core", "GUI"]:
    p = os.path.join(ROOT, folder)
    if p not in sys.path:
        sys.path.insert(0, p)


def launch_gui():
    """Launch the PyQt6 GUI dashboard."""
    try:
        from firewall_gui import main
        print("[run.py] Launching Intelligent Firewall GUI...")
        main()
    except ImportError as e:
        print(f"[ERROR] PyQt6 not found: {e}")
        print("  Install with:  pip install PyQt6")
        sys.exit(1)


def launch_cli():
    """Launch console-only monitoring mode."""
    print("=" * 60)
    print("  INTELLIGENT FIREWALL — CLI MODE")
    print("  All 6 stages running. Press Ctrl+C to stop.")
    print("=" * 60)

    from event_bus import subscribe
    from orchestrator import start_all, stop_all
    import time

    def console_handler(event):
        action = event.get("action", "")
        stage  = event.get("stage", "")
        reason = event.get("reason", "")
        src    = event.get("src_ip", "")
        dst    = event.get("dst_ip", "")
        port   = event.get("port", "")

        # Print only essential info
        if action in ("BLOCK", "FLOOD", "ATTACK", "ERROR"):
            print(f"[{stage:8}] ❌ {action:6} | {src:15} → {dst:15}:{port:<5} | {reason}")
        elif action == "INFO":
            print(f"[SYSTEM  ] ℹ  {reason}")

    subscribe(console_handler)
    start_all()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_all()
        print("\n[run.py] Firewall stopped.")


def run_tests():
    """Run Stage 6 built-in test suite."""
    print("[run.py] Running Stage 6 Zero Trust tests...")
    from main_stage6 import run_tests as stage6_tests
    stage6_tests()


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--cli" in args:
        launch_cli()
    elif "--test" in args:
        run_tests()
    else:
        launch_gui()
