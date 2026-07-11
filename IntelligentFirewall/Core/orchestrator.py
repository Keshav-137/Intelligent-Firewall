# Core/orchestrator.py
# 🚀 Master Orchestrator — Launches all 6 stages in one command
# Each stage runs in its own thread; all events flow through event_bus

import sys
import os
import threading
import time

# ─── Path setup so all stage imports work ─────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for folder in ["Stage1_PacketCapture", "Stage2_RuleEngine",
               "Stage3_4_NGFW_ML", "Stage5_EDR", "Stage6_ZeroTrust", "Core"]:
    p = os.path.join(ROOT, folder)
    if p not in sys.path:
        sys.path.insert(0, p)

from event_bus import emit, subscribe
from telegram_alert import start as tg_start, stop as tg_stop

# ─── Stage threads ────────────────────────────────────────────────────────────
_threads = {}
_stage_status = {
    "Stage1": False,
    "Stage2": False,
    "Stage3_4": False,
    "Stage5": False,
    "Stage6": False,
}
_stop_events = {k: threading.Event() for k in _stage_status}


# ════════════════════════════════════════════════════════════════════
# STAGE 1 — Packet Capture
# ════════════════════════════════════════════════════════════════════
def _run_stage1():
    try:
        from packet_capture import start_capture
        from rule_engine import check_packet
        from telegram_alert import alert_block, alert_flood

        def on_packet(event):
            action, reason = check_packet(event)
            event["action"] = action
            event["reason"] = reason
            event["stage"] = "Stage1/2"
            emit(event)
            if action == "BLOCK":
                alert_block(
                    event.get("src_ip", "?"),
                    event.get("dst_ip", "?"),
                    event.get("port", 0),
                    reason, "Stage2"
                )
            elif action == "FLOOD":
                alert_flood(event.get("src_ip", "?"), 0, "Stage2")

        start_capture(on_packet)
        _stage_status["Stage1"] = True
        emit({"stage": "SYSTEM", "action": "INFO", "reason": "Stage 1+2: Packet capture + Rule engine STARTED"})

        while not _stop_events["Stage1"].is_set():
            time.sleep(1)

    except ImportError as e:
        emit({"stage": "Stage1", "action": "ERROR",
              "reason": f"Stage1 import error (scapy not installed?): {e}"})
    except Exception as e:
        emit({"stage": "Stage1", "action": "ERROR", "reason": str(e)})
    finally:
        _stage_status["Stage1"] = False


# ════════════════════════════════════════════════════════════════════
# STAGE 5 — EDR (Sysmon)
# ════════════════════════════════════════════════════════════════════
def _run_stage5():
    try:
        from sysmon_monitor import monitor_sysmon
        from detection_rules import is_suspicious
        from network_monitor import get_connections
        from response_engine import respond
        from telegram_alert import alert_attack
        import psutil

        seen_pids = set()

        def handle_event(proc):
            try:
                pid = proc["pid"]
                if pid in seen_pids:
                    return
                seen_pids.add(pid)
                if len(seen_pids) > 10000:
                    seen_pids.clear()

                context = {"all_processes": list(psutil.process_iter(['pid', 'ppid', 'name']))}

                if is_suspicious(proc, context):
                    connections = get_connections(pid)
                    respond(proc, connections)
                    alert_attack(proc["name"], pid, proc["cmd"], connections, "Stage5")
                    emit({
                        "stage": "Stage5",
                        "action": "ATTACK",
                        "src_ip": "localhost",
                        "dst_ip": ", ".join(connections) or "N/A",
                        "port": 0,
                        "protocol": "PROCESS",
                        "reason": f"LOL/EDR: {proc['name']} (PID {pid})",
                        "detail": proc["cmd"][:100]
                    })
                else:
                    emit({
                        "stage": "Stage5",
                        "action": "ALLOW",
                        "src_ip": "localhost",
                        "dst_ip": "N/A",
                        "port": 0,
                        "protocol": "PROCESS",
                        "reason": f"Normal: {proc['name']}"
                    })
            except Exception as e:
                pass

        _stage_status["Stage5"] = True
        emit({"stage": "SYSTEM", "action": "INFO", "reason": "Stage 5: EDR Sysmon monitor STARTED"})
        monitor_sysmon(handle_event)

    except ImportError as e:
        emit({"stage": "Stage5", "action": "ERROR",
              "reason": f"Stage5 import error (win32evtlog / Sysmon not installed?): {e}"})
    except Exception as e:
        emit({"stage": "Stage5", "action": "ERROR", "reason": str(e)})
    finally:
        _stage_status["Stage5"] = False


# ════════════════════════════════════════════════════════════════════
# STAGE 6 — Zero Trust
# ════════════════════════════════════════════════════════════════════
def _run_stage6():
    try:
        from main_stage6 import monitor_connections
        _stage_status["Stage6"] = True
        emit({"stage": "SYSTEM", "action": "INFO", "reason": "Stage 6: Zero Trust monitor STARTED"})
        monitor_connections()
    except ImportError as e:
        emit({"stage": "Stage6", "action": "ERROR",
              "reason": f"Stage6 import error: {e}"})
    except Exception as e:
        emit({"stage": "Stage6", "action": "ERROR", "reason": str(e)})
    finally:
        _stage_status["Stage6"] = False


# ════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════
def start_all():
    tg_start()
    emit({"stage": "SYSTEM", "action": "INFO", "reason": "🚀 Intelligent Firewall starting all stages..."})

    stages = {
        "Stage1": _run_stage1,
        "Stage5": _run_stage5,
        "Stage6": _run_stage6,
    }

    for name, fn in stages.items():
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        _threads[name] = t

    emit({"stage": "SYSTEM", "action": "INFO", "reason": "All stage threads launched"})


def stop_all():
    for ev in _stop_events.values():
        ev.set()
    tg_stop()
    emit({"stage": "SYSTEM", "action": "INFO", "reason": "🛑 All stages stopped"})


def get_status():
    return dict(_stage_status)


def start_stage(name):
    fns = {"Stage1": _run_stage1, "Stage5": _run_stage5, "Stage6": _run_stage6}
    if name in fns:
        _stop_events[name].clear()
        t = threading.Thread(target=fns[name], name=name, daemon=True)
        t.start()
        _threads[name] = t


def stop_stage(name):
    _stop_events.get(name, threading.Event()).set()
    _stage_status[name] = False


# ─── Console entry point ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import signal

    def _console_handler(event):
        action = event.get("action", "")
        stage  = event.get("stage", "")
        reason = event.get("reason", "")
        src    = event.get("src_ip", "")
        dst    = event.get("dst_ip", "")

        # Only print essential info
        if action in ("BLOCK", "FLOOD", "ATTACK", "ERROR"):
            print(f"[{stage}] ❌ {action} | {src} → {dst} | {reason}")
        elif action == "INFO":
            print(f"[SYSTEM] ℹ {reason}")

    subscribe(_console_handler)
    start_all()
    print("\n✅ Intelligent Firewall running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_all()
        print("\n🛑 Firewall stopped.")
