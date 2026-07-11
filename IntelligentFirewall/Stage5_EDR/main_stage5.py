# main_stage5.py
# 🚀 Stage 5: EDR-Level LotL Detection (Stable + Continuous)

from sysmon_monitor import monitor_sysmon
from detection_rules import is_suspicious
from network_monitor import get_connections
from response_engine import respond

import psutil

# 🔥 Track already processed PIDs (avoid duplicate spam)
seen_pids = set()


def handle_event(proc):
    try:
        pid = proc["pid"]

        # 🛑 Skip duplicate events
        if pid in seen_pids:
            return

        seen_pids.add(pid)

        # 🧠 Prevent memory overflow
        if len(seen_pids) > 10000:
            seen_pids.clear()

        print("\n📡 EVENT DETECTED")
        print(f"Process: {proc['name']} | PID: {pid}")

        # 🔥 Build context for detection
        context = {
            "all_processes": list(psutil.process_iter(['pid', 'ppid', 'name']))
        }

        # 🔍 Detection
        if is_suspicious(proc, context):

            print("\n🚨 ATTACK DETECTED!")
            print(f"Process: {proc['name']}")
            print(f"PID: {pid}")
            print(f"Command: {proc['cmd']}")

            # 🌐 Network correlation
            connections = get_connections(pid)
            print(f"Connected IPs: {connections}")

            # ⚡ Response action
            respond(proc, connections)

        else:
            print("✅ Normal process")

    except Exception as e:
        print("⚠ ERROR in handle_event:", e)


if __name__ == "__main__":
    print("🚀 Stage 5: EDR-Level LotL Detection (Sysmon - Stable Mode)\n")

    try:
        monitor_sysmon(handle_event)

    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user")

    except Exception as e:
        print("❌ Fatal Error:", e)