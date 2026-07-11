# Core/event_bus.py
# 🔥 Central Event Bus — All stages emit events here
# GUI subscribes to get live updates

import threading
import queue
import json
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

_subscribers = []
_lock = threading.Lock()
_log_enabled = True
_log_file = None


def _get_log_path():
    date_str = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"firewall_{date_str}.log")


def subscribe(callback):
    """Register a GUI callback to receive events."""
    with _lock:
        _subscribers.append(callback)


def unsubscribe(callback):
    with _lock:
        if callback in _subscribers:
            _subscribers.remove(callback)


def emit(event: dict):
    """
    Emit an event to all subscribers and write to log.
    event keys: timestamp, stage, action, src_ip, dst_ip, port, protocol, reason, detail
    """
    if "timestamp" not in event:
        event["timestamp"] = datetime.now().strftime("%H:%M:%S")

    # Write log
    if _log_enabled:
        try:
            with open(_get_log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    # Notify all GUI subscribers (non-blocking)
    with _lock:
        subs = list(_subscribers)
    for cb in subs:
        try:
            cb(event)
        except Exception:
            pass


def set_logging(enabled: bool):
    global _log_enabled
    _log_enabled = enabled


def get_recent_logs(n=200):
    """Read last n lines from today's log."""
    path = _get_log_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        events = []
        for line in lines[-n:]:
            try:
                events.append(json.loads(line.strip()))
            except Exception:
                pass
        return events
    except Exception:
        return []


def get_all_log_files():
    """Return list of log file paths."""
    try:
        return sorted([
            os.path.join(LOG_DIR, f)
            for f in os.listdir(LOG_DIR)
            if f.endswith(".log")
        ], reverse=True)
    except Exception:
        return []
