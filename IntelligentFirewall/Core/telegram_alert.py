# Core/telegram_alert.py
# 🔔 Telegram Bot Alert Integration
# Sends alerts for: BLOCK events, FLOOD attacks, ATTACK detections

import urllib.request
import urllib.parse
import json
import threading
import queue
import time
import os

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telegram_config.json")

DEFAULT_CONFIG = {
    "bot_token": "",       # Set your bot token here
    "chat_id": "",         # Set your chat ID here
    "enabled": False,
    "alert_on_block": True,
    "alert_on_flood": True,
    "alert_on_attack": True,
    "alert_on_edr": True,
    "min_severity": "HIGH"  # LOW / MEDIUM / HIGH
}

_alert_queue = queue.Queue()
_sender_thread = None
_running = False


# ─── Config ───────────────────────────────────────────────────────────────────
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                # Merge with defaults for any missing keys
                for k, v in DEFAULT_CONFIG.items():
                    cfg.setdefault(k, v)
                return cfg
        except Exception:
            pass
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


# ─── Send message via Telegram Bot API ────────────────────────────────────────
def _send_message(bot_token, chat_id, text):
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[Telegram] Send failed: {e}")
        return False


# ─── Background sender thread ─────────────────────────────────────────────────
def _sender_loop():
    global _running
    while _running:
        try:
            msg = _alert_queue.get(timeout=1)
            cfg = load_config()
            if cfg.get("enabled") and cfg.get("bot_token") and cfg.get("chat_id"):
                _send_message(cfg["bot_token"], cfg["chat_id"], msg)
        except queue.Empty:
            pass
        except Exception as e:
            print(f"[Telegram] Sender error: {e}")


def start():
    global _sender_thread, _running
    _running = True
    _sender_thread = threading.Thread(target=_sender_loop, daemon=True)
    _sender_thread.start()


def stop():
    global _running
    _running = False


# ─── Public alert functions ───────────────────────────────────────────────────
def _format_and_queue(title, body, emoji="🚨"):
    from datetime import datetime
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{emoji} <b>{title}</b>\n\n{body}\n\n<i>⏰ {ts}</i>"
    _alert_queue.put(msg)


def alert_block(src_ip, dst_ip, port, reason, stage=""):
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("alert_on_block"):
        return
    body = (
        f"🚫 <b>BLOCKED</b>\n"
        f"From: <code>{src_ip}</code>\n"
        f"To: <code>{dst_ip}:{port}</code>\n"
        f"Reason: {reason}\n"
        f"Stage: {stage}"
    )
    _format_and_queue("Intelligent Firewall — BLOCK EVENT", body, "🚫")


def alert_flood(src_ip, pkt_count, stage="Stage2"):
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("alert_on_flood"):
        return
    body = (
        f"🌊 <b>FLOOD ATTACK DETECTED</b>\n"
        f"Source IP: <code>{src_ip}</code>\n"
        f"Packet rate: {pkt_count} pkt/s\n"
        f"Stage: {stage}\n"
        f"Action: <b>BLOCKED</b>"
    )
    _format_and_queue("Intelligent Firewall — FLOOD ATTACK", body, "🌊")


def alert_attack(proc_name, pid, cmd, ips, stage="Stage5"):
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("alert_on_edr"):
        return
    ips_str = ", ".join(ips) if ips else "None"
    body = (
        f"⚡ <b>ATTACK PROCESS DETECTED & KILLED</b>\n"
        f"Process: <code>{proc_name}</code> (PID: {pid})\n"
        f"Command: <code>{cmd[:80]}</code>\n"
        f"Connected IPs: <code>{ips_str}</code>\n"
        f"Stage: {stage}\n"
        f"Action: <b>KILLED + IPs BLOCKED</b>"
    )
    _format_and_queue("Intelligent Firewall — EDR ATTACK", body, "⚡")


def alert_zero_trust(host, port, blocked_at, reason):
    cfg = load_config()
    if not cfg.get("enabled") or not cfg.get("alert_on_attack"):
        return
    body = (
        f"🛡 <b>ZERO TRUST BLOCK</b>\n"
        f"Host: <code>{host}:{port}</code>\n"
        f"Blocked at: {blocked_at}\n"
        f"Reason: {reason}\n"
        f"Stage: Stage6"
    )
    _format_and_queue("Intelligent Firewall — ZERO TRUST", body, "🛡")


def send_test_message():
    """Send a test message to verify configuration."""
    cfg = load_config()
    if not cfg.get("bot_token") or not cfg.get("chat_id"):
        return False, "Bot token or Chat ID not configured"
    ok = _send_message(cfg["bot_token"], cfg["chat_id"],
                       "✅ <b>Intelligent Firewall</b>\nTelegram alerts configured successfully!\n\nYour firewall is now connected.")
    return ok, "Test message sent!" if ok else "Failed to send"
