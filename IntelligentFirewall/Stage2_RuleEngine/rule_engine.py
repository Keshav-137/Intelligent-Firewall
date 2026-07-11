# Stage2_RuleEngine/rule_engine.py
# 🔥 Stage 2: Rule-Based Firewall Engine
# Stateless packet filtering with user-configurable rules

import json
import os
from datetime import datetime

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_rules.json")

DEFAULT_RULES = {
    "blocked_ips": ["1.2.3.4", "5.6.7.8"],
    "blocked_ports": [4444, 5555, 6666, 31337, 23, 21],
    "allowed_protocols": ["TCP", "UDP", "ICMP"],
    "flood_threshold": 100,   # packets/sec per src IP triggers flood alert
    "rules": [
        {"name": "Block Metasploit", "type": "port", "value": 4444, "action": "BLOCK"},
        {"name": "Block Telnet",     "type": "port", "value": 23,   "action": "BLOCK"},
        {"name": "Block FTP",        "type": "port", "value": 21,   "action": "BLOCK"},
    ]
}

# ─── Load / Save ───────────────────────────────────────────────────────────────
def load_rules():
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    save_rules(DEFAULT_RULES)
    return DEFAULT_RULES.copy()


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


# ─── Per-IP flood tracking ─────────────────────────────────────────────────────
_ip_packet_count = {}   # {ip: [timestamps]}


def _check_flood(src_ip, threshold):
    now = time.time() if True else 0
    import time as _t
    now = _t.time()
    bucket = _ip_packet_count.setdefault(src_ip, [])
    # Keep only last 1 second
    bucket = [t for t in bucket if now - t < 1.0]
    bucket.append(now)
    _ip_packet_count[src_ip] = bucket
    return len(bucket) >= threshold


# ─── Main check ───────────────────────────────────────────────────────────────
def check_packet(event):
    """
    event: {src_ip, dst_ip, protocol, port, size, ...}
    Returns: (action: str, reason: str)
    action: "ALLOW" | "BLOCK" | "FLOOD"
    """
    rules = load_rules()
    src = event.get("src_ip", "")
    port = int(event.get("port", 0))
    protocol = event.get("protocol", "")

    # Flood detection
    threshold = rules.get("flood_threshold", 100)
    if _check_flood(src, threshold):
        return "FLOOD", f"Flood attack from {src} (>{threshold} pkt/s)"

    # Blocked IPs
    if src in rules.get("blocked_ips", []):
        return "BLOCK", f"IP {src} is in blocklist"

    # Blocked ports
    if port in rules.get("blocked_ports", []):
        return "BLOCK", f"Port {port} is blocked"

    # Custom rules
    for rule in rules.get("rules", []):
        if rule["type"] == "port" and rule["value"] == port:
            return rule["action"], f"Rule: {rule['name']}"
        if rule["type"] == "ip" and rule["value"] == src:
            return rule["action"], f"Rule: {rule['name']}"

    return "ALLOW", "No rule matched"
