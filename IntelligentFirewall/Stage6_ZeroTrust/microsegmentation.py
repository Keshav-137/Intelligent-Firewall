# microsegmentation.py
# Stage 6 - Zero Trust: Network Microsegmentation
#
# HOW IT WORKS:
#   1. Divides your network into named ZONES (HR, DB, Finance, etc.)
#   2. Each zone has a list of IPs that belong to it
#   3. Defines RULES: which zone is allowed to talk to which zone
#   4. When a connection src_ip → dst_ip is detected, finds both zones
#   5. Checks if that zone-to-zone communication is in the allowed rules
#   6. If NOT in rules → BLOCK (default deny between zones)
#
# WHERE IT FITS:
#   Called SECOND in main_stage6.py after identity check passes.
#   Prevents lateral movement - even if attacker gets inside HR zone,
#   they cannot reach the DB zone because that rule doesn't exist.

# ──────────────────────────────────────────
# Zone definitions: zone name → list of IPs
# Edit these to match YOUR actual network IPs
# ──────────────────────────────────────────
ZONES = {
    "HR":        ["192.168.1.10", "192.168.1.11"],
    "DB":        ["192.168.1.20", "192.168.1.21"],
    "Finance":   ["192.168.1.30", "192.168.1.31"],
    "Developer": ["192.168.1.40", "192.168.1.41", "192.168.1.42"],
    "Internet":  [],   # external IPs (anything not in above zones)
}

# ──────────────────────────────────────────
# Allowed zone-to-zone communication rules
# Format: ("SOURCE_ZONE", "DEST_ZONE")
# If a pair is NOT here → it is BLOCKED
# ──────────────────────────────────────────
ALLOWED_ZONE_PAIRS = [
    ("Developer", "DB"),        # Devs can reach DB
    ("Developer", "Internet"),  # Devs can reach internet
    ("HR",        "Internet"),  # HR can reach internet
    ("Finance",   "DB"),        # Finance can reach DB
    ("Finance",   "Internet"),  # Finance can reach internet
    # HR → DB is NOT here, so HR cannot reach DB (lateral movement blocked)
    # Finance → HR is NOT here either
]


def get_zone(ip):
    """
    Find which zone an IP belongs to.
    Returns zone name, or 'Internet' if IP not in any defined zone.
    """
    for zone_name, zone_ips in ZONES.items():
        if ip in zone_ips:
            return zone_name
    return "Internet"


def check_microsegmentation(src_ip, dst_ip):
    """
    Main check function.
    Returns: (allowed: bool, reason: str)

    Example:
        allowed, reason = check_microsegmentation("192.168.1.10", "192.168.1.20")
        # HR → DB = BLOCKED
    """
    src_zone = get_zone(src_ip)
    dst_zone = get_zone(dst_ip)

    print(f"  [Microseg] {src_ip}({src_zone}) → {dst_ip}({dst_zone})")

    # Same zone always allowed (machine talking to its own zone)
    if src_zone == dst_zone:
        return True, f"Same zone ({src_zone}) - allowed"

    # Check if this zone pair is in the allowed rules
    if (src_zone, dst_zone) in ALLOWED_ZONE_PAIRS:
        return True, f"Zone rule exists: {src_zone} → {dst_zone}"

    return False, f"No rule for {src_zone} → {dst_zone} (lateral movement blocked)"


# ──────────────────────────────────────────
# Quick self-test
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=== Microsegmentation Self-Test ===\n")

    tests = [
        ("192.168.1.40", "192.168.1.20"),  # Developer → DB (allowed)
        ("192.168.1.10", "192.168.1.20"),  # HR → DB (blocked)
        ("192.168.1.30", "192.168.1.20"),  # Finance → DB (allowed)
        ("192.168.1.10", "192.168.1.30"),  # HR → Finance (blocked)
        ("192.168.1.40", "8.8.8.8"),       # Developer → Internet (allowed)
    ]

    for src, dst in tests:
        allowed, reason = check_microsegmentation(src, dst)
        status = "ALLOW" if allowed else "BLOCK"
        print(f"  [{status}] {src} → {dst} | {reason}")