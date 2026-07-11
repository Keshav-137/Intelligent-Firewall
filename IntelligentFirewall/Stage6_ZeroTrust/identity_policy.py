# identity_policy.py
# Stage 6 - Zero Trust: Identity-Based Access Control
#
# HOW IT WORKS:
#   1. Gets the current logged-in Windows username (os.getlogin())
#   2. Maps that username to a ROLE (Admin / Developer / Student / HR)
#   3. Loads policies.json to get what that role is allowed to access
#   4. Checks: is this domain allowed? is this port blocked?
#   5. Returns True (allow) or False (block)
#
# WHERE IT FITS:
#   Called FIRST in main_stage6.py before any traffic reaches the network.
#   If this returns False → block immediately, don't even check other layers.

import os
import json

# ──────────────────────────────────────────
# Load policies from JSON file
# ──────────────────────────────────────────
_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_dir, "policies.json")) as f:
    POLICIES = json.load(f)

# ──────────────────────────────────────────
# Role mapping: username → role
# Add your actual Windows usernames here
# ──────────────────────────────────────────
USER_ROLE_MAP = {
    "admin":       "Admin",
    "administrator": "Admin",
    "keshav":      "Developer",   # ← add this line
    "developer":   "Developer",
    "dev":         "Developer",
    "student":     "Student",
    "hr":          "HR",
    "hruser":      "HR",
}


def get_current_user():
    """Get the current logged-in Windows username (lowercase)."""
    try:
        return os.getlogin().lower()
    except Exception:
        return "unknown"


def get_role(username):
    """
    Map a username to a role.
    If username not in map → default to 'Student' (least privilege).
    """
    return USER_ROLE_MAP.get(username, "Student")


def check_identity_policy(host, port):
    """
    Main check function.
    Returns: (allowed: bool, reason: str)

    Example:
        allowed, reason = check_identity_policy("github.com", 443)
        if not allowed:
            print(f"BLOCKED: {reason}")
    """
    username = get_current_user()
    role     = get_role(username)
    policy   = POLICIES.get(role, POLICIES["Student"])

    print(f"  [Identity] User={username} | Role={role}")

    # Check blocked ports first
    if port in policy["blocked_ports"]:
        return False, f"Port {port} is blocked for role '{role}'"

    # Check allowed domains
    allowed_domains = policy["allowed_domains"]

    # Wildcard = allow everything (Admin only)
    if "*" in allowed_domains:
        return True, f"Admin role - all domains allowed"

    # Check if host matches any allowed domain
    for domain in allowed_domains:
        if host == domain or host.endswith("." + domain):
            return True, f"Domain '{host}' allowed for role '{role}'"

    return False, f"Domain '{host}' NOT in allowed list for role '{role}'"


# ──────────────────────────────────────────
# Quick self-test (run this file directly)
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=== Identity Policy Self-Test ===\n")

    tests = [
        ("github.com",      443),
        ("youtube.com",     443),
        ("malware-c2.ru",   443),
        ("google.com",      80),
        ("192.168.1.99",    21),
    ]

    for host, port in tests:
        allowed, reason = check_identity_policy(host, port)
        status = "ALLOW" if allowed else "BLOCK"
        print(f"  [{status}] {host}:{port} → {reason}")