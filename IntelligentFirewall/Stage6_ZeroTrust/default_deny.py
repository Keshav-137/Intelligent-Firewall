# default_deny.py
# Stage 6 - Zero Trust: Default Deny + Whitelist Enforcement
#
# HOW IT WORKS:
#   The most important Zero Trust rule:
#   "If it is not explicitly ALLOWED → it is BLOCKED"
#   No guessing. No exceptions. Whitelist only.
#
#   1. Maintains a whitelist of allowed domains and allowed ports
#   2. Any domain not on the list → BLOCKED
#   3. Any port not on the list → BLOCKED
#   4. Both must pass for traffic to continue
#
# WHERE IT FITS:
#   Called THIRD in main_stage6.py.
#   This is the safety net - even if identity and microseg pass,
#   this catches anything going to an unexpected destination.

# ──────────────────────────────────────────
# WHITELIST - only these are allowed
# Add domains your system legitimately needs
# ──────────────────────────────────────────
ALLOWED_DOMAINS = [
    "google.com",
    "github.com",
    "microsoft.com",
    "windowsupdate.com",
    "youtube.com",
    "stackoverflow.com",
    "pypi.org",
    "wikipedia.org",
    "outlook.com",
    "linkedin.com",
]

ALLOWED_PORTS = [
    80,    # HTTP
    443,   # HTTPS
    53,    # DNS
    8080,  # Dev HTTP
    8443,  # Dev HTTPS
]

# ──────────────────────────────────────────
# Always blocked ports (override everything)
# These are NEVER allowed regardless of role
# ──────────────────────────────────────────
ALWAYS_BLOCKED_PORTS = [
    21,    # FTP (insecure)
    23,    # Telnet (insecure, plaintext)
    3389,  # RDP (high attack surface)
    4444,  # Metasploit default
    5555,  # Android ADB / RATs
    6666,  # Common malware port
    31337, # Classic backdoor port
]


def check_default_deny(host, port):
    """
    Main check function.
    Returns: (allowed: bool, reason: str)

    Both domain AND port must pass.
    If either fails → block.
    """
    print(f"  [DefaultDeny] Checking {host}:{port}")

    # Always-blocked ports take absolute priority
    if port in ALWAYS_BLOCKED_PORTS:
        return False, f"Port {port} is permanently blocked (high-risk port)"

    # Port must be in allowed list
    if port not in ALLOWED_PORTS:
        return False, f"Port {port} not in whitelist"

    # Domain check - allow subdomains too
    # e.g. "mail.google.com" passes if "google.com" is whitelisted
    domain_allowed = False
    for allowed in ALLOWED_DOMAINS:
        if host == allowed or host.endswith("." + allowed):
            domain_allowed = True
            break

    if not domain_allowed:
        return False, f"Domain '{host}' not in whitelist"

    return True, f"Domain and port both whitelisted"


def add_to_whitelist(domain=None, port=None):
    """Dynamically add to whitelist at runtime if needed."""
    if domain:
        ALLOWED_DOMAINS.append(domain)
        print(f"  [DefaultDeny] Added domain to whitelist: {domain}")
    if port:
        ALLOWED_PORTS.append(port)
        print(f"  [DefaultDeny] Added port to whitelist: {port}")


# ──────────────────────────────────────────
# Quick self-test
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=== Default Deny Self-Test ===\n")

    tests = [
        ("google.com",       443),
        ("github.com",       80),
        ("malware-c2.ru",    443),
        ("google.com",       4444),  # good domain, bad port
        ("evilsite.com",     80),    # bad domain, good port
        ("mail.google.com",  443),   # subdomain test
        ("update.github.com", 443),  # subdomain test
        ("192.168.1.99",     23),    # internal + always-blocked port
    ]

    for host, port in tests:
        allowed, reason = check_default_deny(host, port)
        status = "ALLOW" if allowed else "BLOCK"
        print(f"  [{status}] {host}:{port} → {reason}")