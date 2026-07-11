# main_stage6.py
# Stage 6: Zero Trust Prevention Layer
#
# ══════════════════════════════════════════════════════════
# FULL SYSTEM FLOW:
#
#   Traffic arrives
#       │
#       ▼
#   [1] Identity Policy    ← Who are you? Role check
#       │ FAIL → BLOCK
#       ▼
#   [2] Microsegmentation  ← Can your zone reach that zone?
#       │ FAIL → BLOCK
#       ▼
#   [3] Default Deny       ← Is this domain/port whitelisted?
#       │ FAIL → BLOCK
#       ▼
#   [4] Sandbox            ← Is this file suspicious?
#       │ FAIL → BLOCK
#       ▼
#   [5] Stage 5 EDR        ← Behavioral detection (LotL, ML)
#       │ THREAT → KILL PROCESS + BLOCK IP
#       ▼
#       ALLOWED ✓
#
# Stage 6 = PREVENTION (block before it runs)
# Stage 5 = DETECTION  (catch what slips through)
# ══════════════════════════════════════════════════════════

import socket
import psutil
import time
from datetime import datetime

from identity_policy   import check_identity_policy
from microsegmentation import check_microsegmentation
from default_deny      import check_default_deny
from sandbox           import check_sandbox

# Import Stage 5 detection (optional - comment out if running Stage 6 standalone)
try:
    from detection_rules import is_suspicious
    from response_engine import respond
    STAGE5_AVAILABLE = True
    print("✓ Stage 5 EDR loaded")
except ImportError:
    STAGE5_AVAILABLE = False
    print("⚠ Stage 5 not found - running Stage 6 prevention only")


# ──────────────────────────────────────────
# Logging helper
# ──────────────────────────────────────────
def log_event(action, host, port, reason, extra=""):
    ts = datetime.now().strftime("%H:%M:%S")
    marker = "🚫 BLOCKED" if action == "BLOCK" else "✅ ALLOWED"
    print(f"\n[{ts}] {marker} | {host}:{port}")
    print(f"         Reason: {reason}")
    if extra:
        print(f"         {extra}")


# ──────────────────────────────────────────
# Core Zero Trust gate
# Every connection request passes through here
# ──────────────────────────────────────────
def zero_trust_check(host, port, src_ip=None, dst_ip=None, url=None):
    """
    Run all Zero Trust checks in order.
    Returns: (allowed: bool, blocked_at: str)

    Call this for every connection/request your system detects.
    """
    print(f"\n{'─'*50}")
    print(f"→ Checking: {host}:{port}")

    # ── Layer 1: Identity ──────────────────
    allowed, reason = check_identity_policy(host, port)
    if not allowed:
        log_event("BLOCK", host, port, reason, "Layer: Identity Policy")
        return False, "identity"

    # ── Layer 2: Microsegmentation ─────────
    if src_ip and dst_ip:
        allowed, reason = check_microsegmentation(src_ip, dst_ip)
        if not allowed:
            log_event("BLOCK", host, port, reason, "Layer: Microsegmentation")
            return False, "microsegmentation"

    # ── Layer 3: Default Deny ──────────────
    allowed, reason = check_default_deny(host, port)
    if not allowed:
        log_event("BLOCK", host, port, reason, "Layer: Default Deny")
        return False, "default_deny"

    # ── Layer 4: Sandbox ───────────────────
    if url:
        allowed, result = check_sandbox(url)
        if not allowed:
            log_event("BLOCK", host, port,
                      f"Sandbox verdict: {result['verdict']} (score={result['score']})",
                      f"Layer: Sandbox | {result['reasons'][0]}")
            return False, "sandbox"

    log_event("ALLOW", host, port, "All Zero Trust layers passed")
    return True, "none"


# ──────────────────────────────────────────
# Live network monitor
# Watches active connections and checks each one
# ──────────────────────────────────────────
def monitor_connections():
    """
    Watches live network connections using psutil.
    For each new connection → run zero_trust_check().
    If blocked and Stage 5 available → trigger EDR response.
    """
    print("\n🚀 Stage 6: Zero Trust Monitor Started")
    print("   Watching live network connections...\n")

    seen = set()

    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr:
                    continue

                dst_ip   = conn.raddr.ip
                dst_port = conn.raddr.port
                src_ip   = conn.laddr.ip if conn.laddr else "unknown"
                key      = (src_ip, dst_ip, dst_port, conn.pid)

                if key in seen:
                    continue
                seen.add(key)

                # Try to resolve IP to hostname
                try:
                    host = socket.gethostbyaddr(dst_ip)[0]
                except Exception:
                    host = dst_ip

                # Run Zero Trust check
                allowed, blocked_at = zero_trust_check(
                    host    = host,
                    port    = dst_port,
                    src_ip  = src_ip,
                    dst_ip  = dst_ip,
                )

                # If blocked AND Stage 5 available → EDR response
                if not allowed and STAGE5_AVAILABLE and conn.pid:
                    try:
                        proc_info = psutil.Process(conn.pid)
                        proc = {
                            "pid":  conn.pid,
                            "ppid": proc_info.ppid(),
                            "name": proc_info.name(),
                            "cmd":  " ".join(proc_info.cmdline()),
                        }
                        print(f"\n  ⚡ Triggering Stage 5 EDR for PID {conn.pid}")
                        respond(proc, [dst_ip])
                    except Exception as e:
                        print(f"  ⚠ EDR response error: {e}")

            # Keep seen set from growing forever
            if len(seen) > 5000:
                seen.clear()

            time.sleep(1)

        except KeyboardInterrupt:
            print("\n🛑 Stage 6 monitor stopped")
            break
        except Exception as e:
            print(f"⚠ Monitor error: {e}")
            time.sleep(1)


# ──────────────────────────────────────────
# Standalone test mode
# Run: python main_stage6.py
# ──────────────────────────────────────────
def run_tests():
    print("=" * 55)
    print("  STAGE 6 ZERO TRUST - TEST MODE")
    print("=" * 55)

    test_cases = [
        # (host,              port, src_ip,         dst_ip,         url,                                    expected)
        ("google.com",        443,  "192.168.1.40", "8.8.8.8",      None,                                   "ALLOW"),
        ("malware-c2.ru",     443,  "192.168.1.10", "1.2.3.4",      None,                                   "BLOCK"),
        ("github.com",        80,   "192.168.1.40", "140.82.121.4", None,                                   "ALLOW"),
        ("192.168.1.20",      3306, "192.168.1.10", "192.168.1.20", None,                                   "BLOCK"),  # HR→DB
        ("github.com",        443,  "192.168.1.40", "140.82.121.4", "https://github.com/r/tool.exe",        "BLOCK"),  # sandbox
        ("google.com",        23,   "192.168.1.40", "8.8.8.8",      None,                                   "BLOCK"),  # bad port
        ("stackoverflow.com", 443,  "192.168.1.40", "1.2.3.4",      None,                                   "ALLOW"),
        ("evil.com",          80,   "192.168.1.40", "9.9.9.9",      None,                                   "BLOCK"),  # not whitelisted
    ]

    results = {"PASS": 0, "FAIL": 0}

    for host, port, src_ip, dst_ip, url, expected in test_cases:
        allowed, blocked_at = zero_trust_check(host, port, src_ip, dst_ip, url)
        actual = "ALLOW" if allowed else "BLOCK"
        passed = actual == expected
        results["PASS" if passed else "FAIL"] += 1
        mark = "✓" if passed else "✗"
        print(f"  {mark} Expected={expected} Got={actual} | {host}:{port}")

    print(f"\n  Results: {results['PASS']} passed, {results['FAIL']} failed")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        # Live monitoring mode: python main_stage6.py monitor
        monitor_connections()
    else:
        # Test mode (default): python main_stage6.py
        run_tests()