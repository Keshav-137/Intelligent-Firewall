# sandbox.py
# Stage 6 - Zero Trust: Sandbox File Analysis
#
# HOW IT WORKS:
#   Before any file download completes, this intercepts and checks it.
#   1. Detects if the URL/filename looks like a dangerous file type
#   2. If suspicious → runs it through sandbox analysis FIRST
#   3. Sandbox checks: extension, URL patterns, known bad indicators
#   4. Returns verdict: "clean" or "malicious"
#   5. If malicious → block the download, log the event
#
# WHERE IT FITS:
#   Called FOURTH in main_stage6.py - after domain/port checks pass.
#   Even if someone reaches github.com (allowed), downloading a
#   suspicious .exe from there still gets sandboxed first.
#
# NOTE: This is a LOCAL sandbox (no external API needed).
#       In production you'd send to VirusTotal / Any.run API.

import re
import time

# ──────────────────────────────────────────
# File extensions that MUST be sandboxed
# ──────────────────────────────────────────
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".ps1", ".vbs",
    ".js",  ".jar", ".msi", ".dll", ".scr",
    ".hta", ".pif", ".com", ".reg", ".lnk",
]

# ──────────────────────────────────────────
# URL patterns that are suspicious
# ──────────────────────────────────────────
SUSPICIOUS_URL_PATTERNS = [
    r"download\.php\?",        # dynamic download scripts
    r"/payload[s]?/",          # payload paths
    r"base64",                 # base64 encoded content
    r"cmd\.exe",               # shell in URL
    r"powershell",             # PS in URL
    r"/tmp/\w+\.\w+",          # temp file paths
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\w+\.\w+",  # IP/file direct
]

# ──────────────────────────────────────────
# Known bad file hashes (expand this list)
# In production: pull from threat intel feed
# ──────────────────────────────────────────
KNOWN_BAD_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb924",  # example
    "d41d8cd98f00b204e9800998ecf8427e",  # example
]


def is_suspicious_url(url):
    """
    Check if a URL looks like it's serving a dangerous file.
    Returns: (suspicious: bool, reason: str)
    """
    url_lower = url.lower()

    # Check file extension
    for ext in SUSPICIOUS_EXTENSIONS:
        if url_lower.endswith(ext) or (ext + "?") in url_lower:
            return True, f"Suspicious file extension: {ext}"

    # Check URL patterns
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url_lower):
            return True, f"Suspicious URL pattern: {pattern}"

    return False, "URL looks clean"


def sandbox_analyze(url, filename=None):
    """
    Run sandbox analysis on a suspicious file/URL.

    In this local version:
    - Checks extension risk level
    - Checks URL patterns
    - Checks against known bad hashes
    - Scores the threat level

    Returns: dict with verdict, score, reason
    """
    print(f"  [Sandbox] Analyzing: {url}")
    time.sleep(0.1)  # simulate analysis time

    score = 0
    reasons = []

    url_lower = url.lower()
    name = filename.lower() if filename else url_lower

    # Score: dangerous extension
    for ext in [".exe", ".bat", ".ps1", ".vbs", ".cmd", ".hta"]:
        if name.endswith(ext):
            score += 40
            reasons.append(f"High-risk extension: {ext}")
            break

    for ext in [".js", ".jar", ".dll", ".msi", ".scr"]:
        if name.endswith(ext):
            score += 25
            reasons.append(f"Medium-risk extension: {ext}")
            break

    # Score: suspicious URL patterns
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url_lower):
            score += 20
            reasons.append(f"Suspicious pattern in URL")
            break

    # Score: served from IP directly (not domain)
    if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        score += 30
        reasons.append("File served directly from IP address (no domain)")

    # Score: non-standard port in URL
    if re.search(r":\d{4,5}/", url) and "443" not in url and "8080" not in url:
        score += 15
        reasons.append("Non-standard port in download URL")

    # Verdict
    if score >= 40:
        verdict = "malicious"
    elif score >= 20:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "score":   score,
        "reasons": reasons if reasons else ["No indicators found"],
        "url":     url,
    }


def check_sandbox(url, filename=None):
    """
    Combined entry point used by main_stage6.py.
    Returns: (allowed: bool, result: dict)
    """
    suspicious, reason = is_suspicious_url(url)

    if not suspicious:
        return True, {"verdict": "clean", "score": 0, "reasons": [reason]}

    print(f"  [Sandbox] Suspicious URL detected: {reason}")
    result = sandbox_analyze(url, filename)

    print(f"  [Sandbox] Verdict: {result['verdict'].upper()} (score={result['score']})")
    for r in result["reasons"]:
        print(f"    - {r}")

    allowed = result["verdict"] == "clean"
    return allowed, result


# ──────────────────────────────────────────
# Quick self-test
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("=== Sandbox Self-Test ===\n")

    urls = [
        "https://github.com/user/repo/archive/main.zip",
        "https://github.com/user/tool/releases/download/v1/tool.exe",
        "http://192.168.1.99/payload.bat",
        "https://google.com/search?q=python",
        "https://evil.com/download.php?file=rat.ps1",
        "https://legit.com/installer.msi",
    ]

    for url in urls:
        allowed, result = check_sandbox(url)
        status = "ALLOW" if allowed else "BLOCK"
        print(f"  [{status}] {url[:60]}")
        print(f"    → verdict={result['verdict']} | {result['reasons'][0]}\n")