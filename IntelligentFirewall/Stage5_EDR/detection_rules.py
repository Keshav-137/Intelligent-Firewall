# detection_rules.py

SUSPICIOUS_KEYWORDS = [
    "powershell", "-enc", "encodedcommand", "iex", "downloadstring",
    "certutil", "bitsadmin", "mshta", "regsvr32", "wmic"
]

LOLBINS = [
    "powershell.exe", "cmd.exe", "mshta.exe",
    "regsvr32.exe", "bitsadmin.exe", "wmic.exe"
]

HIGH_RISK_PARENTS = [
    "winword.exe", "excel.exe", "outlook.exe",
    "chrome.exe", "msedge.exe"
]


def is_suspicious(proc, context):
    """
    proc: {pid, ppid, name, cmd}
    context: {all_processes}
    """

    score = 0
    name = proc["name"].lower()
    cmd = proc["cmd"].lower()

    # 🔥 1. Keyword detection
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in cmd:
            score += 2

    # 🔥 2. LOLBins usage
    if name in LOLBINS:
        score += 2

    # 🔥 3. Parent-child analysis
    parent_name = None
    for p in context["all_processes"]:
        if p.info["pid"] == proc["ppid"]:
            parent_name = p.info["name"].lower()
            break

    if parent_name in HIGH_RISK_PARENTS:
        print(f"⚠ Suspicious Parent: {parent_name}")
        score += 3

    # 🔥 Final decision
    return score >= 3