import os
import time

def safe_kill(pid):
    print("⚡ Taking Action...")

    for _ in range(3):
        result = os.system(f"taskkill /PID {pid} /F >nul 2>&1")
        if result == 0:
            print("🛑 Process Killed")
            return
        time.sleep(0.5)

    print("⚠ Process already terminated (fast attack)")


def block_ip(ip):
    if not ip:
        return

    print(f"🚫 Blocking IP: {ip}")

    os.system(
        f'netsh advfirewall firewall add rule name="Block_{ip}" dir=out action=block remoteip={ip}'
    )


def respond(proc, connections):
    pid = proc["pid"]

    # Step 1: Kill process
    safe_kill(pid)

    # Step 2: Block all connected IPs
    for ip in connections:
        block_ip(ip)