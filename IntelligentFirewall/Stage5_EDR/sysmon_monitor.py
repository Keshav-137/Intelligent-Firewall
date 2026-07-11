import win32evtlog
import time

def monitor_sysmon(callback):
    logtype = "Microsoft-Windows-Sysmon/Operational"

    print("🚀 Sysmon monitoring started...\n")

    query = "*[System/EventID=1]"

    # 🔥 Start from NOW (not old logs)
    flags = win32evtlog.EvtQueryForwardDirection

    handle = win32evtlog.EvtQuery(logtype, flags, query)

    while True:
        try:
            events = win32evtlog.EvtNext(handle, 10)

            if not events:
                time.sleep(0.2)
                continue

            for event in events:
                try:
                    xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

                    if "ProcessId" not in xml:
                        continue

                    import re

                    pid = int(re.search(r"<Data Name='ProcessId'>(.*?)</Data>", xml).group(1))
                    ppid = int(re.search(r"<Data Name='ParentProcessId'>(.*?)</Data>", xml).group(1))
                    name = re.search(r"<Data Name='Image'>(.*?)</Data>", xml).group(1)
                    cmd_match = re.search(r"<Data Name='CommandLine'>(.*?)</Data>", xml)

                    cmd = cmd_match.group(1) if cmd_match else ""

                    proc = {
                        "pid": pid,
                        "ppid": ppid,
                        "name": name.split("\\")[-1],
                        "cmd": cmd
                    }

                    callback(proc)

                except Exception as e:
                    print("⚠ Parse error:", e)

        except Exception as e:
            print("⚠ Read error:", e)
            time.sleep(1)