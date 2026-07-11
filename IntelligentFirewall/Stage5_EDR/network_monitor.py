# network_monitor.py
# 🌐 Get network connections of a process

import psutil

def get_connections(pid):
    connections = []

    try:
        proc = psutil.Process(pid)

        for conn in proc.connections(kind='inet'):
            if conn.raddr:
                ip = conn.raddr.ip
                connections.append(ip)

    except Exception as e:
        # Process may already be dead (common case)
        return []

    return list(set(connections))  # remove duplicates