import psutil

def get_connections(pid):
    ips = []

    try:
        proc = psutil.Process(pid)
        conns = proc.connections(kind='inet')

        for conn in conns:
            if conn.raddr:
                ips.append(conn.raddr.ip)

    except:
        pass

    return list(set(ips))