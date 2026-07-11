# Stage1_PacketCapture/packet_capture.py
# 🔥 Stage 1: Real-time Packet Capture using Scapy
# Runs in a thread, emits events via callback

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
import threading
import time
from datetime import datetime

conf.verb = 0  # suppress scapy output

_capture_thread = None
_stop_event = threading.Event()
_callback = None


def _process_packet(packet):
    if _callback is None:
        return
    try:
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = "OTHER"
        port = 0
        size = len(packet)

        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        event = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "port": port,
            "size": size,
            "stage": "Stage1",
            "action": "MONITOR"
        }
        _callback(event)
    except Exception:
        pass


def start_capture(callback, iface=None):
    global _capture_thread, _callback
    _callback = callback
    _stop_event.clear()

    def _run():
        try:
            sniff(
                prn=_process_packet,
                store=False,
                stop_filter=lambda p: _stop_event.is_set(),
                iface=iface
            )
        except Exception as e:
            print(f"[Stage1] Capture error: {e}")

    _capture_thread = threading.Thread(target=_run, daemon=True)
    _capture_thread.start()
    print("[Stage1] Packet capture started")


def stop_capture():
    _stop_event.set()
    print("[Stage1] Packet capture stopped")
