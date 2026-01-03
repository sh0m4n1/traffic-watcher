import pyshark
from datetime import datetime

def start_capture():
    capture = pyshark.LiveCapture(interface='any')

    for packet in capture:
        try:
            data = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "src_ip": packet.ip.src if 'IP' in packet else None,
                "dst_ip": packet.ip.dst if 'IP' in packet else None,
                "protocol": packet.transport_layer,
                "src_port": packet[packet.transport_layer].srcport if packet.transport_layer else None,
                "dst_port": packet[packet.transport_layer].dstport if packet.transport_layer else None,
                "length": packet.length
            }
            yield data
        except Exception:
            continue
