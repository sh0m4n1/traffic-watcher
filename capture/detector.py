import time
from collections import defaultdict

THRESHOLD = 20      # عدد الباكيتات
WINDOW = 10         # خلال كم ثانية

traffic_counter = defaultdict(list)

def detect_suspicious(packet):
    now = time.time()
    src_ip = packet.get("src_ip")

    if not src_ip:
        return None

    traffic_counter[src_ip].append(now)

    # حذف التواقيت القديمة
    traffic_counter[src_ip] = [
        t for t in traffic_counter[src_ip] if now - t <= WINDOW
    ]

    if len(traffic_counter[src_ip]) >= THRESHOLD:
        return {
            "alert": "High traffic detected",
            "src_ip": src_ip,
            "count": len(traffic_counter[src_ip]),
            "window": WINDOW
        }

    return None
