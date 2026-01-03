import time
from collections import defaultdict

WINDOW = 10              # ثواني المراقبة
PORT_THRESHOLD = 20      # عدد بورتات مختلفة
ALERT_COOLDOWN = 30      # كم ثانية نسكت بعد alert

scan_tracker = defaultdict(lambda: {
    "ports": set(),
    "timestamps": [],
    "last_alert": 0
})

def detect_suspicious(packet):
    src_ip = packet.get("src_ip")
    dst_port = packet.get("dst_port")
    now = time.time()

    if not src_ip or not dst_port:
        return None

    entry = scan_tracker[src_ip]

    entry["ports"].add(dst_port)
    entry["timestamps"].append(now)

    # تنظيف التواقيت القديمة
    entry["timestamps"] = [
        t for t in entry["timestamps"] if now - t <= WINDOW
    ]

    # تحقق من Port Scan
    if len(entry["ports"]) >= PORT_THRESHOLD:
        # تحقق من الـ cooldown
        if now - entry["last_alert"] >= ALERT_COOLDOWN:
            entry["last_alert"] = now
            return {
                "alert": "Port Scan Detected",
                "src_ip": src_ip,
                "ports": len(entry["ports"]),
                "window": WINDOW
            }

    return None
