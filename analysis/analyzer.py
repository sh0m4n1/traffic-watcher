from collections import defaultdict
import time

# نخزن المحاولات هون
connection_tracker = defaultdict(list)

# إعدادات الكشف
ATTEMPT_THRESHOLD = 5   # عدد المحاولات
TIME_WINDOW = 10        # بالثواني

def correlate_packet(packet):
    alerts = []

    try:
        # نتأكد إن الباكيت فيها IP و TCP
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            src_ip = packet.ip.src
            dst_port = packet.tcp.dstport

            # نركز على SSH و FTP
            if dst_port in ['22', '21']:
                current_time = time.time()
                key = f"{src_ip}:{dst_port}"

                # نسجل وقت المحاولة
                connection_tracker[key].append(current_time)

                # نحذف المحاولات القديمة
                connection_tracker[key] = [
                    t for t in connection_tracker[key]
                    if current_time - t <= TIME_WINDOW
                ]

                # إذا تعدت الحد → Alert
                if len(connection_tracker[key]) >= ATTEMPT_THRESHOLD:
                    alerts.append(
                        f"Brute-force suspected from {src_ip} on port {dst_port}"
                    )

    except Exception:
        pass

    return alerts
