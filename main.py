from capture.sniffer import start_capture
from analysis.detector import detect_suspicious
from db.database import init_db, insert_traffic, insert_alert

# تجاهل الاتصالات المحلية
IGNORED_IPS = {"127.0.0.1", "::1"}

def main():
    print("[+] TrafficWatcher started...\n")

    # تهيئة قاعدة البيانات
    init_db()

    for pkt in start_capture():
        src = pkt.get("src_ip")
        dst = pkt.get("dst_ip")

        # تجاهل الحزم غير الصالحة
        if not src or not dst:
            continue

        # تجاهل loopback
        if src in IGNORED_IPS:
            continue

        # تخزين الترافيك في SQLite
        insert_traffic(pkt)

        # عرض الترافيك
        print(
            f"{src}:{pkt['src_port']} "
            f"-> {dst}:{pkt['dst_port']} "
            f"| {pkt['protocol']} | {pkt['length']} bytes"
        )

        # كشف السلوك المشبوه (Port Scan)
        alert = detect_suspicious(pkt)
        if alert:
            insert_alert(alert)
            print(
                f"\n🚨 PORT SCAN ALERT 🚨\n"
                f"Source IP: {alert['src_ip']}\n"
                f"Scanned Ports: {alert['ports']} "
                f"in {alert['window']}s\n"
            )

if __name__ == "__main__":
    main()

