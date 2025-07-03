import json
import time
from plyer import notification  # Desktop notifications

# Suricata log path (default)
eve_log_path = "/var/log/suricata/eve.json"

def send_desktop_notification(alert_msg):
    notification.notify(
        title='🚨 YOU ARE UNDER ATTACK!',
        message=f'Suricata has detected:\n{alert_msg}',
        timeout=10  # The notification will stay for 10 seconds
    )

# Monitor the eve.json log
print("📡 Monitoring Suricata logs...")

with open(eve_log_path, "r") as log_file:
    log_file.seek(0, 2)  # Move to end of file

    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.2)
            continue

        try:
            log = json.loads(line)
            if log.get("event_type") == "alert":
                alert_msg = log["alert"]["signature"]
                print("🚨 YOU ARE UNDER ATTACK!")
                print(f"⚠️  Alert: {alert_msg}")
                send_desktop_notification(alert_msg)
        except json.JSONDecodeError:
            continue

