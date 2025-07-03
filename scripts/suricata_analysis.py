import json
import pandas as pd
import matplotlib.pyplot as plt
from collections import deque
from datetime import datetime
from jinja2 import Template

# ✅ Step 1: اقرأ eve.json بسطر بسطر (آخر 1000 تنبيه فقط)
data = deque(maxlen=10000)  # لتوفير الذاكرة

with open("/var/log/suricata/eve.json", "r") as file:
    for line in file:
        if '"alert"' in line:
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # تجاهل السطر التالف

# ✅ Step 2: تحويل البيانات إلى DataFrame
alerts = pd.json_normalize(data)

alerts['timestamp'] = pd.to_datetime(alerts['timestamp'])
alerts['time_only'] = alerts['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
alerts['src'] = alerts['src_ip']
alerts['dest'] = alerts['dest_ip']
alerts['signature'] = alerts['alert.signature']

# ✅ Step 3: رسم عدد التنبيهات على مدار الوقت
attacks_per_minute = alerts.groupby('time_only').size()
plt.figure(figsize=(10,5))
attacks_per_minute.plot(kind='line', marker='o', color='red')
plt.title('Attacks Over Time')
plt.xlabel('Time')
plt.ylabel('Number of Alerts')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('attack_chart.png')
plt.close()

# ✅ Step 4: توليد تقرير HTML
top_attackers = alerts['src'].value_counts().head(5)
top_signatures = alerts['signature'].value_counts().head(5)

html_template = """
<html>
<head><title>Suricata Attack Report</title></head>
<body style="font-family: Arial;">
    <h1>📊 Suricata Attack Report</h1>
    <p><b>Total Alerts:</b> {{ total_alerts }}</p>

    <h2>🔝 Top Attackers</h2>
    <ul>
    {% for ip, count in top_attackers.items() %}
        <li>{{ ip }} - {{ count }} alerts</li>
    {% endfor %}
    </ul>

    <h2>⚠️ Top Alert Types</h2>
    <ul>
    {% for sig, count in top_signatures.items() %}
        <li>{{ sig }} - {{ count }} alerts</li>
    {% endfor %}
    </ul>

    <h2>🕒 Attack Timeline</h2>
    <img src="attack_chart.png" width="800"/>

    <h2>📄 Raw Alert Samples</h2>
    <pre>{{ samples }}</pre>
</body>
</html>
"""

template = Template(html_template)
report = template.render(
    total_alerts=len(alerts),
    top_attackers=top_attackers.to_dict(),
    top_signatures=top_signatures.to_dict(),
    samples=json.dumps(list(data)[-3:], indent=4)
)

with open("suricata_report.html", "w") as f:
    f.write(report)

print("✅ Report generated: suricata_report.html")
print("✅ Attack chart saved: attack_chart.png")
