import re

log = "04/16/2025-00:20:11.753795  [wDrop] [**] [1:1000001:1] Potential SYN Flood Attack [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 228.115.182.43:18243 -> 192.168.76.133:80"

# Regex pattern to parse the log
pattern = r"""
(?P<timestamp>\d+/\d+/\d+-\d+:\d+:\d+\.\d+)\s+
\[(?P<action>\w+)\].*?
\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+
(?P<message>.*?)\s+
\[Classification:\s(?P<classification>.*?)\]\s+
\[Priority:\s(?P<priority>\d+)\]\s+
\{(?P<protocol>\w+)\}\s+
(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+
(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)
"""

match = re.search(pattern, log, re.VERBOSE)
if match:
    data = match.groupdict()

    # Friendly action message
    action_message = "Attack has been dropped" if data['action'] == "wDrop" else data['action']

    # Create HTML summary
    html_summary = f"""
    <html>
    <head><title>Snort Log Summary</title></head>
    <body>
        <h2>🚨 Intrusion Detection Alert</h2>
        <ul>
            <li><strong>Timestamp:</strong> {data['timestamp']}</li>
            <li><strong>Action:</strong> {action_message}</li>
            <li><strong>Message:</strong> {data['message']}</li>
            <li><strong>Classification:</strong> {data['classification']}</li>
            <li><strong>Priority:</strong> {data['priority']}</li>
            <li><strong>Protocol:</strong> {data['protocol']}</li>
            <li><strong>Source:</strong> {data['src_ip']}:{data['src_port']}</li>
            <li><strong>Destination:</strong> {data['dst_ip']}:{data['dst_port']}</li>
            <li><strong>Signature ID:</strong> {data['sid']} (Rev {data['rev']})</li>
        </ul>
    </body>
    </html>
    """

    # Save to HTML file
    with open("log_summary.html", "w") as file:
        file.write(html_summary)

    print("✅ HTML summary saved to 'log_summary.html'")
else:
    print("❌ No match found in the log line.")

