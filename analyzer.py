from scapy.all import rdpcap, TCP, UDP
import matplotlib.pyplot as plt
import os
from collections import defaultdict
import statistics

# Configuration
PCAP_FILE = "traffic.pcap"
TIME_WINDOW = 1          # seconds per window
SPIKE_THRESHOLD = 2.0    # multiplier for anomaly detection

# Port to protocol mapping for classification
PORT_MAP = {
    20: "FTP", 21: "FTP",
    22: "SSH",
    25: "SMTP", 587: "SMTP", 465: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# classifcation function
def classify(pkt):
    """Classify packet based on TCP/UDP ports"""
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        for port in (dport, sport):
            if port in PORT_MAP:
                return PORT_MAP[port]
        return "Other TCP"

    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        if 53 in (sport, dport):
            return "DNS"
        if 443 in (sport, dport):
            return "QUIC/HTTP3"
        return "Other UDP"

    return "Non-TCP/UDP"

# Read packets from pcap file
packets = rdpcap(PCAP_FILE)

# 1. Traffic classification
stats = {}
for pkt in packets:
    label = classify(pkt)
    stats[label] = stats.get(label, 0) + 1

total = sum(stats.values())

print("\n=== Traffic Classification ===")
for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
    print(f"{proto:15s}: {count:6d}  ({count / total * 100:.2f}%)")

# 2. classification distribution
THRESHOLD = 0.02
filtered = {}
other_misc = 0

# Merge small categories
for k, v in stats.items():
    if v / total < THRESHOLD:
        other_misc += v
    else:
        filtered[k] = v

if other_misc:
    filtered["Other (misc)"] = other_misc

labels = list(filtered.keys())
sizes = list(filtered.values())

COLORS = {
    "HTTPS": "#378ADD",
    "HTTP": "#1D9E75",
    "DNS": "#EF9F27",
    "SSH": "#7F77DD",
    "FTP": "#D85A30",
    "SMTP": "#D4537E",
    "RDP": "#639922",
    "QUIC/HTTP3": "#5DCAA5",
    "Other TCP": "#888780",
    "Other UDP": "#B4B2A9",
    "Other (misc)": "#D3D1C7",
}

colors = [COLORS.get(l, "#CCCCCC") for l in labels]

plt.figure(figsize=(8, 6))
wedges, _, autotexts = plt.pie(
    sizes,
    colors=colors,
    autopct=lambda p: f"{p:.1f}%" if p >= 2 else "",
    startangle=140,
    wedgeprops=dict(edgecolor="white"),
)

legend_labels = [
    f"{l} ({filtered[l]:,}, {filtered[l]/total*100:.1f}%)"
    for l in labels
]

plt.legend(
    wedges,
    legend_labels,
    title="Protocol",
    loc="center left",
    bbox_to_anchor=(1, 0.5)
)

plt.title("Traffic Classification Distribution")
plt.tight_layout()

os.makedirs("plots", exist_ok=True)
plt.savefig("plots/pie_chart.png", dpi=150)
plt.show()
plt.close()

print("classification distribution saved: plots/pie_chart.png")

# 3. Time-based analysis
time_buckets = defaultdict(int)

start_time = packets[0].time

for pkt in packets:
    t = int((pkt.time - start_time) // TIME_WINDOW)
    time_buckets[t] += 1

counts = list(time_buckets.values())

# 4. Anomaly detection using z-score
mean = statistics.mean(counts)
std = statistics.stdev(counts) if len(counts) > 1 else 0

print("\n=== Anomaly Detection ===")
anomalies = []

for t, count in time_buckets.items():
    z = (count - mean) / std if std > 0 else 0
    if z > 3:
        anomalies.append((t, count))
        print(f"[ALERT] Spike at window {t}: {count} packets (z={z:.2f})")

if not anomalies:
    print("No anomalies detected.")

# 5. Time series plot
plt.figure(figsize=(10, 4))
plt.plot(time_buckets.keys(), time_buckets.values(), marker='o')
plt.axhline(mean, linestyle='--')
plt.title("Traffic Over Time (Packets per Window)")
plt.xlabel("Time Window")
plt.ylabel("Packets")
plt.tight_layout()

plt.savefig("plots/time_series.png", dpi=150)
plt.show()
plt.close()

print("Time series saved: plots/time_series.png")

# 6. HTML report generation
status = "Anomaly Detected" if anomalies else "Normal"

html = f"""
<html>
<head>
<title>Traffic Analysis Report</title>

<style>
body {{
    font-family: Arial;
    margin: 40px;
}}
h1 {{
    color: #333;
}}
.section {{
    margin-top: 30px;
}}
.alert {{
    color: red;
    font-weight: bold;
}}
</style>

</head>
<body>

<h1>Network Traffic Report</h1>

<div class="section">
<h2>Summary</h2>
<p>Total Packets: {total}</p>
<p><b>Status:</b> {status}</p>
</div>

<div class="section">
<h2>Protocol Distribution</h2>
<ul>
"""

# Protocol stats
for proto, count in stats.items():
    html += f"<li>{proto}: {count} ({count/total*100:.2f}%)</li>"

# Add classification distribution
html += """
</ul>
<h3>classification distribution Visualization</h3>
<img src="pie_chart.png" width="600">
</div>
"""

# Anomaly section
html += "<div class='section'><h2>Anomaly Detection</h2>"

if anomalies:
    html += "<ul>"
    for t, c in anomalies:
        html += f"<li class='alert'>Spike at window {t}: {c} packets</li>"
    html += "</ul>"
else:
    html += "<p>No anomalies detected</p>"

html += "</div>"

# Time series
html += """
<div class="section">
<h2>Time-Based Analysis</h2>
<h3>Traffic Over Time</h3>
<img src="time_series.png" width="600">
</div>

</body>
</html>
"""

# Save report
with open("plots/report.html", "w") as f:
    f.write(html)

print("\nReport generated: plots/report.html")