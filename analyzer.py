from scapy.all import rdpcap, TCP, UDP
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os

# port to protocol mapping
PORT_MAP = {
    20: "FTP",   21: "FTP",
    22: "SSH",
    25: "SMTP",  587: "SMTP", 465: "SMTP",
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

# classify a packet based on its TCP/UDP ports
def classify(pkt):
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

# read packets and stats
packets = rdpcap("traffic.pcap")
stats: dict[str, int] = {}
for pkt in packets:
    label = classify(pkt)
    stats[label] = stats.get(label, 0) + 1

total = sum(stats.values())

print("\n=== Traffic Classification ===")
for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
    print(f"{proto:15s}: {count:6d}  ({count / total * 100:.2f}%)")

# print top unclassified ports
other_ports: dict[int, int] = {}
for pkt in packets:
    if classify(pkt) in ("Other TCP", "Other UDP"):
        for layer in (TCP, UDP):
            if pkt.haslayer(layer):
                p = pkt[layer].dport
                other_ports[p] = other_ports.get(p, 0) + 1

if other_ports:
    print("\n=== Top 20 unclassified dest-ports ===")
    for port, cnt in sorted(other_ports.items(), key=lambda x: -x[1])[:20]:
        print(f"  port {port:5d}: {cnt} packets")

# merge small categories
THRESHOLD = 0.02
other_misc = 0
filtered: dict[str, int] = {}
for k, v in stats.items():
    if v / total < THRESHOLD:
        other_misc += v
    else:
        filtered[k] = v
if other_misc:
    filtered["Other (misc)"] = filtered.get("Other (misc)", 0) + other_misc

labels = list(filtered.keys())
sizes  = list(filtered.values())

# assign colors to protocols
COLORS = {
    "HTTPS":        "#378ADD",
    "HTTP":         "#1D9E75",
    "DNS":          "#EF9F27",
    "SSH":          "#7F77DD",
    "FTP":          "#D85A30",
    "SMTP":         "#D4537E",
    "RDP":          "#639922",
    "QUIC/HTTP3":   "#5DCAA5",
    "HTTP-Alt":     "#85B7EB",
    "HTTPS-Alt":    "#AFA9EC",
    "MySQL":        "#F0997B",
    "PostgreSQL":   "#B5D4F4",
    "Redis":        "#FAC775",
    "Other TCP":    "#888780",
    "Other UDP":    "#B4B2A9",
    "Non-TCP/UDP":  "#D3D1C7",
    "Other (misc)": "#D3D1C7",
}
colors = [COLORS.get(l, "#CCCCCC") for l in labels]

# plotting
matplotlib.rcParams["font.family"] = "DejaVu Sans"

fig, ax = plt.subplots(figsize=(10, 7))
fig.patch.set_facecolor("white")

wedges, _, autotexts = ax.pie(
    sizes,
    labels=None,
    colors=colors,
    autopct=lambda p: f"{p:.1f}%" if p >= 2 else "",
    pctdistance=0.78,
    startangle=140,
    wedgeprops=dict(linewidth=0.8, edgecolor="white"),
)

for at in autotexts:
    at.set_fontsize(10)
    at.set_color("white")

# legend: show protocol name + count + percentage
legend_labels = [
    f"{l}  ({filtered[l]:,} pkts, {filtered[l]/total*100:.1f}%)"
    for l in labels
]
ax.legend(
    wedges, legend_labels,
    title="Protocol",
    title_fontsize=11,
    loc="center left",
    bbox_to_anchor=(1.02, 0.5),
    fontsize=10,
    frameon=False,
)

ax.set_title("Traffic Classification Distribution", fontsize=15, pad=18)
plt.tight_layout()

os.makedirs("plots", exist_ok=True)
out = "plots/classification_distribution.png"
plt.savefig(out, dpi=150, bbox_inches="tight")
print(f"\nplot saved: {out}")
plt.show()