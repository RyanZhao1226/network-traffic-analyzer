from scapy.all import rdpcap, TCP, UDP
import matplotlib.pyplot as plt

# read packets from pcap file
packets = rdpcap("traffic.pcap")

stats = {
    "TCP": 0,
    "UDP": 0,
    "Other": 0
}

# traverse packets and count protocol types
for pkt in packets:
    if pkt.haslayer(TCP):
        stats["TCP"] += 1
    elif pkt.haslayer(UDP):
        stats["UDP"] += 1
    else:
        stats["Other"] += 1

# output statistics
total = sum(stats.values())

print("\n===== Traffic Statistics =====")
for protocol, count in stats.items():
    percentage = (count / total) * 100
    print(f"{protocol}: {count} packets ({percentage:.2f}%)")

# plot
plt.pie(stats.values(), labels=stats.keys(), autopct='%1.1f%%')
plt.title("Protocol Distribution")
plt.savefig("plots/protocol_distribution.png")
print("\nChart saved to plots/protocol_distribution.png")
plt.show()