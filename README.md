# netTraffic-analyzer

A lightweight automated network traffic analysis system.

This project captures and analyzes real network traffic using Wireshark/tcpdump and Python. It transforms raw PCAP data into structured protocol statistics and visual insights.

---

## Project Overview

Modern network tools such as Wireshark generate raw packet-level data that is difficult to interpret manually.

NetTraffic Analyzer aims to:

* Capture network traffic
* Parse PCAP files automatically
* Perform rule-based application-level classification
* Generate protocol distribution statistics
* Visualize traffic distribution

This repository currently contains the implementation up to  **Iteration 2**.

---

## Iteration 1 Features

### Traffic Capture

* Capture live network traffic using Wireshark
* Save captured traffic as `.pcap` files

### PCAP Parsing

* Read PCAP files using Python and Scapy
* Extract TCP and UDP protocol information

### Basic Protocol Statistics

* Total packet count
* TCP packet count
* UDP packet count
* Protocol percentage distribution

### Visualization

* Generate protocol distribution pie chart
* Save visualization to `/plots` directory

## Iteration 2 Features

### Rule-Based Traffic Classification

* Classify traffic based  on TCP/UDP port mapping
* Detect application-layer protocols including:
  - HTTP / HTTPS
  - DNS
  - SSH
  - FTP
  - SMTP
  - RDP
  - MySQL / PostgreSQL / Redis
  - QUIC / HTTP3
  - HTTP-Alt / HTTPS-Alt
  - Other TCP / Other UDP

### Intelligent Category Filtering

- Merge small categories (<2%) into "Other (misc)"
- Print top unclassified destination ports
- Sort output by packet count

### Enhanced Visualization

- Custom color mapping for protocols
- Clean white background
- Percentage display (≥2%)
- External legend showing:
  - Protocol name
  - Packet count
  - Percentage

---

## Technologies Used

* Wireshark (traffic capture)
* Python 3
* Scapy (packet parsing)
* Matplotlib (visualization)

---

## Project Structure

```plaintext
network-traffic-analyzer/
├── analyzer.py
├── traffic.pcap
├── plots/
│ ├── classification_distribution.png
│ └── protocol_distribution.png
└── README.md
```

## How to Run

### 1. Install dependencies

`pip install scapy matplotlib`

### 2. Capture traffic

Use Wireshark to capture traffic and save it as:

`traffic.pcap`

Place the file in the project directory.

### 3. Run analysis

`python analyzer.py`

The script will:

* Print classified traffic statistics
* Display top unclassified ports
* Generate and save a pie chart in the `/plots` folder

---

## Sample Output

Example protocol distribution:

```
HTTPS          :  8,421  (72.9%)
DNS            :    276  (2.4%)
Other TCP      :  2,843  (24.6%)
```

A visualization will be saved as:

`plots/classification_distribution.png`

---

## Next Iterations

Planned improvements:

- Statistical anomaly detection
- Threshold-based abnormal traffic identification
- Time-based traffic pattern analysis
- Further visualization improvements
