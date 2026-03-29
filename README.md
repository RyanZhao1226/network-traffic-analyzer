# netTraffic-analyzer

A lightweight automated network traffic analysis system.

This project captures and analyzes real network traffic using Wireshark/tcpdump and Python. It transforms raw PCAP data into structured protocol statistics, temporal insights, and anomaly detection results.

---

## Project Overview

Modern network tools such as Wireshark generate raw packet-level data that is difficult to interpret manually.

NetTraffic Analyzer aims to:

* Capture network traffic
* Parse PCAP files automatically
* Perform rule-based application-level classification
* Analyze traffic behavior over time
* Detect abnormal traffic patterns
* Generate automated reports with visual insights

This repository currently contains the implementation up to **Iteration 3**.

---

## Project Structure

```plaintext
network-traffic-analyzer/
├── analyzer.py
├── traffic.pcap
├── plots/
│   ├── classification distribution.png
│   ├── time_series.png
│   ├── report.html
└── README.md
```

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

---

## Iteration 2 Features

### Rule-Based Traffic Classification

* Classify traffic based on TCP/UDP port mapping
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

## Iteration 3 Features

### Time-Based Traffic Analysis

- Extract packet timestamps from PCAP files
- Divide traffic into fixed time windows
- Count packets per time window
- Analyze traffic behavior over time

### Statistical Anomaly Detection

- Compute mean and standard deviation of traffic volume
- Apply Z-score method:
  - Detect anomaly if **Z > 3**
- Identify abnormal traffic spikes

### Time-Series Visualization

- Plot traffic volume over time
- Show average baseline
- Highlight traffic patterns and spikes
- Save visualization as:
  - `plots/time_series.png`

### Protocol Distribution (Enhanced)

- Preserve Iteration 2 pie chart visualization
- Save as:
  - `plots/classification distribution.png`

### Automated HTML Report

- Generate structured report:
  - Summary (total packets + status)
  - Protocol distribution
  - Anomaly detection results
  - Time-series visualization
- Output:
  - `plots/report.html`

---

## Technologies Used

* Wireshark (traffic capture)
* Python 3
* Scapy (packet parsing)
* Matplotlib (visualization)
