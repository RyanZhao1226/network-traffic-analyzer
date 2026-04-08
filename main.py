"""
main.py — Capture then analyze, or analyze an existing pcap.
"""

import sys
from capture import start_capture
from analyzer import analyze

PCAP_FILE  = "traffic.pcap"
OUTPUT_DIR = "plots"


def capture_then_analyze():
    """Live capture → auto analyze when done."""
    path, count = start_capture(
        output_file  = PCAP_FILE,
        interface    = None,
        packet_count = 1000000,
        duration     = 60,
        bpf_filter   = "",
        verbose      = True,
    )

    if not path:
        print("Nothing captured, skipping analysis.")
        return

    result = analyze(pcap_file=path, output_dir=OUTPUT_DIR)
    print(f"\nDone. {result['total']} packets, "
          f"{len(result['anomalies'])} anomaly window(s).")
    print(f"Open report: {result['report_path']}")


def analyze_existing(pcap_path):
    """Analyze a pcap file you already have."""
    result = analyze(pcap_file=pcap_path, output_dir=OUTPUT_DIR)
    print(f"\nDone. Report: {result['report_path']}")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        # python main.py existing.pcap
        analyze_existing(sys.argv[1])
    else:
        # capture + analyze
        capture_then_analyze()