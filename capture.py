from scapy.all import sniff, wrpcap, get_if_list
import os
import threading


def prompt_parameters():
    """
    Interactively prompt the user for capture parameters in the terminal.

    Returns:
        dict : Parameters ready to pass into start_capture().
    """
    print("=" * 52)
    print("  Scapy Packet Capture — Parameter Setup")
    print("=" * 52)

    # Interface
    available = get_if_list()
    print(f"\nAvailable interfaces: {', '.join(available)}")
    iface = input("Interface (leave blank for default): ").strip()
    if iface and iface not in available:
        print(f"  Warning: '{iface}' not in interface list, proceeding anyway.")
    interface = iface or None

    # Output file
    out = input("Output file (default: traffic.pcap): ").strip()
    output_file = out or "traffic.pcap"
    if not output_file.endswith(".pcap"):
        output_file += ".pcap"

    # Packet count
    while True:
        val = input("Max packets to capture (0 = unlimited, default: 100): ").strip()
        if val == "":
            packet_count = 100
            break
        if val.isdigit():
            packet_count = int(val)
            break
        print("  Please enter a non-negative integer.")

    # Duration
    while True:
        val = input("Timeout in seconds (0 = unlimited, default: 30): ").strip()
        if val == "":
            duration = 30
            break
        if val.isdigit():
            duration = int(val) or None   # 0 to None
            break
        print("  Please enter a non-negative integer.")

    # BPF filter
    print("\n  BPF filter examples:")
    print("    tcp port 80       — HTTP only")
    print("    tcp port 443      — HTTPS only")
    print("    udp port 53       — DNS only")
    print("    icmp              — Ping / ICMP")
    print("    host 8.8.8.8      — Specific IP")
    print("    not arp           — Exclude ARP")
    bpf = input("BPF filter (leave blank for none): ").strip()
    bpf_filter = bpf or ""

    # Verbose
    v = input("Print each packet to terminal? (Y/n): ").strip().lower()
    verbose = v != "n"

    # Summary
    print("\n" + "=" * 52)
    print("  Capture Settings")
    print("=" * 52)
    print(f"  Interface : {interface or 'default'}")
    print(f"  Output    : {output_file}")
    print(f"  Max pkts  : {packet_count or '∞'}")
    print(f"  Timeout   : {f'{duration}s' if duration else '∞'}")
    print(f"  Filter    : {bpf_filter or 'none'}")
    print(f"  Verbose   : {verbose}")
    print("=" * 52)

    confirm = input("\nStart capture? (Y/n): ").strip().lower()
    if confirm == "n":
        print("Aborted.")
        raise SystemExit(0)

    return dict(
        output_file  = output_file,
        interface    = interface,
        packet_count = packet_count,
        duration     = duration,
        bpf_filter   = bpf_filter,
        verbose      = verbose,
    )


def start_capture(
    output_file  = "traffic.pcap",
    interface    = None,
    packet_count = 100,
    duration     = 30,
    bpf_filter   = "",
    verbose      = True,
):
    """
    Capture packets and save to a pcap file.

    Args:
        output_file  : Path to the output .pcap file.
        interface    : Network interface (None = auto).
        packet_count : Max packets to capture (0 = unlimited).
        duration     : Timeout in seconds (None = unlimited).
        bpf_filter   : BPF filter string, e.g. "tcp port 80".
        verbose      : Print each packet summary if True.

    Returns:
        str  : Absolute path to the saved pcap file.
        int  : Number of packets captured.
    """
    captured = []

    def handler(pkt):
        captured.append(pkt)
        if verbose:
            print(f"[{len(captured):>5}] {pkt.summary()}")

    if verbose:
        print(f"\n[capture] Starting — iface={interface or 'default'} "
              f"filter='{bpf_filter or 'none'}' "
              f"count={packet_count or '∞'} timeout={duration or '∞'}s")
        print("[capture] Press Ctrl+C to stop early.\n")

    sniff(
        iface=interface,
        filter=bpf_filter,
        prn=handler,
        count=packet_count,
        timeout=duration,
        store=False,
    )

    if captured:
        wrpcap(output_file, captured)
        path = os.path.abspath(output_file)
        if verbose:
            print(f"\n[capture] Saved {len(captured)} packet(s) → {path}")
        return path, len(captured)
    else:
        if verbose:
            print("\n[capture] No packets captured.")
        return None, 0


def start_capture_async(on_done=None, **kwargs):
    """
    Run start_capture() in a background thread (non-blocking).

    Args:
        on_done : Optional callback(path, count) called when capture finishes.
        **kwargs: All arguments accepted by start_capture().

    Returns:
        threading.Thread : The background thread (already started).
    """
    def _run():
        path, count = start_capture(**kwargs)
        if on_done:
            on_done(path, count)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# Run standalone
if __name__ == "__main__":
    import signal, sys

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    params = prompt_parameters()
    start_capture(**params)