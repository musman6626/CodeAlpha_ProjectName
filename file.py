#!/usr/bin/env python3
import argparse
from collections import Counter
from datetime import datetime

from scapy.all import (
    sniff, wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw,
)

stats = Counter()
captured = []


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"      {i:04x}  {hex_part} {ascii_part}")
    return "\n".join(lines)


def tcp_flags(flags) -> str:
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
    return ",".join(names[f] for f in str(flags) if f in names) or "-"


def process_packet(pkt):
    captured.append(pkt)
    ts = datetime.now().strftime("%H:%M:%S")
    stats["total"] += 1

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        print(f"\n[{ts}] #{stats['total']}  {len(pkt)} bytes")
        print(f"  Ethernet : {eth.src} -> {eth.dst}")

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "who-has" if arp.op == 1 else "is-at"
        stats["ARP"] += 1
        print(f"  ARP      : {op} {arp.pdst} (asked by {arp.psrc})")
        return

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst, ttl = ip.src, ip.dst, ip.ttl
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        src, dst, ttl = ip.src, ip.dst, ip.hlim
    else:
        stats["other"] += 1
        print(f"  Other    : {pkt.summary()}")
        return
    print(f"  IP       : {src} -> {dst}  (TTL {ttl})")

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        stats["TCP"] += 1
        print(f"  TCP      : port {t.sport} -> {t.dport}  flags=[{tcp_flags(t.flags)}] "
              f"seq={t.seq} ack={t.ack}")
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        stats["UDP"] += 1
        print(f"  UDP      : port {u.sport} -> {u.dport}  len={u.len}")
    elif pkt.haslayer(ICMP):
        ic = pkt[ICMP]
        stats["ICMP"] += 1
        print(f"  ICMP     : type={ic.type} code={ic.code}")
    else:
        stats["other"] += 1

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        stats["DNS"] += 1
        if dns.qr == 0 and dns.qd:
            print(f"  DNS      : query for {dns.qd.qname.decode(errors='ignore')}")
        elif dns.qr == 1:
            print(f"  DNS      : response ({dns.ancount} answers)")

    if args.payload and pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)
        print(f"  Payload  : {len(data)} bytes")
        print(hexdump(data[:128]))
        if len(data) > 128:
            print("      ... (truncated)")


def print_summary():
    print("\n" + "=" * 40)
    print("Capture summary")
    print("=" * 40)
    for key, count in stats.most_common():
        print(f"  {key:<8} {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple packet sniffer (Scapy)")
    parser.add_argument("-i", "--iface", help="interface (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 443'")
    parser.add_argument("-p", "--payload", action="store_true", help="show payload hexdump")
    parser.add_argument("-w", "--write", help="save capture to a .pcap file")
    args = parser.parse_args()

    print("Sniffing... press Ctrl+C to stop.")
    try:
        sniff(iface=args.iface, filter=args.filter, count=args.count,
              prn=process_packet, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        raise SystemExit("Permission denied: run with sudo / as Administrator.")

    print_summary()
    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"\nSaved {len(captured)} packets to {args.write}")