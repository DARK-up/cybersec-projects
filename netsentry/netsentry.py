#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSentry v2.0 - Real-Time Network Threat Detection Engine
===========================================================
Author : CyberSec Portfolio Project (Blue/Red Team Bridge)
Purpose: Authorized network monitoring / defensive research ONLY.

Modules
-------
* Live packet capture & protocol statistics (scapy)
* ARP spoofing / ARP poisoning detection
    - Unsolicited ARP reply detection
    - Gateway MAC change detection (flapping)
    - Conflict: same IP claiming multiple MACs
* Port-scan detection (SYN rate per source -> auto-alert)
* DNS monitoring: query logging, DGA/suspicious TLD heuristics,
  long-subdomain (tunneling) detection
* Cleartext credential exposure watch (HTTP/FTP/POP3/SMTP AUTH)
* Offline PCAP analysis mode (--pcap) for forensics
* Live alert console + JSONL alert log + summary report

LEGAL: Only monitor networks you own or are explicitly authorized to monitor.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Set, Tuple

try:
    from scapy.all import (  # type: ignore
        ARP, DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, ICMP,
        Raw, sniff, rdpcap, conf, get_if_list,
    )
    SCAPY_OK = True
except Exception:  # pragma: no cover
    SCAPY_OK = False

BANNER = r"""
  _   _      _   _____                                 
 | \ | | ___| |_| ____|_ __ _ __ ___  _ __ ___  _   _ 
 |  \| |/ _ \ __|  _| | '__| '_ ` _ \| '_ ` _ \| | | |
 | |\  |  __/ |_| |___| |  | | | | | | | | | | | |_| |
 |_| \_|\___|\__|_____|_|  |_| |_| |_|_| |_| |_|\__, |
                                                |___/   v2.0
  Real-Time Network Threat Detection Engine
"""

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "cyan": "\033[96m", "magenta": "\033[95m",
    "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}


def colorize(t: str, c: str) -> str:
    return t if not sys.stdout.isatty() else f"{C.get(c, '')}{t}{C['reset']}"


def info(m): print(f"{colorize('[*]', 'blue')} {m}")
def ok(m):   print(f"{colorize('[+]', 'green')} {m}")
def warn(m): print(f"{colorize('[!]', 'yellow')} {m}")


# ============================================================================
# Alert model
# ============================================================================
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Alert:
    ts: float
    category: str
    severity: str
    src: str
    dst: str = ""
    detail: str = ""
    evidence: str = ""

    def render(self) -> str:
        tag = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
               "LOW": "cyan", "INFO": "blue"}.get(self.severity, "blue")
        stamp = datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")
        return (f"{colorize('[' + stamp + ']', 'dim')} "
                f"{colorize(self.severity, tag):<22} "
                f"{colorize(self.category, 'bold'):<24} "
                f"{self.src} -> {self.dst} | {self.detail}")


class AlertBus:
    def __init__(self, log_path: Optional[str] = None, quiet: bool = False):
        self.alerts: List[Alert] = []
        self.log_path = log_path
        self.quiet = quiet
        if log_path:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    def emit(self, a: Alert) -> None:
        self.alerts.append(a)
        if not self.quiet:
            print(a.render())
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")


# ============================================================================
# Detector 1 — ARP spoofing
# ============================================================================
class ArpDetector:
    """
    Tracks IP->MAC bindings. Alerts on:
      * one IP claiming multiple MACs        (ARP spoof / conflict)
      * gateway MAC changing repeatedly      (poisoning / MITM)
      * mass unsolicited ARP replies         (arpspoof / bettercap style)
    """

    def __init__(self, bus: AlertBus, gateway_ip: Optional[str] = None):
        self.bus = bus
        self.gateway_ip = gateway_ip
        self.ip_mac: Dict[str, Set[str]] = collections.defaultdict(set)
        self.mac_ip: Dict[str, Set[str]] = collections.defaultdict(set)
        self.unsolicited: Dict[str, Deque[float]] = collections.defaultdict(
            lambda: collections.deque(maxlen=200)
        )
        self.known_pairs: Set[Tuple[str, str]] = set()

    def feed(self, pkt, ts: Optional[float] = None) -> None:
        if not SCAPY_OK or ARP not in pkt:
            return
        ts = ts if ts is not None else float(pkt.time if hasattr(pkt, "time") else time.time())
        arp = pkt[ARP]
        ip, mac = arp.psrc, arp.hwsrc
        if not ip or ip == "0.0.0.0":
            return

        # Conflict detection
        self.ip_mac[ip].add(mac)
        self.mac_ip[mac].add(ip)
        if len(self.ip_mac[ip]) > 1:
            self.bus.emit(Alert(
                ts=ts, category="ARP-SPOOF(CONFLICT)", severity="CRITICAL",
                src=mac, dst=ip,
                detail=f"IP {ip} is claimed by multiple MACs: {sorted(self.ip_mac[ip])}",
                evidence="Same IP answered ARP with different hardware addresses — "
                         "classic ARP poisoning / MITM attempt.",
            ))

        # Gateway MAC change
        if self.gateway_ip and ip == self.gateway_ip:
            known = {m for (i, m) in self.known_pairs if i == ip}
            if known and mac not in known:
                self.bus.emit(Alert(
                    ts=ts, category="ARP-SPOOF(GW-MAC-CHANGE)", severity="CRITICAL",
                    src=mac, dst=ip,
                    detail=f"Gateway {ip} MAC changed {sorted(known)} -> {mac}",
                    evidence="The gateway's MAC address changed unexpectedly — "
                             "possible man-in-the-middle.",
                ))
            self.known_pairs.add((ip, mac))
        else:
            self.known_pairs.add((ip, mac))

        # Unsolicited ARP reply flood (opcode 2 = reply)
        if arp.op == 2:
            self.unsolicited[ip].append(ts)
            window = [t for t in self.unsolicited[ip] if ts - t <= 5.0]
            if len(window) >= 15:
                self.bus.emit(Alert(
                    ts=ts, category="ARP-FLOOD", severity="HIGH",
                    src=mac, dst=ip,
                    detail=f"{len(window)} ARP replies from {mac} for {ip} within 5s",
                    evidence="Unsolicited ARP reply bursts are typical of active "
                             "ARP spoofing tooling.",
                ))
                self.unsolicited[ip].clear()


# ============================================================================
# Detector 2 — Port scan (SYN rate)
# ============================================================================
class PortScanDetector:
    def __init__(self, bus: AlertBus, threshold: int = 25, window: float = 3.0):
        self.bus = bus
        self.threshold = threshold
        self.window = window
        self.syns: Dict[str, Deque[Tuple[float, int]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=500)
        )
        self.alerted: Dict[str, float] = {}

    def feed(self, pkt, ts: Optional[float] = None) -> None:
        if not SCAPY_OK or IP not in pkt or TCP not in pkt:
            return
        ts = ts if ts is not None else float(pkt.time if hasattr(pkt, "time") else time.time())
        ip, tcp = pkt[IP], pkt[TCP]
        flags = int(tcp.flags)
        is_syn = (flags & 0x02) and not (flags & 0x10)  # SYN, no ACK
        if not is_syn:
            return

        src = ip.src
        self.syns[src].append((ts, int(tcp.dport)))
        window = [(t, p) for t, p in self.syns[src] if ts - t <= self.window]
        ports = {p for _, p in window}
        if len(window) >= self.threshold and len(ports) >= self.threshold:
            if src in self.alerted and ts - self.alerted[src] < 30.0:
                return  # rate-limit alerts per source
            self.alerted[src] = ts
            self.bus.emit(Alert(
                ts=ts, category="PORT-SCAN(SYN)", severity="HIGH",
                src=src, dst=ip.dst,
                detail=f"{len(window)} SYNs to {len(ports)} distinct ports in "
                       f"{self.window}s (e.g. {sorted(ports)[:8]}...)",
                evidence="High-rate SYN sweep to many ports — active reconnaissance "
                         "(nmap/masscan style).",
            ))
            self.syns[src].clear()

    def feed_xmas_null(self, pkt, ts: Optional[float] = None) -> None:
        """XMAS / NULL / FIN scans (stealth scans)."""
        if not SCAPY_OK or IP not in pkt or TCP not in pkt:
            return
        ts = ts if ts is not None else float(pkt.time if hasattr(pkt, "time") else time.time())
        flags = int(pkt[TCP].flags)
        if flags == 0x00:
            self.bus.emit(Alert(ts=ts, category="PORT-SCAN(NULL)", severity="MEDIUM",
                                src=pkt[IP].src, dst=pkt[IP].dst,
                                detail="TCP packet with no flags set",
                                evidence="NULL scan — stealth enumeration attempt."))
        if flags == 0x29:  # FIN+PSH+URG
            self.bus.emit(Alert(ts=ts, category="PORT-SCAN(XMAS)", severity="MEDIUM",
                                src=pkt[IP].src, dst=pkt[IP].dst,
                                detail="TCP FIN+PSH+URG flags set",
                                evidence="XMAS scan — stealth enumeration attempt."))


# ============================================================================
# Detector 3 — DNS threats (tunneling / DGA / suspicious TLDs)
# ============================================================================
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "click",
    "loan", "win", "bid", "date", "racing", "stream", "download", "review",
}

DGA_RX = re.compile(r"^(?=.*[0-9])(?=.*[a-z])[a-z0-9]{12,}$")


class DnsDetector:
    def __init__(self, bus: AlertBus):
        self.bus = bus
        self.queries: List[Tuple[float, str, str]] = []
        self.seen: Set[str] = set()

    def feed(self, pkt, ts: Optional[float] = None) -> None:
        if not SCAPY_OK or DNS not in pkt:
            return
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:
            return
        ts = ts if ts is not None else float(pkt.time if hasattr(pkt, "time") else time.time())
        try:
            qname = dns.qd.qname.decode("utf-8", "replace").rstrip(".")
        except Exception:
            return
        src = pkt[IP].src if IP in pkt else "?"
        self.queries.append((ts, src, qname))

        labels = qname.split(".")
        tld = labels[-1].lower() if labels else ""
        host = labels[0] if labels else ""

        # DNS tunneling heuristic: very long first label (>= 40) or many labels
        if len(host) >= 40 or (len(labels) >= 6 and len(host) >= 20):
            key = "tunnel:" + qname
            if key not in self.seen:
                self.seen.add(key)
                self.bus.emit(Alert(
                    ts=ts, category="DNS-TUNNEL", severity="HIGH", src=src, dst=qname,
                    detail=f"unusually long/complex query name ({len(qname)} chars)",
                    evidence="Long random subdomains are used by DNS tunneling "
                             "exfiltration tools (iodine, dnscat2).",
                ))

        # DGA heuristic: long alnum label with digits
        if DGA_RX.match(host) and tld not in ("com", "net", "org", "edu", "gov"):
            key = "dga:" + qname
            if key not in self.seen:
                self.seen.add(key)
                self.bus.emit(Alert(
                    ts=ts, category="DGA-DOMAIN", severity="MEDIUM", src=src, dst=qname,
                    detail="query matches DGA-like entropy pattern",
                    evidence="Algorithmically generated domains are typical of malware C2.",
                ))

        # Suspicious TLD + digits
        if tld in SUSPICIOUS_TLDS and re.search(r"\d", qname):
            key = "tld:" + qname
            if key not in self.seen:
                self.seen.add(key)
                self.bus.emit(Alert(
                    ts=ts, category="SUSPICIOUS-TLD", severity="LOW", src=src, dst=qname,
                    detail=f"TLD .{tld} with numeric labels",
                    evidence="Cheap/dynamic TLDs are heavily abused by malware campaigns.",
                ))


# ============================================================================
# Detector 4 — Cleartext credential exposure
# ============================================================================
CRED_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(rb"(?i)(authorization:\s*basic\s+[A-Za-z0-9+/=]{8,})"), "HTTP Basic Auth"),
    (re.compile(rb"(?i)(pass(word)?|pwd)\s*=\s*['\"]?([^&\s'\"]{3,})"), "Cleartext password field"),
    (re.compile(rb"(?i)^USER\s+(\S+)"), "FTP USER"),
    (re.compile(rb"(?i)^PASS\s+(\S+)"), "FTP PASS"),
    (re.compile(rb"(?i)^(AUTH|LOGIN)\s+(PLAIN|LOGIN)"), "POP3/IMAP auth"),
    (re.compile(rb"(?i)phpsessid=([a-z0-9]{20,})"), "PHP session cookie over cleartext"),
]


class CredDetector:
    def __init__(self, bus: AlertBus):
        self.bus = bus
        self.seen: Set[str] = set()

    def feed(self, pkt, ts: Optional[float] = None) -> None:
        if not SCAPY_OK or Raw not in pkt:
            return
        ts = ts if ts is not None else float(pkt.time if hasattr(pkt, "time") else time.time())
        raw = bytes(pkt[Raw].load)
        src = pkt[IP].src if IP in pkt else "?"
        dst = pkt[IP].dst if IP in pkt else "?"
        for rx, name in CRED_PATTERNS:
            m = rx.search(raw)
            if m:
                key = f"{src}|{name}"
                if key in self.seen:
                    continue
                self.seen.add(key)
                self.bus.emit(Alert(
                    ts=ts, category="CLEARTEXT-CRED", severity="HIGH",
                    src=src, dst=dst,
                    detail=f"{name} observed in traffic",
                    evidence=m.group(0)[:60].decode("utf-8", "replace") + "...",
                ))


# ============================================================================
# Statistics
# ============================================================================
class Stats:
    def __init__(self):
        self.total = 0
        self.protos: collections.Counter = collections.Counter()
        self.talkers: collections.Counter = collections.Counter()
        self.tcp_flags: collections.Counter = collections.Counter()
        self.bytes = 0

    def feed(self, pkt, ts: Optional[float] = None) -> None:
        self.total += 1
        try:
            self.bytes += len(pkt)
        except Exception:
            pass
        if SCAPY_OK:
            if ARP in pkt:
                self.protos["ARP"] += 1
            elif IP in pkt:
                self.talkers[pkt[IP].src] += 1
                if TCP in pkt:
                    self.protos["TCP"] += 1
                    self.tcp_flags[str(pkt[TCP].flags)] += 1
                elif UDP in pkt:
                    self.protos["UDP"] += 1
                elif ICMP in pkt:
                    self.protos["ICMP"] += 1
                else:
                    self.protos["IP-other"] += 1
            else:
                self.protos["Other"] += 1

    def render(self) -> str:
        lines = [
            colorize("────── Traffic Statistics ──────", "bold"),
            f"  Packets: {self.total:,} | Bytes: {self.bytes:,}",
            f"  Protocols: {dict(self.protos.most_common(8))}",
            f"  Top talkers: {dict(self.talkers.most_common(8))}",
        ]
        if self.tcp_flags:
            lines.append(f"  TCP flags: {dict(self.tcp_flags.most_common(8))}")
        return "\n".join(lines)


# ============================================================================
# Engine
# ============================================================================
class NetSentry:
    def __init__(self, bus: AlertBus, gateway: Optional[str], syn_threshold: int):
        self.bus = bus
        self.stats = Stats()
        self.arp = ArpDetector(bus, gateway)
        self.pscan = PortScanDetector(bus, threshold=syn_threshold)
        self.dns = DnsDetector(bus)
        self.creds = CredDetector(bus)

    def handle(self, pkt, ts: Optional[float] = None) -> None:
        self.stats.feed(pkt, ts)
        self.arp.feed(pkt, ts)
        self.pscan.feed(pkt, ts)
        self.pscan.feed_xmas_null(pkt, ts)
        self.dns.feed(pkt, ts)
        self.creds.feed(pkt, ts)

    def summary(self) -> Dict:
        by_cat: collections.Counter = collections.Counter(a.category for a in self.bus.alerts)
        by_sev: collections.Counter = collections.Counter(a.severity for a in self.bus.alerts)
        return {
            "tool": "NetSentry v2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "packets": self.stats.total,
            "bytes": self.stats.bytes,
            "protocols": dict(self.stats.protos),
            "alerts_total": len(self.bus.alerts),
            "alerts_by_severity": dict(by_sev),
            "alerts_by_category": dict(by_cat),
        }


# ============================================================================
# CLI
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsentry",
        description="NetSentry v2.0 - Real-Time Network Threat Detection Engine",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 netsentry.py --live -i eth0 --gateway 192.168.1.1\n"
            "  sudo python3 netsentry.py --live -i wlan0 --filter 'arp or tcp'\n"
            "  python3 netsentry.py --pcap capture.pcapng --report reports/summary.json\n"
            "  python3 netsentry.py --demo            # run detectors on synthetic traffic\n\n"
            "LEGAL: Only monitor networks you are authorized to observe."
        ),
    )
    p.add_argument("--live", action="store_true", help="Live capture mode (needs root)")
    p.add_argument("--pcap", metavar="FILE", help="Offline PCAP analysis")
    p.add_argument("--demo", action="store_true", help="Synthetic demo (no root needed)")
    p.add_argument("-i", "--iface", help="Interface (default: scapy default)")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'arp or tcp'")
    p.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets [0=infinite]")
    p.add_argument("-t", "--seconds", type=int, default=0, help="Stop after N seconds")
    p.add_argument("--gateway", help="Trusted gateway IP (improves ARP detection)")
    p.add_argument("--syn-threshold", type=int, default=25,
                   help="SYN packets in window to flag a scan [25]")
    p.add_argument("--alert-log", metavar="FILE", help="JSONL alert log path")
    p.add_argument("--report", metavar="FILE", help="JSON summary report path")
    p.add_argument("--quiet", action="store_true", help="No console alerts (log only)")
    return p


def run_live(args, engine: NetSentry) -> None:
    if not SCAPY_OK:
        fail("scapy is not installed — pip install scapy")
        sys.exit(1)
    if args.iface:
        conf.iface = args.iface
    info(f"Live capture on {args.iface or conf.iface} | BPF: {args.filter or '(none)'}")
    info("Press Ctrl+C to stop.\n")
    t0 = time.time()

    def cb(pkt):
        engine.handle(pkt)

    stop = {"flag": False}

    def sigint(*_):
        stop["flag"] = True

    signal.signal(signal.SIGINT, sigint)
    try:
        sniff(
            filter=args.filter or None,
            iface=args.iface or None,
            prn=cb,
            store=False,
            count=args.count or 0,
            timeout=args.seconds or None,
        )
    except PermissionError:
        fail("Permission denied — live capture requires root/CAP_NET_RAW.")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    ok(f"Capture stopped after {engine.stats.total:,} packets "
       f"({round(time.time() - t0, 1)}s)")


def run_pcap(args, engine: NetSentry) -> None:
    if not SCAPY_OK:
        fail("scapy is not installed — pip install scapy")
        sys.exit(1)
    if not os.path.exists(args.pcap):
        fail(f"PCAP not found: {args.pcap}")
        sys.exit(1)
    info(f"Loading PCAP: {args.pcap}")
    packets = rdpcap(args.pcap)
    ok(f"Loaded {len(packets):,} packets — analyzing...")
    for pkt in packets:
        engine.handle(pkt)


def run_demo(args, engine: NetSentry) -> None:
    """Build synthetic malicious traffic to demonstrate detectors (no root)."""
    if not SCAPY_OK:
        fail("scapy is not installed — pip install scapy")
        sys.exit(1)
    info("Running DEMO on synthetic attack traffic...\n")
    if not engine.arp.gateway_ip:
        engine.arp.gateway_ip = "192.168.1.1"
    t = time.time()
    packets = []

    # 1) Normal traffic
    for i in range(10):
        packets.append(IP(src="192.168.1.10", dst="93.184.216.34") /
                       TCP(sport=50000 + i, dport=80, flags="S"))
        packets.append(IP(src="93.184.216.34", dst="192.168.1.10") /
                       TCP(sport=80, dport=50000 + i, flags="SA"))

    # 2) ARP: legitimate gateway first, then attacker 192.168.1.66 claims .1 and .10
    for _ in range(5):
        packets.append(Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55",
                           pdst="192.168.1.10", hwdst="aa:bb:cc:dd:ee:ff"))
    for _ in range(20):
        packets.append(Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff",
                           pdst="192.168.1.10", hwdst="00:11:22:33:44:55"))
        packets.append(Ether(src="aa:bb:cc:dd:ee:ff") /
                       ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff"))

    # 3) SYN port scan from 10.0.0.99
    for port in range(1, 60):
        packets.append(IP(src="10.0.0.99", dst="192.168.1.10") /
                       TCP(sport=40000, dport=port, flags="S"))

    # 4) XMAS scan
    packets.append(IP(src="10.0.0.99", dst="192.168.1.10") /
                   TCP(sport=4444, dport=22, flags="FPU"))

    # 5) DNS tunneling + DGA
    packets.append(IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5555, dport=53) /
                   DNS(qd=DNSQR(qname="aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbA.xf3k2n8s1.exfil-tunnel.tk")))
    packets.append(IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5556, dport=53) /
                   DNS(qd=DNSQR(qname="xkq3j8v1n5m7b2c9z4w6e8r0t5y7u3i1o9p2m4n6b8v0c2x4z6q8w1e3r5t7y9u1i.com")))

    # 6) Cleartext FTP creds
    packets.append(IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=3333, dport=21, flags="PA") /
                   Raw(load=b"USER admin\r\nPASS SuperSecret123\r\n"))

    for i, pkt in enumerate(packets):
        try:
            pkt.time = t + i * 0.01
        except Exception:
            pass
        engine.handle(pkt, ts=t + i * 0.01)

    ok(f"Demo traffic processed: {len(packets)} packets")


def main() -> None:
    args = build_parser().parse_args()
    print(colorize(BANNER, "cyan"))
    warn("Authorized monitoring only — you are responsible for legal compliance.")

    if not (args.live or args.pcap or args.demo):
        build_parser().print_help()
        return

    bus = AlertBus(log_path=args.alert_log, quiet=args.quiet)
    engine = NetSentry(bus, gateway=args.gateway, syn_threshold=args.syn_threshold)

    t0 = time.time()
    if args.demo:
        run_demo(args, engine)
    elif args.pcap:
        run_pcap(args, engine)
    else:
        run_live(args, engine)

    # Summary
    print()
    print(engine.stats.render())
    print(colorize("────── Alert Summary ──────", "bold"))
    summary = engine.summary()
    sev_counts = summary["alerts_by_severity"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in sev_counts:
            tag = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                   "LOW": "cyan", "INFO": "blue"}[sev]
            print(f"  {colorize(sev, tag):<22} {sev_counts[sev]}")
    print(f"  {colorize('TOTAL', 'bold'):<22} {summary['alerts_total']}")
    ok(f"Analyzed {engine.stats.total:,} packets in {round(time.time() - t0, 2)}s")

    if args.report:
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)
        ok(f"Report saved: {args.report}")
    if args.alert_log:
        ok(f"Alert log: {args.alert_log} ({len(bus.alerts)} alerts)")


if __name__ == "__main__":
    main()
