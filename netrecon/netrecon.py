#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRecon v2.0 - Advanced Asynchronous Network Reconnaissance Framework
======================================================================
Author : CyberSec Portfolio Project (Red Team Track)
Purpose: Authorized penetration testing / network auditing ONLY.

Features
--------
* Async TCP connect scanner (high concurrency via asyncio)
* CIDR / IP range / hostname / port-range & top-ports support
* Service fingerprinting: banner grabbing + active protocol probes
* OS hinting from service banners (SSH/OpenSSH, IIS, Samba, etc.)
* Host discovery sweep (TCP ping on multiple probe ports)
* Timing profiles: sneaky / normal / aggressive / insane
* Port randomization + per-host throttling (evasion friendly)
* Multi-format reporting: colored console, JSON, HTML
* Zero third-party dependencies (pure standard library)

LEGAL: Only scan systems you own or have explicit written permission
       to test. Unauthorized scanning is illegal.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import random
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# ----------------------------------------------------------------------------
# Banner styling
# ----------------------------------------------------------------------------
BANNER = r"""
   __  __      _   ____                      
  |  \/  | ___| |_|  _ \ ___  ___ ___  _ __  
  | |\/| |/ _ \ __| |_) / _ \/ __/ _ \| '_ \ 
  | |  | |  __/ |_|  _ <  __/ (_| (_) | | | |
  |_|  |_|\___|\__|_| \_\___|\___\___/|_| |_|
  Advanced Network Reconnaissance Framework v2.0
"""

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "cyan": "\033[96m", "bold": "\033[1m",
    "dim": "\033[2m", "reset": "\033[0m",
}


def colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{C.get(color, '')}{text}{C['reset']}"


def info(msg: str) -> None:
    print(f"{colorize('[*]', 'blue')} {msg}")


def ok(msg: str) -> None:
    print(f"{colorize('[+]', 'green')} {msg}")


def warn(msg: str) -> None:
    print(f"{colorize('[!]', 'yellow')} {msg}")


def fail(msg: str) -> None:
    print(f"{colorize('[-]', 'red')} {msg}")


# ----------------------------------------------------------------------------
# Fingerprint database: (probe_payload, regex/signature) -> service/version
# ----------------------------------------------------------------------------
FINGERPRINT_DB: List[Tuple[str, bytes, re.Pattern]] = [
    # (name, probe to send, response regex)
    ("SSH",    b"",                re.compile(rb"SSH-([\d.]+)-([\w.\-]+)")),
    ("FTP",    b"",                re.compile(rb"^220[ \-]([\w.\-]+).*FTP", re.I | re.M)),
    ("SMTP",   b"EHLO netrecon\r\n", re.compile(rb"^220[ \-]([\w.\-]+)", re.I | re.M)),
    ("POP3",   b"",                re.compile(rb"^\+OK.*", re.I | re.M)),
    ("IMAP",   b"",                re.compile(rb"^\* OK.*IMAP", re.I | re.M)),
    ("MySQL",  b"",                re.compile(rb"mysql_native_password|MariaDB", re.I)),
    ("Redis",  b"PING\r\n",        re.compile(rb"\+PONG|-NOAUTH|DENIED", re.I)),
    ("Memcached", b"stats\r\n",    re.compile(rb"STAT pid", re.I)),
    ("MongoDB", b"",               re.compile(rb"ismaster|MongoDB", re.I)),
    ("RDP",    b"",                re.compile(rb"\x03\x00.{2}\x0e", re.S)),
    ("VNC",    b"RFB ",            re.compile(rb"RFB [\d.]+")),
    ("IRC",    b"",                re.compile(rb"NOTICE \* :.*(?:irc|Unreal|InspIRCd)", re.I)),
    ("LDAP",   b"",                re.compile(rb"LDAP", re.I)),
    ("SIP",    b"OPTIONS sip:netrecon@target SIP/2.0\r\n\r\n",
               re.compile(rb"SIP/2\.0|Server: ", re.I)),
    ("DNS-TCP", b"",               re.compile(rb".")),  # handled separately
]

HTTP_PROBE = (
    b"HEAD / HTTP/1.0\r\n"
    b"Host: {host}\r\n"
    b"User-Agent: NetRecon/2.0 (Authorized Security Testing)\r\n"
    b"Accept: */*\r\n"
    b"Connection: close\r\n\r\n"
)

HTTP_SERVER_RE = re.compile(rb"Server:\s*([^\r\n]+)", re.I)
HTTP_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
HTTP_POWERED_RE = re.compile(rb"X-Powered-By:\s*([^\r\n]+)", re.I)

OS_HINTS = [
    (re.compile(r"OpenSSH.*?(Ubuntu|Debian)", re.I), "Linux (Ubuntu/Debian)"),
    (re.compile(r"OpenSSH", re.I), "Linux/Unix (OpenSSH)"),
    (re.compile(r"Microsoft-IIS|Windows Server|Microsoft HTTPAPI", re.I), "Microsoft Windows"),
    (re.compile(r"Apache.*?(Ubuntu|Debian)", re.I), "Linux (Apache)"),
    (re.compile(r"nginx", re.I), "Linux/Unix (nginx)"),
    (re.compile(r"ProFTPD|vsftpd", re.I), "Linux/Unix (FTP server)"),
    (re.compile(r"Samba|SMB", re.I), "Linux/Unix or Windows (Samba)"),
    (re.compile(r"cisco|Cisco", re.I), "Cisco IOS / Network appliance"),
    (re.compile(r"MikroTik|RouterOS", re.I), "MikroTik RouterOS"),
]

# Nmap-inspired top 100 TCP ports
TOP_PORTS = [
    80, 443, 22, 21, 25, 53, 110, 139, 143, 445, 3389, 3306, 5432, 8080,
    1433, 1521, 5900, 6379, 27017, 111, 135, 514, 587, 88, 137, 138, 512,
    513, 23, 389, 636, 873, 993, 995, 1723, 2049, 3268, 3269, 5800, 5985,
    5986, 6000, 6001, 6667, 8000, 8008, 8081, 8443, 8888, 9090, 9200,
    9300, 10000, 11211, 27018, 27019, 50000, 50070, 61616, 5672, 15672,
    4369, 25672, 445, 593, 1025, 1026, 1027, 1028, 1029, 1433, 1720,
    2000, 2001, 2049, 2100, 2222, 2383, 2701, 3000, 3001, 3128, 3260,
    3307, 3388, 4000, 4001, 4443, 4444, 4500, 4899, 5000, 5001, 5060,
    5222, 5353, 5357, 5433, 5631, 5666, 5801, 5901, 6002, 6378, 6646,
    7001, 7070, 8009, 8010, 8082, 8083, 8088, 8090, 8181, 8200, 8444,
    8880, 9000, 9001, 9091, 9100, 9443, 9999, 10250, 15672, 27015, 27016,
]

# Timing profiles: (concurrency, timeout, per-host delay)
TIMING = {
    "sneaky":     (50,  3.0, 0.30),
    "normal":     (300, 1.2, 0.05),
    "aggressive": (800, 0.8, 0.0),
    "insane":     (2000, 0.5, 0.0),
}


# ----------------------------------------------------------------------------
# Data models
# ----------------------------------------------------------------------------
@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    banner: str = ""
    version: str = ""
    extra: Dict = field(default_factory=dict)


@dataclass
class HostResult:
    host: str
    hostname: str = ""
    alive: bool = False
    os_hint: str = "Unknown"
    ports: List[PortResult] = field(default_factory=list)
    scan_time: float = 0.0

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]


# ----------------------------------------------------------------------------
# Target parsing
# ----------------------------------------------------------------------------
def parse_targets(raw: List[str]) -> List[str]:
    """Expand hostnames, single IPs, CIDR blocks and dash ranges."""
    hosts: List[str] = []
    for token in raw:
        token = token.strip()
        if not token:
            continue
        # CIDR
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                hosts.extend(str(h) for h in net.hosts())
                continue
            except ValueError:
                fail(f"Invalid CIDR: {token}")
                continue
        # Dash range 192.168.1.1-50  or  192.168.1.1-192.168.1.50
        m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)\s*-\s*(\d+)$", token)
        if m:
            base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            if start <= end <= 255:
                hosts.extend(f"{base}{i}" for i in range(start, end + 1))
            continue
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$", token)
        if m:
            try:
                a = int(ipaddress.ip_address(m.group(1)))
                b = int(ipaddress.ip_address(m.group(2)))
                if a <= b:
                    hosts.extend(str(ipaddress.ip_address(i)) for i in range(a, b + 1))
                continue
            except ValueError:
                pass
        # Hostname
        hosts.append(token)
    # De-dup preserving order
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def parse_ports(spec: str) -> List[int]:
    """'22,80,443', '1-1024', 'top100', 'top:20', 'all' -> list of ports."""
    spec = spec.strip().lower()
    if spec in ("all", "*"):
        return list(range(1, 65536))
    if spec.startswith("top"):
        n = 100
        if ":" in spec:
            try:
                n = int(spec.split(":")[1])
            except ValueError:
                n = 100
        return TOP_PORTS[:n]
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
                ports.update(range(max(1, lo), min(65535, hi) + 1))
            except ValueError:
                fail(f"Bad port range: {part}")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                fail(f"Bad port: {part}")
    return sorted(ports)


# ----------------------------------------------------------------------------
# Core scanner engine
# ----------------------------------------------------------------------------
class NetRecon:
    def __init__(
        self,
        targets: List[str],
        ports: List[int],
        timing: str = "normal",
        probe: bool = True,
        discover: bool = False,
        resolve: bool = True,
        randomize: bool = True,
    ):
        self.targets = targets
        self.ports = ports
        self.concurrency, self.timeout, self.delay = TIMING[timing]
        self.timing = timing
        self.probe = probe
        self.discover = discover
        self.resolve = resolve
        self.randomize = randomize
        self.results: List[HostResult] = []
        self.start_ts = 0.0

    # -- host discovery -----------------------------------------------------
    async def _tcp_probe(self, host: str, port: int, sem: asyncio.Semaphore) -> bool:
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except Exception:
                return False

    async def discover_host(self, host: str) -> bool:
        sem = asyncio.Semaphore(20)
        probe_ports = [80, 443, 22, 445, 139, 3389, 8080, 53, 135, 25]
        tasks = [self._tcp_probe(host, p, sem) for p in probe_ports]
        results = await asyncio.gather(*tasks)
        return any(results)

    # -- banner + fingerprint ----------------------------------------------
    async def grab_banner(self, host: str, port: int, service_hint: str = "") -> Tuple[str, str, str]:
        """Returns (service, banner_text, version)."""
        banner_text, service, version = "", "", ""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
        except Exception:
            return service, banner_text, version

        try:
            # Some services speak first (SSH, FTP, SMTP, POP3, IMAP, RDP...)
            first = True
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=min(self.timeout, 1.2))
            except asyncio.TimeoutError:
                data = b""

            if data:
                banner_text = data.decode("utf-8", errors="replace").strip()[:400]
                for name, _probe, rx in FINGERPRINT_DB:
                    m = rx.search(data)
                    if m:
                        service = name
                        if m.groups():
                            version = " ".join(g.decode("utf-8", "replace") for g in m.groups() if g)
                        break

            # HTTP probe (always, cheap and informative)
            if not service or service in ("HTTP", ""):
                host_hdr = host
                try:
                    host_hdr = socket.gethostbyaddr(host)[0]
                except Exception:
                    pass
                writer.write(HTTP_PROBE.replace(b"{host}", host_hdr.encode()))
                await writer.drain()
                try:
                    resp = await asyncio.wait_for(reader.read(2048), timeout=min(self.timeout, 1.5))
                except asyncio.TimeoutError:
                    resp = b""

                if resp.startswith(b"HTTP/") or b"HTTP/1." in resp[:32]:
                    service = "HTTP/HTTPS"
                    srv = HTTP_SERVER_RE.search(resp)
                    pw = HTTP_POWERED_RE.search(resp)
                    title = HTTP_TITLE_RE.search(resp)
                    if srv:
                        version = srv.group(1).decode("utf-8", "replace").strip()
                    extra = []
                    if pw:
                        extra.append("X-Powered-By: " + pw.group(1).decode("utf-8", "replace").strip())
                    if title:
                        extra.append("title=" + title.group(1).decode("utf-8", "replace").strip()[:60])
                    banner_text = " | ".join(extra) if extra else banner_text

            # Active protocol probes for unknown ports
            if not service and self.probe:
                for name, probe, rx in FINGERPRINT_DB:
                    if not probe:
                        continue
                    try:
                        writer.write(probe)
                        await writer.drain()
                        r = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                    except Exception:
                        continue
                    if r and rx.search(r):
                        service = name
                        banner_text = r.decode("utf-8", errors="replace").strip()[:400]
                        break

        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if not service:
            service = "unknown"
        return service, banner_text, version

    @staticmethod
    def os_hint_from_banner(banner: str, version: str) -> str:
        blob = f"{banner} {version}"
        for rx, hint in OS_HINTS:
            if rx.search(blob):
                return hint
        return "Unknown"

    # -- single port check ---------------------------------------------------
    async def scan_port(self, host: str, port: int, sem: asyncio.Semaphore) -> Optional[PortResult]:
        async with sem:
            t0 = time.monotonic()
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

            pr = PortResult(port=port, state="open")
            # RST vs open: open_connection succeeded => open
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if self.probe:
                service, banner, version = await self.grab_banner(host, port)
                pr.service, pr.banner, pr.version = service, banner, version
            else:
                pr.service = "unknown"
            pr.extra["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
            return pr

    # -- full host scan ------------------------------------------------------
    async def scan_host(self, host: str) -> HostResult:
        hr = HostResult(host=host)

        if self.resolve:
            try:
                hr.hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                hr.hostname = ""

        if self.discover:
            info(f"Discovering {host} ...")
            hr.alive = await self.discover_host(host)
            if not hr.alive:
                warn(f"{host} seems down (no TCP probe answered)")
                return hr
        else:
            hr.alive = True

        t0 = time.monotonic()
        sem = asyncio.Semaphore(self.concurrency)
        ports = self.ports[:]
        if self.randomize:
            random.shuffle(ports)

        tasks = [self.scan_port(host, p, sem) for p in ports]
        # Process in chunks to show progress and avoid giant gather lists
        chunk = max(self.concurrency, 256)
        found = 0
        for i in range(0, len(tasks), chunk):
            batch = tasks[i:i + chunk]
            for pr in await asyncio.gather(*batch):
                if pr:
                    hr.ports.append(pr)
                    found += 1
                    self.print_port(host, pr)
            if len(tasks) > 512:
                done = min(i + chunk, len(tasks))
                sys.stdout.write(
                    f"\r{colorize('[~]', 'cyan')} {host}: {done}/{len(tasks)} ports "
                    f"({found} open)   "
                )
                sys.stdout.flush()
        if len(tasks) > 512:
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()

        hr.ports.sort(key=lambda p: p.port)
        for pr in hr.ports:
            hint = self.os_hint_from_banner(pr.banner, pr.version)
            if hint != "Unknown" and hr.os_hint == "Unknown":
                hr.os_hint = hint
        hr.scan_time = round(time.monotonic() - t0, 2)
        return hr

    def print_port(self, host: str, pr: PortResult) -> None:
        svc = pr.service or "unknown"
        ver = f" ({pr.version})" if pr.version else ""
        ban = f" | {pr.banner[:70]}" if pr.banner else ""
        print(
            f"{colorize('[+]', 'green')} {host}:{pr.port:<6} "
            f"{colorize('open', 'green')}  {colorize(svc + ver, 'cyan')}{colorize(ban, 'dim')}"
        )

    # -- orchestration --------------------------------------------------------
    async def run(self) -> List[HostResult]:
        self.start_ts = time.time()
        info(f"Targets: {len(self.targets)} | Ports/host: {len(self.ports)} | "
             f"Timing: {self.timing} | Concurrency: {self.concurrency}")
        for host in self.targets:
            print(colorize(f"\n=== Scanning host {host} ===", "bold"))
            hr = await self.scan_host(host)
            self.results.append(hr)
            if hr.open_ports:
                ok(f"Host {host}: {len(hr.open_ports)} open port(s) in {hr.scan_time}s "
                   f"(OS hint: {hr.os_hint})")
        return self.results

    # -- reporting ------------------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "tool": "NetRecon v2.0",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "duration_s": round(time.time() - self.start_ts, 2),
            "timing": self.timing,
            "ports_per_host": len(self.ports),
            "hosts": [
                {
                    **{k: v for k, v in asdict(h).items() if k != "ports"},
                    "open_ports": [asdict(p) for p in h.open_ports],
                }
                for h in self.results
            ],
        }

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        ok(f"JSON report saved: {path}")

    def save_html(self, path: str) -> None:
        rows = []
        for h in self.results:
            for p in h.open_ports:
                rows.append(
                    f"<tr><td>{h.host}</td><td>{h.hostname or '-'}</td><td>{p.port}</td>"
                    f"<td>{p.service}</td><td>{p.version or '-'}</td>"
                    f"<td><code>{(p.banner or '-')[:80]}</code></td></tr>"
                )
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>NetRecon Report</title>
<style>
body{{font-family:Segoe UI,Arial;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff}} table{{border-collapse:collapse;width:100%;margin-top:16px}}
th,td{{border:1px solid #30363d;padding:8px 10px;text-align:left;font-size:14px}}
th{{background:#161b22;color:#58a6ff}} tr:nth-child(even){{background:#161b22}}
code{{color:#7ee787}} .meta{{color:#8b949e}}
</style></head><body>
<h1>NetRecon v2.0 &mdash; Scan Report</h1>
<p class="meta">Generated: {datetime.now(timezone.utc).isoformat()} |
Targets: {len(self.targets)} | Timing: {self.timing}</p>
<table><tr><th>Host</th><th>Hostname</th><th>Port</th><th>Service</th>
<th>Version</th><th>Banner</th></tr>
{''.join(rows) if rows else '<tr><td colspan=6>No open ports found</td></tr>'}
</table></body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        ok(f"HTML report saved: {path}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netrecon",
        description="NetRecon v2.0 - Advanced Async Network Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 netrecon.py -t 192.168.1.0/24 -p top100\n"
            "  python3 netrecon.py -t scanme.example.com -p 1-5000 -T aggressive\n"
            "  python3 netrecon.py -t 10.0.0.5 -p 22,80,443,3306 --no-probe\n"
            "  python3 netrecon.py -t 192.168.1.1-50 -p all --discover\n\n"
            "LEGAL: Use only on systems you are authorized to test."
        ),
    )
    p.add_argument("-t", "--targets", nargs="+", required=True,
                   help="Hosts / CIDR / IP ranges (e.g. 192.168.1.0/24 10.0.0.1-20)")
    p.add_argument("-p", "--ports", default="top100",
                   help="Ports: '22,80,443' | '1-1024' | 'top100' | 'top:20' | 'all' [default: top100]")
    p.add_argument("-T", "--timing", choices=list(TIMING), default="normal",
                   help="Timing profile [default: normal]")
    p.add_argument("--discover", action="store_true", help="TCP ping sweep before scanning")
    p.add_argument("--no-probe", action="store_true", help="Skip banner grabbing / fingerprinting")
    p.add_argument("--no-resolve", action="store_true", help="Skip reverse DNS")
    p.add_argument("--ordered", action="store_true", help="Scan ports in order (no shuffle)")
    p.add_argument("--json", metavar="FILE", help="Save JSON report")
    p.add_argument("--html", metavar="FILE", help="Save HTML report")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    print(colorize(BANNER, "cyan"))
    warn("Authorized testing only — you are responsible for legal compliance.")

    targets = parse_targets(args.targets)
    if not targets:
        fail("No valid targets.")
        sys.exit(1)
    ports = parse_ports(args.ports)
    if not ports:
        fail("No valid ports.")
        sys.exit(1)

    scanner = NetRecon(
        targets=targets,
        ports=ports,
        timing=args.timing,
        probe=not args.no_probe,
        discover=args.discover,
        resolve=not args.no_resolve,
        randomize=not args.ordered,
    )

    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        warn("\nScan interrupted by user.")
    finally:
        print(colorize("\n────── Summary ──────", "bold"))
        total_open = sum(len(h.open_ports) for h in scanner.results)
        for h in scanner.results:
            state = "UP" if h.alive else "DOWN"
            print(f"  {h.host:<18} {state:<5} open={len(h.open_ports):<3} os_hint={h.os_hint}")
        ok(f"Total open ports: {total_open} | Duration: "
           f"{round(time.time() - scanner.start_ts, 2)}s")

        if args.json:
            scanner.save_json(args.json)
        if args.html:
            scanner.save_html(args.html)


if __name__ == "__main__":
    main()
