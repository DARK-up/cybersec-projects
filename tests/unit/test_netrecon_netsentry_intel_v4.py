#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit Tests for Phases 7-9:
  - Phase 7: NetRecon Service Version Confidence Engine & OS/CVE accuracy
  - Phase 8: NetSentry Behavioral Baseline, DNS Entropy/Burst, IOC & Timeline Correlation
  - Phase 9: Evidence-based MITRE ATT&CK Mapping & Risk Prioritization
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
for p in (str(ROOT / "netrecon"), str(ROOT / "netsentry"), str(ROOT / "modules"), str(ROOT / "dark")):
    if p not in sys.path:
        sys.path.append(p)

import netrecon as nr  # noqa: E402
import netsentry as ns  # noqa: E402
import mitre_attack as ma  # noqa: E402
import vuln_intel as vi  # noqa: E402


def test_phase7_netrecon_confidence_and_os_accuracy():
    high = nr.score_service_confidence(22, "SSH", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH 8.2p1")
    assert high["confidence"] >= 0.85 and high["confidence_label"] == "Confirmed"
    assert "protocol-fingerprint" in high["signals"] and "semver-extracted" in high["signals"]

    low = nr.score_service_confidence(8080, "unknown", "", "")
    assert low["confidence"] < 0.50 and low["confidence_label"] == "Low"


def test_phase8_netsentry_baseline_dns_ioc_timeline():
    bus = ns.AlertBus(quiet=True)
    eng = ns.NetSentry(bus, gateway="10.0.0.1", syn_threshold=20, ioc_indicators={"198.51.100.77", "evil-c2.example"})

    # Test Shannon entropy helper directly
    assert ns._shannon_entropy("aaaaaaaaaaaaaaaaaaaa") == 0.0
    assert ns._shannon_entropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4") >= 3.6

    # Synthetic alerts fed into bus -> timeline & multi-stage correlation
    bus.emit(ns.Alert(ts=100.0, category="PORT-SCAN", severity="HIGH", src="10.0.0.50", dst="10.0.0.10", detail="SYN scan", confidence=0.9))
    bus.emit(ns.Alert(ts=105.0, category="CLEARTEXT-CRED", severity="HIGH", src="10.0.0.50", dst="10.0.0.10", detail="FTP PASS", confidence=0.9))
    bus.emit(ns.Alert(ts=110.0, category="IOC-MATCH", severity="HIGH", src="10.0.0.50", dst="198.51.100.77", detail="C2 IP", confidence=0.92))

    summary = eng.summary()
    assert summary["alerts_total"] == 3
    assert len(summary["timeline"]) == 3
    assert summary["timeline"][0]["ts"] <= summary["timeline"][2]["ts"]
    assert len(summary["correlated_incidents"]) == 1
    inc = summary["correlated_incidents"][0]
    assert inc["src"] == "10.0.0.50" and inc["severity"] == "CRITICAL" and len(inc["stages"]) == 3

    # Scapy packet-level checks if scapy is available
    if ns.SCAPY_OK:
        from scapy.all import IP, TCP, UDP, DNS, DNSQR  # type: ignore
        for idx in range(5):
            eng.handle(IP(src="10.0.0.99", dst="198.51.100.77") / TCP(dport=80 + idx, flags="S"), ts=200.0 + idx * 0.01)
        assert any(a.category == "IOC-MATCH" and a.dst == "198.51.100.77" for a in bus.alerts)
        eng.handle(
            IP(src="10.0.0.99", dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.exfil.example")),
            ts=201.0,
        )
        assert any(a.category == "DNS-TUNNEL" for a in bus.alerts)


def test_phase9_mitre_attack_mapping_and_confidence_preservation():
    # Info noise without concrete evidence must NOT produce fabricated ATT&CK mapping
    assert ma.map_finding_to_attack({"vuln_type": "Server Banner", "severity": "Info", "evidence": ""}) is None

    sqli_f = {
        "vuln_type": "SQL Injection (Error-Based)",
        "severity": "Critical",
        "url": "https://app.example/item?id=1",
        "evidence": "DBMS signature: MySQL (absent from baseline)",
        "confidence": 0.95,
    }
    scored = vi.score_finding_axes(sqli_f)
    assert scored["confidence"] == 0.95
    assert scored["mitre_attack"]["technique_id"] == "T1190"

    matrix = ma.summarize_attack_matrix([
        scored,
        {"vuln_type": "OS Command Injection", "severity": "Critical", "evidence": "echo canary matched", "confidence": 0.94},
    ])
    tids = {t["technique_id"] for t in matrix["techniques"]}
    assert "T1190" in tids and "T1059" in tids
