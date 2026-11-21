#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Container & Kubernetes Security Auditor + CycloneDX-style SBOM Generator."""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "modules") not in sys.path:
    sys.path.insert(0, str(ROOT / "modules"))

import vuln_intel as vi  # noqa: E402


def _cfinding(title: str, severity: str, target: str, evidence: str, remediation: str, cwe: str = "CWE-250") -> dict:
    return {
        "vuln_type": f"[Container] {title}",
        "severity": severity,
        "url": target,
        "parameter": "container",
        "how_it_entered": f"Container/Kubernetes/Dependency audit on {target}",
        "evidence": evidence,
        "impact": "Container misconfigurations or vulnerable packages can lead to container escape or supply-chain compromise.",
        "remediation": remediation,
        "cwe": cwe,
        "owasp": "A05:2021 Security Misconfiguration",
    }


def _audit_dockerfile(src: str, text: str) -> tuple[List[dict], List[dict]]:
    findings: List[dict] = []
    components: List[dict] = []
    lines = text.splitlines()
    has_user = False
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        up = s.upper()
        if up.startswith("FROM "):
            img = s.split()[1] if len(s.split()) > 1 else ""
            if ":" not in img or img.endswith(":latest"):
                findings.append(_cfinding(
                    "Unpinned or :latest Base Image", "Medium", f"{src}:{i}",
                    f"Line {i}: {s}", "Pin base images to an immutable version tag and SHA256 digest.", "CWE-1104"
                ))
            name, _, ver = img.partition(":")
            components.append({"name": name, "version": ver or "latest", "type": "container-image", "purl": f"pkg:oci/{name}@{ver or 'latest'}"})
        elif up.startswith("USER "):
            has_user = True
            u = s.split()[1].lower() if len(s.split()) > 1 else ""
            if u in ("root", "0"):
                findings.append(_cfinding(
                    "Container Configured to Run as Root", "High", f"{src}:{i}",
                    f"Line {i}: {s}", "Create and switch to a non-root UID via USER appuser."
                ))
        elif up.startswith("ENV ") or up.startswith("ARG "):
            kv = s.split(None, 1)[1] if len(s.split(None, 1)) > 1 else ""
            m_kv = re.match(r'^([A-Za-z0-9_]+)\s*[= ]\s*(.+)$', kv.strip())
            if m_kv:
                kname, kval = m_kv.group(1), m_kv.group(2).strip().strip('"').strip("'")
                if re.search(r'(?:^|_)(PASSWORD|PASSWD|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN|JWT_SECRET)$', kname, re.I):
                    if kval and not kval.startswith("$") and kval.lower() not in ("", "changeme", "example", "dummy", "placeholder", "none", "null"):
                        findings.append(_cfinding(
                            "Secret Embedded in Dockerfile ENV/ARG", "Critical", f"{src}:{i}",
                            f"Line {i}: non-empty secret assignment to {kname}",
                            "Pass secrets at runtime via orchestrator secrets, never bake into image layers.", "CWE-798"
                        ))
        elif re.search(r'(curl|wget)\s+[^|]+\|\s*(sh|bash)', s, re.I):
            findings.append(_cfinding(
                "Unsafe Remote Script Pipe-to-Shell in RUN", "High", f"{src}:{i}",
                f"Line {i}: {s[:100]}", "Download artifacts with checksum verification instead of piping remote scripts directly to shell.", "CWE-494"
            ))
    if not has_user:
        findings.append(_cfinding(
            "Dockerfile Missing Non-Root USER Directive", "Medium", src,
            "No USER instruction found; container defaults to UID 0 (root)",
            "Add a dedicated non-root user and set USER before CMD/ENTRYPOINT."
        ))
    return findings, components


def _audit_k8s_or_compose(src: str, text: str) -> tuple[List[dict], List[dict]]:
    findings: List[dict] = []
    components: List[dict] = []
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:
        return findings, components

    def _walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            if obj.get("privileged") is True:
                findings.append(_cfinding(
                    "Privileged Container Enabled", "Critical", src,
                    f"{path}.privileged=true", "Set securityContext.privileged: false."
                ))
            if obj.get("hostNetwork") is True or obj.get("hostPID") is True or obj.get("hostIPC") is True:
                findings.append(_cfinding(
                    "Host Namespace Shared with Container (hostNetwork/hostPID/hostIPC)", "High", src,
                    f"{path} enables host namespace sharing", "Disable hostNetwork, hostPID, and hostIPC unless strictly required."
                ))
            if obj.get("allowPrivilegeEscalation") is True:
                findings.append(_cfinding(
                    "allowPrivilegeEscalation Enabled", "High", src,
                    f"{path}.allowPrivilegeEscalation=true", "Set allowPrivilegeEscalation: false."
                ))
            if obj.get("readOnlyRootFilesystem") is False:
                findings.append(_cfinding(
                    "Writable Container Root Filesystem", "Low", src,
                    f"{path}.readOnlyRootFilesystem=false", "Set readOnlyRootFilesystem: true and mount explicit tmpfs/volumes."
                ))
            caps = obj.get("capabilities")
            if isinstance(caps, dict):
                adds = [str(x).upper() for x in (caps.get("add") or [])]
                if any(c in ("ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE") for c in adds):
                    findings.append(_cfinding(
                        "Dangerous Linux Capabilities Granted", "High", src,
                        f"{path}.capabilities.add={adds}", "Drop ALL capabilities and add only minimal required capabilities."
                    ))
            if "image" in obj and isinstance(obj["image"], str):
                img = obj["image"]
                name, _, ver = img.partition(":")
                components.append({"name": name, "version": ver or "latest", "type": "container-image", "purl": f"pkg:oci/{name}@{ver or 'latest'}"})
                if not ver or ver == "latest":
                    findings.append(_cfinding(
                        "Mutable :latest Image Tag in Manifest", "Medium", src,
                        f"image: {img}", "Use explicit semantic tags and image digests."
                    ))
            for k, v in obj.items():
                _walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(obj, list):
            for idx, it in enumerate(obj):
                _walk(it, f"{path}[{idx}]")

    for d in docs:
        if isinstance(d, dict):
            _walk(d)
    return findings, components


def _parse_dependencies(src: str, text: str) -> tuple[List[dict], List[dict]]:
    findings: List[dict] = []
    components: List[dict] = []
    low_src = src.lower()

    if low_src.endswith("requirements.txt") or ("==" in text and "FROM " not in text):
        for ln in text.splitlines():
            s = ln.strip().split("#")[0].strip()
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9.\-_]*)', s)
            if m:
                pkg, ver = m.group(1).lower(), m.group(2)
                cves = vi.match_product_cves(pkg, ver)
                components.append({"name": pkg, "version": ver, "type": "pypi", "purl": f"pkg:pypi/{pkg}@{ver}",
                                   "cves": [c["cve_id"] for c in cves]})
                for c in cves:
                    findings.append(_cfinding(
                        f"Vulnerable Dependency {pkg}=={ver} ({c['cve_id']})", c["severity"], src,
                        f"{pkg}=={ver} < {c['version_lt']} | CVSS {c['cvss_v31']} | {c['summary']}",
                        c["remediation"], "CWE-1395"
                    ))
    elif low_src.endswith("package.json") or '"dependencies"' in text:
        try:
            pj = json.loads(text)
            deps = {}
            deps.update(pj.get("dependencies") or {})
            deps.update(pj.get("devDependencies") or {})
            for pkg, ver_raw in deps.items():
                ver = re.sub(r'^[\^~>=< ]+', '', str(ver_raw))
                cves = vi.match_product_cves(pkg, ver)
                components.append({"name": pkg, "version": ver, "type": "npm", "purl": f"pkg:npm/{pkg}@{ver}",
                                   "cves": [c["cve_id"] for c in cves]})
                for c in cves:
                    findings.append(_cfinding(
                        f"Vulnerable NPM Package {pkg}@{ver} ({c['cve_id']})", c["severity"], src,
                        f"{pkg}@{ver} < {c['version_lt']} | CVSS {c['cvss_v31']} | {c['summary']}",
                        c["remediation"], "CWE-1395"
                    ))
        except Exception:
            pass
    return findings, components


def _audit_docker_inspect(src: str, text: str) -> tuple[List[dict], List[dict]]:
    findings: List[dict] = []
    components: List[dict] = []
    try:
        raw = json.loads(text)
    except Exception:
        return findings, components
    items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    for idx, obj in enumerate(items):
        if not isinstance(obj, dict) or ("HostConfig" not in obj and "Config" not in obj):
            continue
        cfg = obj.get("Config") or {}
        hc = obj.get("HostConfig") or {}
        img = str(cfg.get("Image") or obj.get("RepoTags", ["unknown"])[0] if isinstance(obj.get("RepoTags"), list) else "unknown")
        name, _, ver = img.partition(":")
        components.append({"name": name, "version": ver or "latest", "type": "container-image", "purl": f"pkg:oci/{name}@{ver or 'latest'}"})
        if (cfg.get("User") or "") in ("", "0", "root"):
            findings.append(_cfinding("Docker Inspect: Container Runs as Root", "High", f"{src}[{idx}]",
                                      f"Config.User='{cfg.get('User','')}' on image {img}", "Set non-root User in container image."))
        if hc.get("Privileged") is True:
            findings.append(_cfinding("Docker Inspect: Privileged Container", "Critical", f"{src}[{idx}]",
                                      "HostConfig.Privileged=true", "Remove --privileged flag."))
        if hc.get("NetworkMode") == "host":
            findings.append(_cfinding("Docker Inspect: Host Network Mode", "High", f"{src}[{idx}]",
                                      "HostConfig.NetworkMode='host'", "Use isolated bridge/overlay network."))
        for b in (hc.get("Binds") or []):
            if "docker.sock" in str(b):
                findings.append(_cfinding("Docker Inspect: Docker Socket Mounted Inside Container", "Critical", f"{src}[{idx}]",
                                          f"Bind mount exposes {b}", "Never mount /var/run/docker.sock inside untrusted containers."))
        for ev in (cfg.get("Env") or []):
            if re.search(r'(password|secret|token|api_key)\s*=\s*\S+', str(ev), re.I):
                findings.append(_cfinding("Docker Inspect: Secret in Container Env", "High", f"{src}[{idx}]",
                                          "Sensitive variable present in Config.Env", "Use runtime secret mounts instead of Env.", "CWE-798"))
    return findings, components


def audit_container_and_sbom(content: str = "", target_path: Optional[str] = None, kind: str = "auto") -> dict:
    inputs: List[tuple[str, str]] = []
    if content and content.strip():
        inputs.append((f"inline-{kind}", content))
    if target_path:
        p = Path(target_path)
        if p.is_file():
            inputs.append((str(p), p.read_text(encoding="utf-8", errors="ignore")))
        elif p.is_dir():
            for fp in sorted(p.rglob("*")):
                if fp.is_file() and (
                    fp.name.lower().startswith("dockerfile")
                    or fp.name.lower() in ("requirements.txt", "package.json", "docker-compose.yml", "docker-compose.yaml")
                    or fp.suffix.lower() in (".yaml", ".yml")
                ):
                    if fp.stat().st_size <= 2_000_000:
                        inputs.append((str(fp), fp.read_text(encoding="utf-8", errors="ignore")))

    findings: List[dict] = []
    components: List[dict] = []
    for src, txt in inputs:
        low = src.lower()
        if "dockerfile" in low or ("FROM " in txt and any(k in txt for k in ("RUN ", "USER ", "ENV ", "CMD ", "COPY ", "ENTRYPOINT "))):
            fs, cs = _audit_dockerfile(src, txt)
            findings.extend(fs); components.extend(cs)
        if low.endswith((".yml", ".yaml")) or "kind:" in txt or "services:" in txt:
            fs, cs = _audit_k8s_or_compose(src, txt)
            findings.extend(fs); components.extend(cs)
        if '"HostConfig"' in txt or '"Config"' in txt:
            fs, cs = _audit_docker_inspect(src, txt)
            findings.extend(fs); components.extend(cs)
        fs, cs = _parse_dependencies(src, txt)
        findings.extend(fs); components.extend(cs)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {"tools": [{"name": "DARK Container & SBOM Auditor"}]},
        "components": components,
    }
    return {
        "target": target_path or "container-audit",
        "files_scanned": len(inputs),
        "findings": findings,
        "sbom": sbom,
        "stats": {"urls_crawled": len(inputs), "requests_sent": len(components), "duration_s": 0.1},
    }
