#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Cloud Security Auditor — AWS, Azure & GCP configuration, IAM,
Storage, Network Security Group, and IaC (Terraform/JSON/YAML) auditor.

Operates safely on read-only cloud configuration exports, Terraform `.tf`,
CloudFormation/ARM templates, or inline policy documents.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def _finding(provider: str, title: str, severity: str, resource: str,
             evidence: str, remediation: str, cwe: str = "CWE-732") -> dict:
    return {
        "vuln_type": f"[{provider.upper()}] {title}",
        "severity": severity,
        "url": resource,
        "parameter": provider.lower(),
        "how_it_entered": f"Cloud IaC/policy configuration audit on {resource}",
        "evidence": evidence,
        "impact": "Misconfigured cloud permissions or public storage can expose sensitive enterprise data or allow privilege escalation.",
        "remediation": remediation,
        "cwe": cwe,
        "owasp": "A05:2021 Security Misconfiguration",
    }


def audit_cloud_config(provider: str = "aws", content: str = "", target_path: Optional[str] = None,
                       live_profile: Optional[str] = None) -> dict:
    prov = (provider or "aws").strip().lower()
    if prov not in ("aws", "azure", "gcp", "auto"):
        prov = "auto"

    texts: List[tuple[str, str]] = []
    if content and content.strip():
        texts.append(("inline-config", content))
    if target_path:
        p = Path(target_path)
        if p.is_file():
            texts.append((str(p), p.read_text(encoding="utf-8", errors="ignore")))
        elif p.is_dir():
            for fp in sorted(p.rglob("*")):
                if fp.is_file() and fp.suffix.lower() in (".json", ".tf", ".yaml", ".yml"):
                    if fp.stat().st_size <= 2_000_000:
                        texts.append((str(fp), fp.read_text(encoding="utf-8", errors="ignore")))

    findings: List[dict] = []
    resources_checked = len(texts)

    for src, raw in texts:
        low = raw.lower()
        # Auto-detect provider if auto
        cur_prov = prov
        if cur_prov == "auto":
            if "azurerm_" in low or "microsoft.storage" in low or "sharedaccesssignature" in low:
                cur_prov = "azure"
            elif "google_" in low or "iam.gserviceaccount" in low or "allusers" in low:
                cur_prov = "gcp"
            else:
                cur_prov = "aws"

        # 1. JSON IAM Policy / CloudFormation / ARM analysis
        try:
            doc = json.loads(raw)
            stmts = doc.get("Statement") if isinstance(doc, dict) else None
            if isinstance(stmts, list):
                for st in stmts:
                    if not isinstance(st, dict):
                        continue
                    eff = str(st.get("Effect", "")).lower()
                    act = st.get("Action", [])
                    res = st.get("Resource", [])
                    acts = act if isinstance(act, list) else [act]
                    ress = res if isinstance(res, list) else [res]
                    if eff == "allow" and ("*" in acts or "iam:*" in acts) and "*" in ress:
                        findings.append(_finding(
                            cur_prov, "Overly Permissive Wildcard IAM Policy (*:*)", "Critical", src,
                            f"Statement grants Effect=Allow, Action={acts}, Resource={ress}",
                            "Apply least-privilege IAM actions and scope Resource ARNs explicitly.", "CWE-269"
                        ))
                    elif eff == "allow" and any("iam:passrole" in str(a).lower() or "sts:assumerole" in str(a).lower() for a in acts) and "*" in ress:
                        findings.append(_finding(
                            cur_prov, "Unscoped IAM Role Assumption / PassRole", "High", src,
                            f"Action={acts} permitted on Resource=*",
                            "Restrict PassRole/AssumeRole to explicit role ARNs and Condition keys.", "CWE-269"
                        ))
        except Exception:
            pass

        # 2. AWS checks
        if cur_prov in ("aws", "auto"):
            if re.search(r'(acl\s*=\s*["\']public-read|acl\s*=\s*["\']public-read-write|block_public_acls\s*=\s*false)', low):
                findings.append(_finding(
                    "aws", "Public S3 Bucket ACL / Disabled Public Access Block", "Critical", src,
                    "Detected public-read ACL or block_public_acls = false",
                    "Enable S3 Block Public Access (all 4 flags) and enforce private bucket ACLs."
                ))
            if re.search(r'(0\.0\.0\.0/0|::/0)', low) and re.search(r'(from_port\s*=\s*(22|3389)\b|port.*(22|3389))', low):
                findings.append(_finding(
                    "aws", "Security Group Exposes Admin Port (SSH/RDP) to 0.0.0.0/0", "High", src,
                    "Ingress rule opens port 22 or 3389 to the entire internet (0.0.0.0/0)",
                    "Restrict SSH/RDP ingress to VPN/bastion CIDRs or use AWS SSM Session Manager.", "CWE-284"
                ))
            if "aws_s3_bucket" in low and "server_side_encryption" not in low and "kms_master_key_id" not in low:
                findings.append(_finding(
                    "aws", "S3 Bucket Missing Explicit Server-Side Encryption", "Medium", src,
                    "aws_s3_bucket definition lacks server_side_encryption / KMS configuration",
                    "Configure SSE-KMS or SSE-S3 encryption by default on all buckets.", "CWE-311"
                ))
            if re.search(r'AKIA[0-9A-Z]{16}', raw):
                findings.append(_finding(
                    "aws", "Hardcoded AWS Access Key ID in Cloud Config", "Critical", src,
                    "Matched AKIA* AWS static access key pattern",
                    "Remove static IAM keys immediately, rotate them, and use IAM Roles / OIDC.", "CWE-798"
                ))

        # 3. Azure checks
        if cur_prov in ("azure", "auto"):
            if re.search(r'allow_blob_public_access\s*=\s*true|"allowblobpublicaccess"\s*:\s*true', low):
                findings.append(_finding(
                    "azure", "Azure Storage Account Allows Public Blob Access", "Critical", src,
                    "allow_blob_public_access is set to true",
                    "Set allow_blob_public_access = false and enforce RBAC/SAS tokens."
                ))
            if re.search(r'enable_https_traffic_only\s*=\s*false|"supportshttpstrafficonly"\s*:\s*false', low):
                findings.append(_finding(
                    "azure", "Azure Storage HTTPS-Only Transfer Disabled", "High", src,
                    "supportsHttpsTrafficOnly / enable_https_traffic_only = false",
                    "Enforce HTTPS-only traffic on all Azure Storage Accounts.", "CWE-319"
                ))
            if re.search(r'role_definition_name\s*=\s*["\']owner["\']', low):
                findings.append(_finding(
                    "azure", "Broad Azure Owner Role Assignment", "High", src,
                    "Assigned built-in Owner role in IaC",
                    "Prefer granular custom roles or Contributor/Reader scoped to resource level.", "CWE-269"
                ))

        # 4. GCP checks
        if cur_prov in ("gcp", "auto"):
            if "allusers" in low or "allauthenticatedusers" in low:
                findings.append(_finding(
                    "gcp", "Public GCS / IAM Binding (allUsers / allAuthenticatedUsers)", "Critical", src,
                    "Detected allUsers or allAuthenticatedUsers member in IAM/bucket binding",
                    "Remove allUsers/allAuthenticatedUsers and grant access to specific principals."
                ))
            if "roles/owner" in low or "roles/editor" in low:
                findings.append(_finding(
                    "gcp", "Overprivileged GCP Primitive Role (Owner/Editor)", "High", src,
                    "Primitive role roles/owner or roles/editor assigned",
                    "Replace primitive roles with predefined least-privilege IAM roles.", "CWE-269"
                ))
            if '"type": "service_account"' in low and '"private_key"' in low:
                findings.append(_finding(
                    "gcp", "Exposed GCP Service Account Private Key JSON", "Critical", src,
                    "Service account private_key material present in configuration",
                    "Revoke key and migrate workloads to Workload Identity Federation.", "CWE-798"
                ))

    if live_profile and prov in ("aws", "auto"):
        try:
            import boto3  # type: ignore
            sess = boto3.Session(profile_name=live_profile)
            s3 = sess.client("s3")
            for b in (s3.list_buckets().get("Buckets") or [])[:25]:
                bname = b.get("Name", "")
                resources_checked += 1
                try:
                    pab = s3.get_public_access_block(Bucket=bname).get("PublicAccessBlockConfiguration", {})
                    if not all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                        findings.append(_finding("aws", f"Live S3 Bucket Missing Full Public Access Block ({bname})", "High", f"s3://{bname}",
                                                 f"PublicAccessBlockConfiguration={pab}", "Enable all 4 S3 Block Public Access flags."))
                except Exception:
                    pass
        except ImportError:
            findings.append(_finding("aws", "Live AWS Connector Info (boto3 not installed)", "Info", f"profile:{live_profile}",
                                     "Install boto3 for live read-only AWS API checks; IaC/policy offline audit completed.",
                                     "pip install boto3 and attach ReadOnlyAccess IAM profile.", "CWE-200"))
        except Exception as e:
            findings.append(_finding("aws", "Live AWS Profile Audit Skipped", "Info", f"profile:{live_profile}",
                                     f"{type(e).__name__}: {e}", "Verify read-only AWS credentials.", "CWE-200"))

    return {
        "target": target_path or f"{prov}-config",
        "provider": prov,
        "resources_checked": resources_checked,
        "findings": findings,
        "stats": {"urls_crawled": resources_checked, "requests_sent": resources_checked, "duration_s": 0.1},
    }
