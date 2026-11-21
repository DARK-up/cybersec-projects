# DARK 5-Axis Risk Scoring Documentation

## Overview
Every finding receives a transparent, configurable Risk Score on a **0–100** scale computed from five independent axes (each normalized `0.0–1.0`):

1. **Severity (`severity`, default weight `0.28`)**: Derived from CVSS v3.1 / v4.0 base score or finding severity (`Critical=1.0, High=0.82, Medium=0.55, Low=0.30, Info=0.10`).
2. **Confidence (`confidence`, default weight `0.16`)**: Quality of verification proof (concrete exploit/data extraction vs single marker/error hint).
3. **Exploitability (`exploitability`, default weight `0.24`)**: Combines FIRST EPSS probability and CISA KEV active exploitation status (`+0.35` KEV boost).
4. **Business Impact (`business_impact`, default weight `0.18`)**: Driven by asset criticality (`critical=1.0, high=0.85, medium=0.60, low=0.35`) and business context (`payment/auth/prod` boost).
5. **Exposure (`exposure`, default weight `0.14`)**: Internet-facing asset exposure (`1.0` if exposed, `0.45` if internal).

## Formula
```text
risk_score = round((w_sev * severity + w_conf * confidence + w_expl * exploitability + w_imp * business_impact + w_exp * exposure) * 100, 1)
```
Where weights are normalized to sum to `1.0` and can be inspected or tuned live via `GET / POST /api/intel/risk/weights`.

## Attack Path Correlation
When multiple findings coexist on the same target (for example, exposed credentials/secrets paired with injection, missing auth, or weak admin surface), `vuln_intel.prioritize_findings` surfaces correlated attack paths with boosted combined risk.
