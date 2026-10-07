#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Finding knowledge base — CWE / OWASP / CVSS / impact / remediation.

Used by the executive HTML report so every finding (legacy or new) is
enriched to the same standard as a commercial DAST report, without
requiring every scanner module to duplicate the text.
"""
from __future__ import annotations

from typing import Dict

# Each entry is matched against Finding.vuln_type (exact, then prefix).
# Keep remediation actionable. Keep impact honest. Never inflate severity.
CATALOG: Dict[str, dict] = {
    "SQL Injection (Error-Based)": {
        "cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 9.8,
        "impact": "An attacker can read, modify or destroy the database, "
                  "bypass authentication, and in many stacks escalate to "
                  "remote code execution via stacked queries or INTO OUTFILE.",
        "remediation": "Use parameterised queries / prepared statements on "
                       "every SQL call. Never concatenate user input into SQL. "
                       "Apply least-privilege DB accounts and disable stacked "
                       "queries where the driver allows it.",
        "refs": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "SQL Injection (Boolean-Based Blind)": {
        "cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 8.6,
        "impact": "The application answers true/false questions about the "
                  "database. An attacker can dump tables one bit at a time.",
        "remediation": "Same as error-based SQLi: parameterised queries only. "
                       "Do not return different page shapes for true vs false "
                       "SQL predicates.",
        "refs": ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    },
    "SQL Injection (Time-Based Blind)": {
        "cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 8.6,
        "impact": "Even with no error and no content difference, SLEEP/WAITFOR "
                  "lets an attacker extract data by measuring response time.",
        "remediation": "Parameterised queries. Block stacked queries. Alert on "
                       "abnormally slow database statements.",
        "refs": ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    },
    "SQL Injection (Error-Based, URL path)": {
        "cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 9.8,
        "impact": "Path segments are interpolated into SQL — every REST-style "
                  "URL becomes an injection point.",
        "remediation": "Treat path parameters like any other input: bind them, "
                       "never concatenate. Validate they match an expected type.",
        "refs": ["https://owasp.org/www-community/attacks/SQL_Injection"],
    },
    "Reflected XSS (Executable)": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 8.1,
        "impact": "A victim who opens a crafted URL executes attacker JavaScript "
                  "in their session — cookie theft, account takeover, malware.",
        "remediation": "Context-aware output encoding (HTML, attribute, JS, URL). "
                       "Deploy a strict Content-Security-Policy with no unsafe-inline. "
                       "Set cookies HttpOnly + Secure + SameSite.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "Reflected XSS (executable": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 8.1,
        "impact": "Injected input reached an executable HTML/JS context. A victim "
                  "who opens the crafted URL runs attacker script in their session.",
        "remediation": "Encode on output for the exact context (HTML body, attribute, "
                       "JS string, URL). Add CSP without 'unsafe-inline'. HttpOnly cookies.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "XSS — input lands directly in JavaScript source": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 8.1,
        "impact": "User input is concatenated into a script block as code. Any "
                  "JavaScript can be injected with no delimiter breakout required.",
        "remediation": "Never place user data in JS source. Put it in a JSON island "
                       "or data-* attribute and read it with JSON.parse / dataset.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "Stored (persistent) XSS": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 9.6,
        "impact": "The payload is saved and served to every visitor — worms, "
                  "mass session theft, defacement. Highest-impact XSS class.",
        "remediation": "Encode on output, sanitise rich HTML with a well-tested "
                       "library (DOMPurify server-side equivalent), CSP, HttpOnly.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "Stored XSS": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 9.6,
        "impact": "Payload persists and executes for other users.",
        "remediation": "Output encoding + HTML sanitiser + CSP + HttpOnly cookies.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "Potential DOM-based XSS": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 5.4,
        "impact": "Client-side source (location, postMessage, storage) flows into "
                  "a sink (innerHTML, eval, document.write). Confirmed in a browser.",
        "remediation": "Use textContent / setAttribute with safe names. Adopt "
                       "DOMPurify. Avoid eval / new Function / string setTimeout.",
        "refs": ["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
    },
    "Local File Inclusion / Path Traversal": {
        "cwe": "CWE-22", "owasp": "A01:2021 Broken Access Control", "cvss": 8.6,
        "impact": "Arbitrary files are read from the server — /etc/passwd, "
                  "application source, cloud credentials, SSH keys.",
        "remediation": "Never concatenate user input into file paths. Use a "
                       "whitelist of allowed names. Canonicalise and reject '..'.",
        "refs": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    "Server-Side Template Injection (SSTI)": {
        "cwe": "CWE-1336", "owasp": "A03:2021 Injection", "cvss": 9.8,
        "impact": "Template expressions execute on the server. On Jinja/Twig/"
                  "Freemarker this is typically remote code execution.",
        "remediation": "Never render user input as a template. Use a sandboxed "
                       "engine if you must, and keep templates on disk only.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"
                 "latest/4-Web_Application_Security_Testing/"
                 "07-Input_Validation_Testing/"
                 "18-Testing_for_Server_Side_Template_Injection"],
    },
    "OS Command Injection": {
        "cwe": "CWE-78", "owasp": "A03:2021 Injection", "cvss": 9.8,
        "impact": "Attacker-controlled shell metacharacters are executed — "
                  "full host compromise, reverse shells, ransomware.",
        "remediation": "Do not call a shell. Use library APIs / subprocess with "
                       "argument lists (never shell=True). Whitelist arguments.",
        "refs": ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    "XML External Entity (XXE)": {
        "cwe": "CWE-611", "owasp": "A05:2021 Security Misconfiguration", "cvss": 9.1,
        "impact": "The XML parser fetches attacker-specified entities — local "
                  "file disclosure, SSRF, in some parsers denial of service.",
        "remediation": "Disable DTDs and external entities in the XML parser "
                       "(FEATURE_SECURE_PROCESSING / libxml_disable_entity_loader).",
        "refs": ["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
    },
    "Server-Side Request Forgery (SSRF)": {
        "cwe": "CWE-918", "owasp": "A10:2021 SSRF", "cvss": 8.6,
        "impact": "The server fetches attacker URLs — cloud metadata (IAM keys), "
                  "internal admin panels, port scanning of RFC1918.",
        "remediation": "Allow-list schemes and hosts. Block link-local and "
                       "private ranges. Do not follow redirects. Use a locked-down "
                       "egress proxy.",
        "refs": ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
    },
    "Open Redirect": {
        "cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control", "cvss": 6.1,
        "impact": "Used in phishing and OAuth/token-theft chains: the real site "
                  "redirects the victim to an attacker domain.",
        "remediation": "Allow-list redirect targets. Prefer relative paths. Never "
                       "send the user to a raw user-supplied URL.",
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
    },
    "CORS Misconfiguration": {
        "cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration", "cvss": 6.5,
        "impact": "Any website can read authenticated responses — data theft "
                  "from the victim's session.",
        "remediation": "Never reflect Origin blindly. Never combine ACAO:* with "
                       "credentials. Allow-list exact trusted origins.",
        "refs": ["https://portswigger.net/web-security/cors"],
    },
    "CRLF / HTTP Header Injection": {
        "cwe": "CWE-113", "owasp": "A03:2021 Injection", "cvss": 6.1,
        "impact": "Response splitting, cache poisoning, session fixation via "
                  "injected Set-Cookie / Location headers.",
        "remediation": "Strip CR/LF from any value written into headers. Use "
                       "framework header APIs that reject control characters.",
        "refs": ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection"],
    },
    "CSRF — Missing Anti-CSRF Token": {
        "cwe": "CWE-352", "owasp": "A01:2021 Broken Access Control", "cvss": 6.5,
        "impact": "A third-party site can submit state-changing requests as the "
                  "logged-in victim (password change, transfer, email change).",
        "remediation": "Synchroniser tokens on every state-changing request, "
                       "SameSite=Lax/Strict cookies, and check Origin/Referer.",
        "refs": ["https://owasp.org/www-community/attacks/csrf"],
    },
    "Host Header Injection": {
        "cwe": "CWE-644", "owasp": "A05:2021 Security Misconfiguration", "cvss": 6.5,
        "impact": "Password-reset poisoning, cache poisoning, and absolute-URL "
                  "generation that points at an attacker domain.",
        "remediation": "Ignore the Host header for URL generation; use a "
                       "configured canonical hostname. Disallow unmatched vhosts.",
        "refs": ["https://portswigger.net/web-security/host-header"],
    },
    "Weak / Tamperable JWT": {
        "cwe": "CWE-347", "owasp": "A02:2021 Cryptographic Failures", "cvss": 8.1,
        "impact": "Tokens can be forged (alg=none, empty signature) — full "
                  "authentication bypass.",
        "remediation": "Whitelist algorithms (RS256/ES256). Reject alg=none. "
                       "Verify signature on every request. Short TTL + rotation.",
        "refs": ["https://portswigger.net/web-security/jwt"],
    },
    "Default / Weak Credentials": {
        "cwe": "CWE-798", "owasp": "A07:2021 Identification and Authentication Failures",
        "cvss": 9.8,
        "impact": "Trivial account takeover of administrative interfaces.",
        "remediation": "Force unique passwords at first login. Disable default "
                       "accounts. Rate-limit and lock out brute force.",
        "refs": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    },
    "Apache Path Traversal RCE": {
        "cwe": "CWE-22", "owasp": "A06:2021 Vulnerable and Outdated Components",
        "cvss": 9.8,
        "impact": "Unpatched Apache 2.4.49/50 discloses files and can execute "
                  "CGI — remote code execution.",
        "remediation": "Upgrade Apache to a current 2.4.x release immediately.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    "Known-Vulnerable Software Version": {
        "cwe": "CWE-1104", "owasp": "A06:2021 Vulnerable and Outdated Components",
        "cvss": 7.5,
        "impact": "Public exploits exist for the advertised version.",
        "remediation": "Patch or upgrade. Hide server banners where possible.",
        "refs": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
    },
    "Outdated / Vulnerable JS Library": {
        "cwe": "CWE-1104", "owasp": "A06:2021 Vulnerable and Outdated Components",
        "cvss": 6.1,
        "impact": "Known client-side CVEs (XSS, prototype pollution) in a "
                  "library the page loads.",
        "remediation": "Upgrade the library. Pin versions via a lockfile. Scan "
                       "with npm audit / yarn npm audit in CI.",
        "refs": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
    },
    "Sensitive Path Exposed": {
        "cwe": "CWE-538", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5,
        "impact": "Admin panels, backups, source control or secrets are reachable "
                  "without authentication.",
        "remediation": "Block these paths at the reverse proxy. Move backups off "
                       "the web root. Require auth on admin interfaces.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Information File Present": {
        "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "cvss": 5.3,
        "impact": "Robots, sitemaps, traces or dump files leak structure.",
        "remediation": "Do not serve backup/trace files. Restrict robots.txt to "
                       "what you actually want indexed.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Directory Listing Enabled": {
        "cwe": "CWE-548", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "impact": "Anyone can enumerate files — backups, configs, source.",
        "remediation": "Disable autoindex (Options -Indexes / autoindex off) and "
                       "deploy a default document.",
        "refs": ["https://owasp.org/www-community/attacks/Forced_browsing"],
    },
    "Missing Security Header": {
        "cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration", "cvss": 3.1,
        "impact": "Missing defence-in-depth (clickjacking, MIME sniffing, XSS "
                  "impact, HTTPS downgrade).",
        "remediation": "Set HSTS, CSP, X-Content-Type-Options, Referrer-Policy, "
                       "Permissions-Policy and a frame-ancestors policy.",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    "Insecure Cookie Flags": {
        "cwe": "CWE-614", "owasp": "A05:2021 Security Misconfiguration", "cvss": 4.3,
        "impact": "Session cookies can leak over HTTP or to JavaScript (XSS → "
                  "session theft).",
        "remediation": "Set Secure, HttpOnly and SameSite=Lax (Strict for "
                       "session cookies) on every authentication cookie.",
        "refs": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
    },
    "Dangerous HTTP Method Enabled": {
        "cwe": "CWE-650", "owasp": "A05:2021 Security Misconfiguration", "cvss": 5.3,
        "impact": "TRACE/PUT/DELETE/DEBUG may enable XST or unintended writes.",
        "remediation": "Allow only GET/POST/HEAD (and PUT/PATCH/DELETE where the "
                       "API actually needs them) at the reverse proxy.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Server Banner Disclosure": {
        "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "cvss": 3.1,
        "impact": "Exact software versions help an attacker pick exploits.",
        "remediation": "Suppress Server / X-Powered-By. Keep software patched "
                       "regardless of banner hiding.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Technology Disclosure": {
        "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration", "cvss": 2.0,
        "impact": "Stack fingerprinting accelerates targeted attacks.",
        "remediation": "Remove generator meta tags and verbose error pages.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Sensitive Data Exposure": {
        "cwe": "CWE-312", "owasp": "A02:2021 Cryptographic Failures", "cvss": 7.5,
        "impact": "Secrets in HTML/JS (API keys, AWS keys, private tokens) are "
                  "stolen by anyone who views source.",
        "remediation": "Rotate every exposed credential now. Keep secrets on the "
                       "server. Scan repos and bundles in CI.",
        "refs": ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
    },
    "Information Disclosure": {
        "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "cvss": 3.1,
        "impact": "Leaked emails/usernames aid phishing and password spraying.",
        "remediation": "Minimise PII in public pages. Rate-limit user-enumeration "
                       "endpoints.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "GraphQL Introspection Enabled": {
        "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "cvss": 5.3,
        "impact": "The full schema (types, mutations, hidden fields) is public — "
                  "attackers map the API without source code.",
        "remediation": "Disable introspection in production. Add query depth/cost "
                       "limits and authentication on the endpoint.",
        "refs": ["https://owasp.org/www-project-graphql-security/"],
    },
    "OpenAPI / Swagger Spec Exposed": {
        "cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control", "cvss": 5.3,
        "impact": "The complete API surface, including unpublished operations "
                  "and parameter names, is downloadable.",
        "remediation": "Do not serve swagger.json / openapi.json in production, "
                       "or protect it with authentication.",
        "refs": ["https://owasp.org/www-project-api-security/"],
    },
    "Source-Control Metadata Exposed": {
        "cwe": "CWE-527", "owasp": "A01:2021 Broken Access Control", "cvss": 8.6,
        "impact": ".git / .svn on a web root lets an attacker reconstruct the "
                  "entire repository — source, secrets, history.",
        "remediation": "Block /.git and /.svn at the reverse proxy. Rotate any "
                       "credential that ever lived in that repo.",
        "refs": ["https://owasp.org/www-community/vulnerabilities/Unprotected_Directory"],
    },
    "Environment / Secrets File Exposed": {
        "cwe": "CWE-260", "owasp": "A01:2021 Broken Access Control", "cvss": 9.8,
        "impact": "A reachable .env / credentials file is usually full server "
                  "compromise (DB password, cloud keys, app secrets).",
        "remediation": "Remove the file from the web root immediately, rotate "
                       "every value in it, and block dotfiles at the proxy.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Debug / Diagnostic Endpoint Exposed": {
        "cwe": "CWE-489", "owasp": "A05:2021 Security Misconfiguration", "cvss": 7.5,
        "impact": "phpinfo, Spring Actuator, Django DEBUG, Elmah, Trace.axd "
                  "leak configuration, secrets and stack traces.",
        "remediation": "Disable debug in production. Authenticate or firewall "
                       "actuator/admin endpoints.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Backup / Source File Exposed": {
        "cwe": "CWE-530", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5,
        "impact": "editor swap files and .bak copies disclose source code and "
                  "sometimes credentials.",
        "remediation": "Stop editors writing backups into the web root. Block "
                       "*.bak, *~, *.old, *.swp at the reverse proxy.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Cloud Storage Listing Exposed": {
        "cwe": "CWE-538", "owasp": "A01:2021 Broken Access Control", "cvss": 7.5,
        "impact": "S3/GCS listing reveals every object — data breach.",
        "remediation": "Disable public listing. Use bucket policies and signed "
                       "URLs. Audit ACLs.",
        "refs": ["https://owasp.org/www-community/vulnerabilities/Insecure_Storage"],
    },
    "CMS Fingerprint / Attack Surface": {
        "cwe": "CWE-205", "owasp": "A06:2021 Vulnerable and Outdated Components",
        "cvss": 3.1,
        "impact": "A known CMS (WordPress/Drupal/Joomla) with version info "
                  "lets an attacker pick public exploits.",
        "remediation": "Keep the CMS and plugins patched. Hide generator tags. "
                       "Restrict xmlrpc.php / user enumeration.",
        "refs": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "Clickjacking (missing frame protection)": {
        "cwe": "CWE-1021", "owasp": "A04:2021 Insecure Design", "cvss": 4.3,
        "impact": "The page can be framed; UI-redressing tricks users into "
                  "clicking privileged actions.",
        "remediation": "Set Content-Security-Policy frame-ancestors 'self' "
                       "(and X-Frame-Options: DENY as a legacy fallback).",
        "refs": ["https://owasp.org/www-community/attacks/Clickjacking"],
    },
    "Input reflected without execution": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 2.0,
        "impact": "Input is echoed but did not reach an executable context in "
                  "this scan. It becomes XSS if a DOM sink later consumes it.",
        "remediation": "Encode on output anyway. Review any client-side sink "
                       "that reads this parameter.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
    "Stored input reflected without execution": {
        "cwe": "CWE-79", "owasp": "A03:2021 Injection", "cvss": 3.1,
        "impact": "Data persists and is re-served. Sanitisation may differ per "
                  "output location — verify in a browser.",
        "remediation": "Encode every output location independently.",
        "refs": ["https://owasp.org/www-community/attacks/xss/"],
    },
}

_DEFAULT = {
    "cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration", "cvss": 0.0,
    "impact": "See evidence. Confirm exploitability before treating this as "
              "a confirmed vulnerability.",
    "remediation": "Review the affected component, apply the principle of "
                   "least privilege, and retest after the change.",
    "refs": ["https://owasp.org/www-project-top-ten/"],
}


def enrich(vuln_type: str, cvss_hint: float = 0.0) -> dict:
    """Return catalog metadata for a finding type (prefix match allowed)."""
    vt = (vuln_type or "").strip()
    if vt in CATALOG:
        meta = dict(CATALOG[vt])
    else:
        meta = dict(_DEFAULT)
        for key, val in CATALOG.items():
            if vt.startswith(key) or key.startswith(vt) or key.lower() in vt.lower():
                meta = dict(val)
                break
    if cvss_hint and not meta.get("cvss"):
        meta["cvss"] = cvss_hint
    if cvss_hint and meta.get("cvss") == 0.0:
        meta["cvss"] = cvss_hint
    return meta


# OWASP Top 10 2021 — used to draw the coverage matrix in the report.
OWASP_TOP10 = [
    ("A01:2021 Broken Access Control",
     ("Path Traversal", "CSRF", "Open Redirect", "Source-Control",
      "Environment / Secrets", "Sensitive Path", "GraphQL", "OpenAPI",
      "Backup / Source", "Cloud Storage", "Information File", "Directory Listing")),
    ("A02:2021 Cryptographic Failures",
     ("JWT", "Sensitive Data", "Insecure Cookie")),
    ("A03:2021 Injection",
     ("SQL Injection", "XSS", "SSTI", "Command Injection", "CRLF", "XXE")),
    ("A04:2021 Insecure Design",
     ("Clickjacking", "Host Header")),
    ("A05:2021 Security Misconfiguration",
     ("CORS", "Missing Security Header", "Dangerous HTTP Method",
      "Server Banner", "Debug / Diagnostic", "XXE", "Directory Listing")),
    ("A06:2021 Vulnerable and Outdated Components",
     ("Known-Vulnerable", "Outdated / Vulnerable JS", "CMS Fingerprint",
      "Apache Path Traversal")),
    ("A07:2021 Identification and Authentication Failures",
     ("Default / Weak Credentials",)),
    ("A08:2021 Software and Data Integrity Failures",
     ("Outdated / Vulnerable JS",)),
    ("A09:2021 Security Logging and Monitoring Failures",
     ()),  # detection-only; we don't claim to test this
    ("A10:2021 SSRF",
     ("Server-Side Request Forgery",)),
]
