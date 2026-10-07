#!/usr/bin/env python3
"""Unit tests for the context classifier + the execution verifier.

These are the tests that protect the zero-false-positive guarantee: a payload
reflected inside a <textarea>, a comment or an encoded attribute must NOT be
reported as executable.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import xss_deep as x


class Resp:
    def __init__(self, text, ct="text/html"):
        self.text = text
        self.headers = {"Content-Type": ct}


CASES = [
    ("<p>MARK</p>",                              "html_text",        ""),
    ('<input value="MARK">',                     "attr:value:dq",    "value"),
    ("<input value=MARK>",                       "attr:value:unq",   "value"),
    ("<input value='MARK'>",                     "attr:value:sq",    "value"),
    ('<a href="MARK">x</a>',                     "attr:href:dq",     "href"),
    ('<script>var x = "MARK";</script>',         "script_str_dq",    ""),
    ("<script>var x = 'MARK';</script>",         "script_str_sq",    ""),
    ("<script>var x = `MARK`;</script>",         "script_tpl",       ""),
    ("<script>var x = MARK;</script>",           "script_js",        ""),
    ("<script>// MARK\n</script>",               "script_comment",   ""),
    ("<!-- MARK -->",                            "html_comment",     ""),
    ("<textarea>MARK</textarea>",                "rawtext:textarea", "textarea"),
    ("<title>MARK</title>",                      "rawtext:title",    "title"),
    ("<style>a{color:MARK}</style>",             "style_css",        ""),
    ('<div onclick="MARK">x</div>',              "attr:onclick:dq",  "onclick"),
    ('<img src="x" onerror=MARK>',               "attr:onerror:unq", "onerror"),
]

print("=" * 74)
print("CONTEXT CLASSIFICATION")
print("=" * 74)
fails = 0
for body, want, want_meta in CASES:
    cm = x.ContextMap(body)
    hits = cm.find("MARK")
    got, meta = (hits[0][1], hits[0][2]) if hits else ("<NOT FOUND>", "")
    ok = got == want and (not want_meta or meta == want_meta)
    if not ok:
        fails += 1
    print(f"  {'OK ' if ok else 'BAD'}  {body[:44]:<46} -> {got:<20} (want {want})")

# JSON
cm = x.ContextMap('{"name":"MARK"}', "application/json")
print(f"  {'OK ' if cm.is_json else 'BAD'}  JSON content-type detected -> is_json={cm.is_json}")

print()
print("=" * 74)
print("EXECUTION VERIFICATION (the zero-FP guarantee)")
print("=" * 74)


class Dummy:
    def __init__(self): self.client = None
    add = staticmethod(lambda **kw: None)


class FakeScanner(x.DeepXssScanner):
    def __init__(self):
        self.client = type("C", (), {"module": ""})()
        self.state = Dummy()
        self.F = None
        self.quiet = True
        self._log = lambda *a: None


sc = FakeScanner()
M = "MARK"
VERIFY_CASES = [
    # (response body, marker, kind, expected_vuln?, why)
    ("<div><script>var MARK=1</script></div>", True,
     "script lands in JS source"),
    ("<div><img src=x onerror=var MARK=1></div>", True,
     "event handler attribute created"),
    ('<a href="javascript:var MARK=1">c</a>', True,
     "javascript: URI in navigable attr"),
    ("<textarea><script>var MARK=1</script></textarea>", False,
     "MUST NOT FIRE: trapped inside <textarea>"),
    ("<!--<script>var MARK=1</script>-->", False,
     "MUST NOT FIRE: trapped inside an HTML comment"),
    ("<div>&lt;script&gt;var MARK=1&lt;/script&gt;</div>", False,
     "MUST NOT FIRE: HTML-encoded reflection"),
    ('<input value="<script>var MARK=1</script>">', False,
     "MUST NOT FIRE: inside a quoted attribute value"),
    ('<script>var s = "<script>var MARK=1</script>";</script>', False,
     "MUST NOT FIRE: inside a JS string literal"),
    ("<title><script>var MARK=1</script></title>", False,
     "MUST NOT FIRE: trapped inside <title>"),
    ("MARK", False,
     "MUST NOT FIRE: plain text reflection, no construct"),
]
for body, expect_vuln, why in VERIFY_CASES:
    v = sc._verify(Resp(body), M, "script", body)
    got = bool(v)
    ok = got == expect_vuln
    if not ok:
        fails += 1
    tag = "OK " if ok else "BAD"
    detail = f"{v[0]} / {v[1]}" if v else "no finding"
    print(f"  {tag}  {why}")
    print(f"        {body[:60]:<62} -> {detail}")

print()
print("=" * 74)
print("CONTENT-TYPE AWARENESS (JSON/API responses must not be called XSS)")
print("=" * 74)
CT_CASES = [
    ('{"q":"<script>var MARK=1</script>"}', "application/json", False,
     "MUST NOT FIRE: application/json is not rendered as HTML"),
    ('{"q":"<script>var MARK=1</script>"}', "application/json; charset=utf-8", False,
     "MUST NOT FIRE: application/json with charset"),
    ("<script>var MARK=1</script>", "text/plain", False,
     "MUST NOT FIRE: text/plain is not rendered as HTML"),
    ('<x>&lt;script&gt;var MARK=1</x>', "application/xml", False,
     "MUST NOT FIRE: XML response"),
    ('{"q":"<script>var MARK=1</script>"}', "text/html", True,
     "MUST FIRE: JSON-shaped body served as text/html IS rendered by browsers"),
    ("<script>var MARK=1</script>", "", True,
     "MUST FIRE: no Content-Type -> browsers may sniff as HTML"),
]
for body, ct, expect_vuln, why in CT_CASES:
    v = sc._verify(Resp(body, ct), M, "script", body)
    got = bool(v)
    ok = got == expect_vuln
    if not ok:
        fails += 1
    print(f"  {'OK ' if ok else 'BAD'}  {why}")
    print(f"        ct={ct or '(none)':<32} -> {('FIRED ' + v[0]) if v else 'no finding'}")

print()
print("=" * 74)
print("MARKER EMBEDDING INTO COMMUNITY VECTORS")
print("=" * 74)
EMBED_CASES = [
    "<script>alert(1)</script>",
    '<img src=x onerror=alert("XSS")>',
    "<svg onload=prompt(1)>",
    "<script>document.write(location.hash)</script>",
    '<a href="javascript:confirm(1)">x</a>',
    "plain string with no vector",
]
for raw in EMBED_CASES:
    sent, tagged = x.embed_marker(raw, M)
    ok = tagged == ("vector" not in raw)
    if not ok:
        fails += 1
    print(f"  {'OK ' if ok else 'BAD'}  tagged={tagged!s:<5} {raw[:40]:<42} -> {sent[:52]}")

lib = x.community_payloads(10 ** 9)
taggable = sum(1 for p in lib if x.embed_marker(p, M)[1])
print(f"  community vectors: {len(lib)} | verifiable (marker-embeddable): {taggable}")
if taggable < len(lib) * 0.5:
    fails += 1
    print("  BAD  too few community vectors can be verified")

print()
print("=" * 74)
print("CAPABILITY PROBE")
print("=" * 74)
mk = "dkx0001"
probe = x.caps_probe_string(mk)
# server that encodes < > but keeps the rest
enc = probe.replace("<", "&lt;").replace(">", "&gt;")
caps = x.parse_caps(enc, probe)
survived = sorted(c for c, ok in caps.items() if ok)
blocked = sorted(c for c, ok in caps.items() if not ok)
print(f"  survived: {survived}")
print(f"  blocked : {blocked}")
ok = ("<" in blocked) and (">" in blocked) and ('"' in survived)
if not ok:
    fails += 1
print(f"  {'OK ' if ok else 'BAD'}  encoder correctly detected")

sel = [p for p in x.PAYLOAD_LIBRARY
       if p.contexts & {"attr_dq"} and p.needs <= set(survived)]
print(f"  payloads selectable for attr_dq with these caps: {len(sel)}")
print(f"    e.g. {sel[0].tpl if sel else '-'}")
if not sel:
    fails += 1

print()
print("RESULT:", "ALL TESTS PASSED" if fails == 0 else f"{fails} FAILURE(S)")
sys.exit(1 if fails else 0)
