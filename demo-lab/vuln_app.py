#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vulnerable Demo Lab — DELIBERATELY INSECURE TARGET
===================================================
Purpose: Local training target for testing NetRecon / WebVulnX legally.

DO NOT deploy this application on a public network. It is intentionally
vulnerable and exists only so you can practice scanning YOUR OWN lab.

Run:  python3 vuln_app.py [port]     (default 8080)

Simulated vulnerabilities
-------------------------
* /search?q=  ........ Reflected XSS (raw reflection)
* /page?id=  ......... SQL injection (error-based + boolean + time-based)
* /login ............. Login form (SQLi in POST user/pass)
* /admin ............. Hidden admin panel (found by dirbuster)
* /backup.sql ........ Sensitive file exposure
* /robots.txt ........ Discovers /secret-panel
* No security headers, banner disclosure
"""

import html
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTML_HEAD = """<!DOCTYPE html><html><head><title>{title}</title></head>
<body style="font-family:Arial;background:#111;color:#eee;padding:24px">
<h1 style="color:#6cf">{title}</h1>"""

INDEX = HTML_HEAD.format(title="Demo Shop") + """
<p>Welcome to the totally secure demo shop.</p>
<ul>
  <li><a href="/search?q=hello">Search</a></li>
  <li><a href="/page?id=1">Product page</a></li>
  <li><a href="/news?id=1">News</a></li>
  <li><a href="/lfi?file=index.php">Files</a></li>
  <li><a href="/tpl?name=guest">Templates</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping tool</a></li>
  <li><a href="/go?next=/">Redirect</a></li>
  <li><a href="/files">Downloads</a></li>
  <li><a href="/api/data">API</a></li>
  <li><a href="/xxe">XML Import</a></li>
  <li><a href="/fetch?url=http://example.com">URL Fetcher</a></li>
  <li><a href="/reset">Password Reset</a></li>
</ul>
<script>var SESSION = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.";</script>
  <li><a href="/login">Login</a></li>
</ul>
<form action="/search" method="GET">
  <input name="q" placeholder="search..."><button>Go</button>
</form></body></html>"""

LOGIN = HTML_HEAD.format(title="Login") + """
<form method="POST" action="/login">
  <input name="user" placeholder="user"><br>
  <input name="pass" type="password" placeholder="pass"><br>
  <button>Login</button>
</form></body></html>"""


class VulnHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49 (Unix)"      # banner disclosure
    sys_version = ""

    def _send(self, body: str, code: int = 200, ct: str = "text/html") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.4.21")   # tech disclosure
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self._send(INDEX)
        elif path == "/search":
            q = qs.get("q", [""])[0]
            # RAW reflection -> Reflected XSS
            self._send(HTML_HEAD.format(title="Search") +
                       f"<p>You searched for: {q}</p>"
                       f"<p><a href='/'>home</a></p></body></html>")
        elif path == "/page":
            pid = qs.get("id", ["1"])[0]
            # Time-based blind SQLi
            if "SLEEP" in pid.upper() or "WAITFOR" in pid.upper():
                time.sleep(5)
                self._send(HTML_HEAD.format(title="Product") + "<p>Product 1</p></body></html>")
                return
            # Error-based SQLi
            if "'" in pid or '"' in pid or "UNION" in pid.upper():
                self._send(HTML_HEAD.format(title="Error") +
                           "<p>You have an error in your SQL syntax; check the manual "
                           "that corresponds to your MySQL server version</p></body></html>")
                return
            # Boolean-based blind
            if "1=1" in pid.replace(" ", ""):
                self._send(HTML_HEAD.format(title="Product") +
                           "<p>Product 1 - Full details - price 100$</p></body></html>")
            elif "1=2" in pid.replace(" ", ""):
                self._send(HTML_HEAD.format(title="Product") +
                           "<p>Not found</p></body></html>")
            else:
                self._send(HTML_HEAD.format(title="Product") +
                           f"<p>Product {html.escape(pid)}</p></body></html>")
        elif path == "/news":
            nid = qs.get("id", ["1"])[0]
            # Time-based blind SQLi (no error messages leaked)
            if "SLEEP" in nid.upper() or "WAITFOR" in nid.upper() or "PG_SLEEP" in nid.upper():
                time.sleep(5)
                self._send(HTML_HEAD.format(title="News") +
                           "<p>Latest news</p><p>...</p></body></html>")
                return
            # Boolean-based blind SQLi (TRUE ~= default page, FALSE differs)
            if "1=2" in nid.replace(" ", ""):
                self._send(HTML_HEAD.format(title="News") +
                           "<p>No news</p></body></html>")
            else:
                # default AND 1=1 share the same page (real boolean-blind behavior)
                self._send(HTML_HEAD.format(title="News") +
                           "<p>Latest news: our shop is open, we have many products "
                           "and great offers for everyone this season</p></body></html>")
        elif path == "/lfi":
            # LFI simulation: returns fake /etc/passwd content for traversal payloads
            f = qs.get("file", [""])[0]
            if "etc/passwd" in f or "win.ini" in f or "proc/self" in f:
                self._send(HTML_HEAD.format(title="File") +
                           "<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n"
                           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</pre></body></html>")
            else:
                self._send(HTML_HEAD.format(title="File") +
                           f"<pre>content of {html.escape(f) or 'index.php'}</pre></body></html>")
        elif path == "/tpl":
            # SSTI simulation: actually evaluates simple {expr} patterns
            name = qs.get("name", ["guest"])[0]
            import re as _re
            m = _re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", name) or \
                _re.fullmatch(r"\$\{(\d+)\*(\d+)\}", name) or \
                _re.fullmatch(r"<%=(\d+)\*(\d+)%>", name) or \
                _re.fullmatch(r"#\{(\d+)\*(\d+)\}", name)
            if m:
                out = str(int(m.group(1)) * int(m.group(2)))
            elif _re.fullmatch(r"\{\{7\*'7'\}\}", name):
                out = "7777777"
            else:
                out = html.escape(name)
            self._send(HTML_HEAD.format(title="Template") + f"<p>Hello {out}</p></body></html>")
        elif path == "/go":
            # Open redirect simulation
            nxt = qs.get("next", [""])[0]
            if nxt.startswith("http://") or nxt.startswith("https://"):
                self.send_response(302)
                self.send_header("Location", nxt)
                self.end_headers()
            else:
                self._send(HTML_HEAD.format(title="Go") + "<p>redirecting...</p></body></html>")
        elif path == "/ping":
            # Command injection simulation
            host = qs.get("host", [""])[0]
            if ";" in host or "|" in host or "`" in host or "$(" in host:
                self._send(HTML_HEAD.format(title="Ping") +
                           "<pre>PING 127.0.0.1\nuid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>"
                           "</body></html>")
            else:
                self._send(HTML_HEAD.format(title="Ping") +
                           f"<pre>PING {html.escape(host)}: 64 bytes</pre></body></html>")
        elif path == "/files":
            # Directory listing simulation
            self._send("<!DOCTYPE html><html><head><title>Index of /files/</title></head><body>"
                       "<h1>Index of /files/</h1><ul><li><a href='backup.zip'>backup.zip</a></li>"
                       "<li><a href='db.sql'>db.sql</a></li></ul></body></html>")
        elif path == "/api/data":
            # CORS reflection simulation
            origin = self.headers.get("Origin", "")
            body = '{"secret": "user-data"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        elif path == "/xxe":
            # XXE simulation (POST XML) — runs on any method
            self._send(HTML_HEAD.format(title="XML Import") +
                       "<p>Upload XML data</p></body></html>")
        elif path == "/fetch":
            # SSRF simulation
            u = qs.get("url", [""])[0]
            if "127.0.0.1:1" in u or "localhost:1" in u:
                self._send(HTML_HEAD.format(title="Fetch") +
                           "<pre>Failed to fetch URL: Connection refused (ECONNREFUSED)</pre></body></html>")
            elif "file://" in u:
                self._send(HTML_HEAD.format(title="Fetch") +
                           "<pre>root:x:0:0:root:/root:/bin/bash</pre></body></html>")
            else:
                self._send(HTML_HEAD.format(title="Fetch") +
                           f"<pre>content of {html.escape(u)}</pre></body></html>")
        elif path == "/reset":
            # Host header echo (password-reset poisoning simulation)
            host = self.headers.get("Host", "localhost")
            self._send(HTML_HEAD.format(title="Reset") +
                       f"<p>Reset link: http://{html.escape(host)}/reset?token=abc123</p></body></html>")
        elif path == "/login":
            self._send(LOGIN)
        elif path == "/admin":
            self._send(HTML_HEAD.format(title="Admin Panel") +
                       "<p>TOP SECRET ADMIN PANEL — user list, config, etc.</p></body></html>")
        elif path == "/backup.sql":
            self._send("-- dump\nCREATE TABLE users (id INT, pass VARCHAR(64));\n"
                       "INSERT INTO users VALUES (1,'admin:5f4dcc3b5aa765d61d8327deb882cf99');\n",
                       ct="application/sql")
        elif path == "/robots.txt":
            self._send("User-agent: *\nDisallow: /admin\nDisallow: /secret-panel\n",
                       ct="text/plain")
        elif path == "/secret-panel":
            self._send(HTML_HEAD.format(title="Secret") + "<p>secret</p></body></html>")
        elif path == "/.env":
            self._send("DB_PASS=SuperSecret123\nAPI_KEY=sk-live-abc123\n", ct="text/plain")
        else:
            self._send(HTML_HEAD.format(title="404") + "<p>Not Found</p></body></html>", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "ignore")
        params = urllib.parse.parse_qs(body)
        if self.path == "/xxe":
            # XXE simulation: resolve external entity when XML contains a file DOCTYPE
            if "ENTITY" in body.upper() and "file:///" in body:
                self._send(HTML_HEAD.format(title="XML Import") +
                           "<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin</pre>"
                           "</body></html>")
            else:
                self._send(HTML_HEAD.format(title="XML Import") +
                           "<p>XML processed OK</p></body></html>")
        elif self.path == "/login":
            user = params.get("user", [""])[0]
            if "'" in user:
                self._send(HTML_HEAD.format(title="Error") +
                           "<p>You have an error in your SQL syntax; check the manual "
                           "that corresponds to your MySQL server version</p></body></html>")
            else:
                self._send(HTML_HEAD.format(title="Login") +
                           "<p>Invalid credentials</p></body></html>")
        else:
            self._send(HTML_HEAD.format(title="404") + "<p>Not Found</p></body></html>", 404)

    def log_message(self, fmt, *args):
        pass  # quiet


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv = ThreadingHTTPServer(("0.0.0.0", port), VulnHandler)
    print(f"[demo-lab] Vulnerable app listening on http://127.0.0.1:{port}")
    print("[demo-lab] INTENTIONALLY INSECURE — local testing only!")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[demo-lab] stopped")


if __name__ == "__main__":
    main()
