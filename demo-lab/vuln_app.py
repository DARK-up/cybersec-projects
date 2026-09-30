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
        if self.path == "/login":
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
