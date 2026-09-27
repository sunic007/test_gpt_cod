#!/usr/bin/env python3
"""
Mini training target — an INTENTIONALLY VULNERABLE web app for practice.

This is your own practice range, in the spirit of OWASP Juice Shop / DVWA, but
tiny enough to run on a phone under Termux with nothing but the Python standard
library (no pip, no native builds).

    IT IS DELIBERATELY INSECURE. Run it ONLY on your own device, bound to
    localhost. Never expose it to a network or the internet, and never point the
    techniques you practise here at systems you do not own.

Run:
    python vuln_server.py            # then open http://localhost:8000

It binds to 127.0.0.1 only, so nothing outside the phone can reach it.

Built-in exercises (all self-contained, no real data at risk):
  1. Missing security headers   — scan it with the app's Audit tab.
  2. Insecure cookie            — SID is set without Secure/HttpOnly/SameSite.
  3. Information disclosure      — Server / X-Powered-By reveal fake versions.
  4. Reflected XSS              — /greet?name=...
  5. SQL injection             — /login  (try  ' OR 1=1 --  as the username)
  6. Open redirect             — /redirect?url=...
"""

import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST = "127.0.0.1"
PORT = 8000

# A throwaway in-memory user table for the SQL-injection exercise.
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (username TEXT, password TEXT, note TEXT)")
_db.executemany(
    "INSERT INTO users VALUES (?, ?, ?)",
    [
        ("admin", "s3cr3t-admin-pw", "flag{you_found_the_admin_row}"),
        ("alice", "password1", "alice's private note"),
        ("bob", "hunter2", "bob's private note"),
    ],
)
_db.commit()

PAGE = """<!doctype html>
<html><head><title>Training Target</title></head><body>
<h1>&#9888; Intentionally vulnerable training target</h1>
<p>Your own practice range. Do not expose it to any network.</p>
<h2>Exercises</h2>
<ul>
  <li><b>Missing headers / cookie</b>: scan <code>http://localhost:8000</code> in the app's Audit tab.</li>
  <li><b>Reflected XSS</b>: <a href="/greet?name=friend">/greet?name=friend</a>
      &mdash; try <code>name=&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
  <li><b>SQL injection</b>: <a href="/login">/login</a>
      &mdash; try username <code>' OR 1=1 -- </code></li>
  <li><b>Open redirect</b>: <a href="/redirect?url=https://example.com">/redirect?url=...</a></li>
</ul>
</body></html>"""

LOGIN_FORM = """<!doctype html>
<html><head><title>Login</title></head><body>
<h1>Login (SQL injection exercise)</h1>
<form method="post" action="/login">
  <p>Username: <input name="username"></p>
  <p>Password: <input name="password" type="password"></p>
  <p><button type="submit">Log in</button></p>
</form>
<p>Hint: the query is built by string concatenation. Try <code>' OR 1=1 -- </code> (note the trailing space).</p>
{result}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "TrainingTarget/0.1"          # information disclosure
    sys_version = ""

    def _send(self, body, status=200, headers=None, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # Deliberately leaky / insecure headers — nothing you would ship.
        self.send_header("X-Powered-By", "TrainingTarget PHP/5.4.0")
        self.send_header("Set-Cookie", "SID=trainingsession123; Path=/")   # no Secure/HttpOnly/SameSite
        # NOTE: intentionally NO CSP, HSTS, X-Frame-Options, X-Content-Type-Options.
        for k, v in (headers or {}):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        params = parse_qs(parsed.query)

        if route == "/":
            self._send(PAGE)
        elif route == "/greet":
            name = params.get("name", ["world"])[0]
            # VULN: reflected XSS — user input echoed without escaping.
            self._send(f"<!doctype html><html><body><h1>Hello, {name}!</h1></body></html>")
        elif route == "/login":
            self._send(LOGIN_FORM.format(result=""))
        elif route == "/redirect":
            # VULN: open redirect — destination taken straight from user input.
            target = params.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        else:
            self._send("<h1>404</h1>", status=404)

    def do_POST(self):
        if urlparse(self.path).path != "/login":
            self._send("<h1>404</h1>", status=404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(body)
        user = form.get("username", [""])[0]
        pw = form.get("password", [""])[0]

        # VULN: SQL injection — inputs concatenated straight into the query.
        query = (
            "SELECT username, note FROM users "
            f"WHERE username = '{user}' AND password = '{pw}'"
        )
        try:
            rows = _db.execute(query).fetchall()
        except Exception as exc:  # noqa: BLE001 - surfacing errors is part of the lesson
            self._send(LOGIN_FORM.format(result=f"<p>DB error: {html.escape(str(exc))}</p>"))
            return

        if rows:
            items = "".join(f"<li>{html.escape(u)}: {html.escape(n)}</li>" for u, n in rows)
            self._send(LOGIN_FORM.format(result=f"<h3>Logged in. Rows returned:</h3><ul>{items}</ul>"))
        else:
            self._send(LOGIN_FORM.format(result="<p>Invalid credentials.</p>"))

    def log_message(self, fmt, *args):
        print(f"[target] {self.address_string()} {fmt % args}")


def main():
    print("=" * 60)
    print(" INTENTIONALLY VULNERABLE training target")
    print(f" Listening on http://{HOST}:{PORT}  (localhost only)")
    print(" Your device only. Do not expose to any network.")
    print(" Stop with Ctrl+C.")
    print("=" * 60)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
