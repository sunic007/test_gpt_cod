# Phone-only lab (Termux)

No PC, no Docker — a real, own practice target running **on your Android phone**
with nothing but Python. Because it runs on your device and listens on localhost
only, it is yours to attack, which keeps practice legal.

## 1. Install Termux

Install **Termux** from F-Droid (https://f-droid.org/packages/com.termux/) — the
Play Store build is outdated. Open it.

## 2. Get Python and this repo

```bash
pkg update -y && pkg install python git -y
git clone https://github.com/sunic007/test_gpt_cod
cd test_gpt_cod/lab/termux
```

## 3. Start the target

```bash
python vuln_server.py
```

It serves an intentionally vulnerable app at **http://localhost:8000** (localhost
only — nothing off the phone can reach it). Leave this Termux session running.

## 4. Scan it with your own app

Open the Web Security Audit app → **Audit** tab → enter `localhost:8000`, tick the
authorisation box (it *is* yours), run. You should see the missing security
headers, the insecure `SID` cookie, and the `Server` / `X-Powered-By` disclosure
light up.

## 5. Practise the active exercises

In a browser on the phone (or a second Termux session with `curl`):

| Exercise | Try |
| --- | --- |
| Reflected XSS | open `http://localhost:8000/greet?name=<script>alert(1)</script>` |
| SQL injection | at `/login`, username `' OR 1=1 -- ` (trailing space), any password |
| Open redirect | `http://localhost:8000/redirect?url=https://example.com` |

A second Termux shell (swipe from the left → **NEW SESSION**) lets you run CLI
tools while the server keeps running, e.g.:

```bash
curl -i http://localhost:8000/
curl "http://localhost:8000/greet?name=<script>alert(1)</script>"
curl -X POST --data-urlencode "username=' OR 1=1 -- " --data-urlencode "password=x" \
     http://localhost:8000/login
```

## 6. Learn the bugs

- PortSwigger Web Security Academy (free, phone-friendly): https://portswigger.net/web-security
- OWASP Top 10: https://owasp.org/www-project-top-ten/

## Stop it

Press `Ctrl+C` in the Termux session running the server.

---

### Want the full Juice Shop / DVWA + real Kali tools?

That needs more than a phone. The `lab/docker-compose.yml` in this repo runs both
on any machine with Docker, and you can drive it for free from your phone's
browser via GitHub Codespaces or Gitpod. Ask and I'll add a ready-to-run cloud
config.
