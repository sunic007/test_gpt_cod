# Phone-only lab (Termux) — ready-made targets

No PC, no Docker. Run a real, well-known vulnerable app **on your Android phone**
with Python. Because it runs on your device and listens on localhost only, it is
yours to attack, which keeps practice legal.

## Recommended: DSVW (a ready-made GitHub project)

[**DSVW — Damn Small Vulnerable Web**](https://github.com/stamparm/DSVW) by
Miroslav Stampar (co-author of sqlmap): a single Python file with ~26 classic web
vulnerabilities (SQLi, XSS, XXE, SSRF, LFI/RFI, command injection, and more). It
binds to `127.0.0.1:65412` by default, so it stays on your phone.

### 1. Install Termux

Install **Termux** from F-Droid (https://f-droid.org/packages/com.termux/) — the
Play Store build is outdated. Open it.

### 2. Fetch and run DSVW

```bash
pkg update -y && pkg install python git -y
git clone https://github.com/stamparm/DSVW
cd DSVW
python dsvw.py
```

It prints `running HTTP server at 'http://127.0.0.1:65412'`. Leave it running.

> Optional: a few XML/XXE exercises need `lxml`. Everything else works without it.
> To enable them: `pkg install libxml2 libxslt` then `pip install lxml`.

### 3. Scan it with your own app

Open Web Security Audit → **Audit** tab → enter `localhost:65412`, tick the
authorisation box (it *is* yours), run.

### 4. Practise

DSVW's landing page lists its vulnerable endpoints with example payloads — work
through them in the phone browser or a second Termux session (`curl`). Swipe from
the left edge → **NEW SESSION** to get a second shell while the server runs.

## Other ready-made options

- **OWASP Juice Shop** (https://github.com/juice-shop/juice-shop) — much richer,
  but Node with native deps; realistically needs a PC or cloud, not a phone.
- **DVWA** (https://github.com/digininja/DVWA) — classic PHP app; needs PHP +
  MySQL. See `lab/docker-compose.yml` to run it (and Juice Shop) on any machine
  with Docker.

## Offline fallback

If you cannot `git clone` (no network in Termux), this repo ships a tiny
self-contained target you can copy over manually: `lab/termux/vuln_server.py`
(`python vuln_server.py` → http://localhost:8000). DSVW above is preferred — it is
maintained and far more complete.

## Learn the bugs

- PortSwigger Web Security Academy (free): https://portswigger.net/web-security
- OWASP Top 10: https://owasp.org/www-project-top-ten/

## Safety

These apps are deliberately insecure. Run them only on your own device, on a
network you trust, and never expose them to the internet. Never point what you
practise here at systems you do not own or are not authorised to test.
