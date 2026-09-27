# Training lab

A local, intentionally-vulnerable playground for practising security tooling
**legally** — because it runs on your own machine, against targets you own.

> The whole point of a lab is that it removes the legality problem: you may run
> any tool, including the aggressive ones, against these containers, because they
> are yours. Never point the same tools at systems you do not own or lack written
> authorisation to test.

## Start it

Requires Docker.

```bash
docker compose -f lab/docker-compose.yml up -d
```

Two deliberately-vulnerable apps come up, bound to localhost only:

| Target | URL | Notes |
| --- | --- | --- |
| OWASP Juice Shop | http://localhost:3000 | Modern JS app, huge range of challenges |
| DVWA | http://localhost:8080 | Classic PHP app; login admin/password, then set security to Low |

Stop and remove them when done:

```bash
docker compose -f lab/docker-compose.yml down
```

## Point this app at the lab

The `Audit` screen of the app works against the lab too: enter `localhost:3000`
(tick the authorisation box — it *is* yours) to see the passive report on Juice
Shop. It is a good way to watch findings change as you harden a target.

## Practise with real Kali tooling

On your Kali machine (or any box with these installed), run against the lab —
this is where the offensive tools belong, aimed at your own containers:

```bash
# Recon / assessment
nmap -sV -p- 127.0.0.1
whatweb http://localhost:3000
nuclei -u http://localhost:3000
testssl.sh http://localhost:8080

# Content discovery (against YOUR lab only)
ffuf -u http://localhost:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://localhost:3000 -w /usr/share/wordlists/dirb/common.txt

# Guided exploitation exercises (DVWA / Juice Shop have built-in lessons)
sqlmap -u "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" --batch
```

Everything above targets `localhost` / `127.0.0.1` — your own hardware.

## Learn the exploitation, not just the commands

The tools are the easy part; understanding the bugs is the point:

- OWASP Juice Shop tutorial: https://pwning.owasp-juice.shop/
- PortSwigger Web Security Academy (free): https://portswigger.net/web-security
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- DVWA on GitHub: https://github.com/digininja/DVWA

## Why the app itself stays passive

This project's app ships only passive, read-what-the-site-publishes checks, so it
is safe to run against a real site you are assessing. The aggressive tooling lives
here, in a lab you control, rather than baked into a distributable APK that could
be pointed at anyone — that separation is deliberate.
