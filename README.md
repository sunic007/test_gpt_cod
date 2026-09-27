# Web Security Audit (Android)

An Android app that runs a **passive, non-intrusive security assessment** of a
web page and reports on common HTTP-level hardening problems.

> ⚠️ **Use only on systems you own or are explicitly authorised to test.**
> Scanning systems without permission may be illegal in your jurisdiction. The
> app requires you to confirm authorisation before every scan.

## What it does

For a target URL, the app makes **one ordinary GET request** — the same request
a browser makes when you open the page — and inspects the response metadata:

- **Transport**: whether the site is served over HTTPS.
- **HSTS**: `Strict-Transport-Security` present.
- **CSP**: `Content-Security-Policy` present.
- **Clickjacking**: `X-Frame-Options` / CSP `frame-ancestors`.
- **MIME sniffing**: `X-Content-Type-Options: nosniff`.
- **Referrer / Permissions policy**.
- **Information disclosure**: `Server` version, `X-Powered-By`.
- **Cookie hygiene**: `Secure`, `HttpOnly`, `SameSite` flags on `Set-Cookie`.

Each finding includes a severity, an explanation, and a remediation hint, plus an
overall "header hygiene" score.

## What it deliberately does NOT do

By design it is a **defensive/awareness** tool, not an attack tool. It does not
send exploit payloads (SQLi/XSS/RCE), does not fuzz parameters, does not
brute-force credentials or paths, and does not generate high-volume/DoS traffic.
For deeper authorised testing use dedicated tooling such as OWASP ZAP or Nikto.

## Building

The project builds with Gradle 8.9 and the Android Gradle Plugin 8.5.

```bash
# from a machine with the Android SDK installed
gradle assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

### Getting the APK from CI

Every push runs `.github/workflows/build.yml`, which runs the unit tests, builds
the debug APK, and uploads it as the **`web-security-audit-debug-apk`** artifact.
Open the workflow run in the GitHub **Actions** tab and download it from the
*Artifacts* section, then install the `.apk` on a device with "install from
unknown sources" enabled.

## Project layout

```
app/src/main/java/com/secaudit/webscan/
├── MainActivity.kt            # Compose UI + authorisation gate
├── model/Findings.kt          # Finding / Severity / ScanReport / ScanState
├── scanner/WebScanner.kt      # Passive checks over a single GET
└── ui/ScanViewModel.kt        # State handling
```

## Stack

Kotlin · Jetpack Compose (Material 3) · Coroutines · OkHttp
