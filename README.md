# Web Security Audit (Android)

An Android app that runs a **passive, non-intrusive security assessment** of a
web site, then correlates the observations into conclusions with a visible chain
of reasoning. Interface in **Russian and English**, dark terminal styling.

> ⚠️ **Use only on systems you own or are explicitly authorised to test.**
> Scanning systems without permission may be illegal in your jurisdiction. The
> app requires you to confirm authorisation before every scan.

## What it collects

Everything below is information the target publishes about itself. Nothing is
fuzzed, guessed or brute-forced.

| Source | What happens |
| --- | --- |
| **Page request** | One ordinary GET — the request a browser makes to open the site |
| **TLS probe** | Up to four handshake-only connections, one per protocol version, with no HTTP request sent |
| **Disclosure policy** | A read of `/.well-known/security.txt`, then `/security.txt` |

A whole run costs fewer requests than loading the site's home page in a browser.

### Checks

- **Transport** — HTTPS in use, HSTS published.
- **TLS profile** — which of TLS 1.0 / 1.1 / 1.2 / 1.3 the listener actually
  accepts, the negotiated cipher suite, and the certificate's subject, issuer,
  SAN count and remaining validity.
- **Headers** — CSP, `X-Frame-Options` / `frame-ancestors`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- **Disclosure** — RFC 9116 `security.txt`: presence, `Contact`, `Expires`
  (including whether it has lapsed), `Policy`, `Encryption`, `Canonical`.
- **Information leakage** — `Server` version strings, `X-Powered-By`.
- **Cookies** — `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie`.

## The investigation layer

A checklist tells you a header is missing. The interesting half of an assessment
is what the observations mean *together*, so `Investigator` reads them as a whole
and reports **leads**: a hypothesis, a confidence level, the chain of clues
behind it, and why it matters. Every lead shows its evidence so you can check the
reasoning instead of trusting a verdict. For example:

- **Cookie exposure chain** — a cookie without `Secure` is a note on its own. On
  an HTTPS site that also publishes no HSTS policy, the two combine: the browser
  is willing to send the cookie over plain HTTP, and nothing stops it from making
  that request. The lead explains that fixing either one breaks the chain.
- **Unmaintained deployment** — legacy TLS accepted, a banner advertising a
  version behind the supported branch, an expired `security.txt`, no TLS 1.3.
  Each is minor; together they suggest the vendor's current guidance is not being
  applied, so other patches are probably outstanding too.
- **No hardening layer** — four or more response headers absent at once usually
  means nobody configured headers at all, which is a process gap rather than a
  config gap.
- **Origin leaking through the edge** — a CDN serves the response, but
  `X-Powered-By` and framework cookie names from the origin pass through it
  unchanged.
- **Identifiable but unreachable** — the stack is easy to fingerprint and there
  is no published contact, so a researcher who finds a problem has nowhere to
  send it.
- **Downgrade surface** — TLS 1.2 is available *and* TLS 1.0/1.1 are still
  accepted, which buys little compatibility while keeping the old weaknesses
  reachable.

The app also builds a **technology profile**, inferring the stack from many
individually inconclusive hints (`Server`, `X-Powered-By`, `X-AspNet-Version`,
CDN headers, `Link: wp-json`, and cookie names such as `PHPSESSID`,
`JSESSIONID`, `laravel_session`, `csrftoken`), and lists the signal behind each
conclusion.

## Language

The app ships in Russian and English and starts in the device's language. A
`РУС / ENG` switch in the toolbar changes it at any time — including on a report
that is already on screen, which is re-worded **instantly and without touching
the network**, because collection (`WebScanner` → `RawObservations`) is kept
separate from wording (`ReportBuilder`).

Text lives in a key/template map (`i18n/`) rather than Android string resources,
so the scanner and investigator stay free of Android dependencies and can be
unit-tested on a plain JVM. `StringsParityTest` guards that choice: it fails if a
key exists in one language but not the other, if a key's `%s`/`%d` placeholders
differ between languages, or if a lead's prose was left untranslated.

## Interface

Dark-only, monospaced, laid out like a terminal report: a severity stripe down
the left edge of each panel, `//` section markers, colour-coded severity chips,
and a header-hygiene bar. Dark is deliberate rather than decorative — the report
is dense technical text, and one consistent dark surface keeps the severity
colours legible instead of fighting a light background.

While a scan runs, the progress screen shows a **"digital rain"** animation
(`MatrixRain`) — falling green glyphs with a bright head and fading tail — behind
a blinking-cursor status line. It is purely decorative: it renders nothing about
the target and stops the moment the scan finishes.

## What it deliberately does NOT do

By design this is a **defensive/awareness** tool, not an attack tool. It does not
send exploit payloads (SQLi/XSS/RCE), does not fuzz parameters, does not
brute-force credentials or paths, does not enumerate subdomains or hosts, and
does not generate high-volume or DoS traffic. For deeper authorised testing use
dedicated tooling such as OWASP ZAP or Nikto.

## Building

The project builds with Gradle 8.9, Android Gradle Plugin 8.5 and JDK 17.

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
├── MainActivity.kt                # Compose UI, dark terminal styling, language switch
├── i18n/
│   ├── Strings.kt                 # Lang + key/template lookup
│   ├── RuStrings.kt               # Russian
│   └── EnStrings.kt               # English
├── model/Findings.kt              # Finding / Lead / LeadId / TlsInfo / SecurityTxt / ScanReport
├── scanner/
│   ├── WebScanner.kt              # Collection → RawObservations (language-neutral)
│   ├── ReportBuilder.kt           # Observations → a written report in one language
│   ├── TlsProbe.kt                # Handshake-only protocol version profiling
│   ├── SecurityTxtCheck.kt        # RFC 9116 retrieval and parsing
│   └── Investigator.kt            # Correlation: leads, evidence chains, tech profile
├── ui/ScanViewModel.kt            # State, progress and language handling
└── ui/MatrixRain.kt               # "Digital rain" scan animation
```

## Tests

45 unit tests cover the correlation rules and their negative cases, the report
builder, RFC 9116 parsing, SNI eligibility, and translation parity. They run on a
plain JVM (no Android SDK required) as part of the CI build.

A professional-style robustness review of the app itself — how it behaves against
hostile or malformed server responses — is written up in
[`docs/SELF_AUDIT.md`](docs/SELF_AUDIT.md).

## Stack

Kotlin · Jetpack Compose (Material 3) · Coroutines · OkHttp · JSSE
