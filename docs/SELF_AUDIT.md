# Self-audit

A review of **this app's own robustness**, done the way a professional would
review a network client before shipping it. The question here is not "is the
target site secure" — that is what the app reports — but "does the app behave
correctly and safely when the network and the server are hostile."

## Threat model

The app makes requests to whatever host the user types and then parses whatever
comes back. The server is therefore **untrusted input**. A malicious or broken
server can return oversized bodies, malformed headers, bad certificates, junk in
`security.txt`, redirect loops, or unusual host shapes (IP literals, punycode,
underscores). None of that may crash the app, hang it indefinitely, or produce a
misleading report.

The app is also, by deliberate design, **collection-only**: it sends no attack
payloads, does no fuzzing, brute force, host enumeration or high-volume traffic.
That boundary is part of the audit — a change that crossed it would be a finding,
not a feature.

## Method

- Read every collector against the threat model above.
- Extracted the pure decision logic (SNI eligibility, RFC 9116 parsing, version
  comparison, correlation rules) so it can be tested deterministically on a plain
  JVM without a live network.
- Added regression tests for each finding below.
- Ran the full suite (45 tests) against real OkHttp and the JDK.

## Findings and fixes

| # | Severity | Area | Finding | Fix |
|---|----------|------|---------|-----|
| 1 | **High** | `TlsProbe` | `SNIHostName(host)` throws for an IP literal, a trailing-dot FQDN, or a label with an underscore. Because it was called for every version, one throw marked a perfectly reachable host as **refusing all four TLS versions** — a false report. | SNI eligibility moved to a pure, tested `isValidSniHost`. Invalid names now connect **without** SNI instead of failing, and the guard is wrapped defensively. |
| 2 | Low | `SecurityTxtCheck` | An SPA that serves its HTML shell for every unknown path could be misread as publishing a policy. | Already mitigated (HTML content-type rejected, `Contact:`/`Expires:` required); confirmed and locked in with parser tests. |
| 3 | Low | `Strings` | A wrongly typed or missing format argument could throw mid-report. | `t()` already falls back to the raw template on any `format` failure; pinned with a regression test. |

Verified as **already sound**, not just assumed:

- Response bodies are capped (`peekBody(64 KiB)`); headers are bounded by OkHttp.
- Redirects are followed only for `http`/`https`; loops surface as a caught error.
- All network calls run on `Dispatchers.IO` and every failure path resolves to a
  displayed error state rather than a crash.
- `Set-Cookie` with no `=`, blank lines, stray text and comments in `security.txt`,
  and unparseable `Expires` values are all handled without throwing.
- Certificate expiry maths and version comparison are covered by tests.

## Residual risks (accepted)

- **Scan duration.** TLS versions are probed **sequentially** — up to four short
  connections, ~8 s timeout each — so a dead port can make a scan feel slow. This
  is a deliberate trade for making fewer simultaneous connections to the target;
  it is politeness, not a defect.
- **Self-signed / interception.** The probe reports the certificate the server
  presents; it does not itself decide trust. That is correct for an assessment
  tool but means the certificate fields describe what was served, not a verdict.
- **Out of scope by design.** Active exploitation, authenticated testing and host
  enumeration are intentionally absent. For those, on systems you are authorised
  to test, use dedicated tooling such as OWASP ZAP or Nikto.

## Test coverage

45 unit tests, all passing, run on a plain JVM as part of CI:

- correlation rules and their negative cases (`InvestigatorTest`)
- report building and language-switch invariance (`ReportBuilderTest`)
- RFC 9116 parsing edge cases (`SecurityTxtParseTest`)
- SNI eligibility (`TlsProbeTest`)
- translation parity and format safety (`StringsParityTest`)
- URL normalisation (`WebScannerTest`)
