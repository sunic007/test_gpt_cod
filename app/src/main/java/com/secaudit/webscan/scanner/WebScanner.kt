package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.Finding
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TlsInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.util.concurrent.TimeUnit

/**
 * Passive web-security assessment.
 *
 * The scanner collects evidence from three sources, all of which observe what the
 * target publishes about itself:
 *
 *  1. one ordinary GET of the target (the request a browser makes to open it),
 *  2. handshake-only TLS probes to see which protocol versions are accepted,
 *  3. the site's RFC 9116 disclosure policy, if it publishes one.
 *
 * It then hands everything to [Investigator], which correlates the observations.
 * No attack payloads are sent, nothing is fuzzed or brute-forced, and the whole
 * run costs fewer requests than loading the site's home page in a browser. It is
 * intended for sites you own or are explicitly authorised to test.
 */
class WebScanner {

    companion object {
        const val USER_AGENT = "WebSecAudit/1.1 (passive configuration review)"
    }

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .retryOnConnectionFailure(false)
        .build()

    /** What the first GET told us, captured before the response is closed. */
    private data class InitialResponse(
        val finalUrl: HttpUrl,
        val status: Int,
        val headers: Map<String, String>,
        val cookies: List<String>,
        val findings: List<Finding>
    )

    private val tlsProbe = TlsProbe()
    private val securityTxtCheck = SecurityTxtCheck(client)
    private val investigator = Investigator()

    /** Normalises user input into a valid absolute URL, defaulting to https://. */
    fun normalizeTarget(raw: String): String {
        val trimmed = raw.trim()
        return when {
            trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true) -> trimmed
            else -> "https://$trimmed"
        }
    }

    suspend fun scan(
        rawTarget: String,
        onProgress: (String) -> Unit = {}
    ): ScanReport = withContext(Dispatchers.IO) {
        val target = normalizeTarget(rawTarget)
        val started = System.currentTimeMillis()

        onProgress("Requesting $target …")
        val request = Request.Builder()
            .url(target)
            .header("User-Agent", USER_AGENT)
            .get()
            .build()

        val initial = client.newCall(request).execute().use { response ->
            InitialResponse(
                finalUrl = response.request.url,
                status = response.code,
                headers = response.headers.names()
                    .associate { it.lowercase() to response.headers[it].orEmpty() },
                cookies = response.headers.values("Set-Cookie"),
                findings = analyzeHeaders(response)
            )
        }

        val finalUrl = initial.finalUrl
        val findings = initial.findings.toMutableList()

        val tls: TlsInfo? = if (finalUrl.isHttps) {
            onProgress("Probing TLS versions on ${finalUrl.host} …")
            tlsProbe.probe(finalUrl.host, finalUrl.port).also { findings += analyzeTls(it) }
        } else {
            null
        }

        onProgress("Looking for a disclosure policy …")
        val securityTxt = securityTxtCheck.fetch(finalUrl).also { findings += analyzeSecurityTxt(it) }

        onProgress("Correlating observations …")
        val investigation = investigator.investigate(
            Evidence(
                finalUrl = finalUrl.toString(),
                host = finalUrl.host,
                isHttps = finalUrl.isHttps,
                status = initial.status,
                headers = initial.headers,
                setCookies = initial.cookies,
                tls = tls,
                securityTxt = securityTxt
            )
        )

        ScanReport(
            target = target,
            finalUrl = finalUrl.toString(),
            httpStatus = initial.status,
            findings = findings.sortedByDescending { it.severity.weight },
            leads = investigation.leads,
            caseSummary = investigation.summary,
            techProfile = investigation.techProfile,
            tls = tls,
            securityTxt = securityTxt,
            startedAtEpochMs = started,
            durationMs = System.currentTimeMillis() - started
        )
    }

    // ---------------------------------------------------------------- headers

    private fun analyzeHeaders(response: Response): List<Finding> {
        val findings = mutableListOf<Finding>()
        val headers = response.headers
        fun header(name: String): String? = headers[name]

        val finalUrl = response.request.url
        val isHttps = finalUrl.isHttps

        if (!isHttps) {
            findings += Finding(
                title = "Site not served over HTTPS",
                severity = Severity.HIGH,
                detail = "The final response was delivered over plain HTTP ($finalUrl). " +
                    "Traffic can be read or modified in transit.",
                remediation = "Serve all content over HTTPS and redirect HTTP to HTTPS.",
                category = "Transport"
            )
        }

        if (isHttps && header("Strict-Transport-Security").isNullOrBlank()) {
            findings += Finding(
                title = "Missing Strict-Transport-Security (HSTS)",
                severity = Severity.MEDIUM,
                detail = "No HSTS header. Browsers may fall back to HTTP on the first visit.",
                remediation = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                category = "Transport"
            )
        }

        val csp = header("Content-Security-Policy").orEmpty()
        if (csp.isBlank()) {
            findings += Finding(
                title = "Missing Content-Security-Policy",
                severity = Severity.MEDIUM,
                detail = "No CSP header. CSP is a key defence against XSS and data injection.",
                remediation = "Define a Content-Security-Policy tailored to your resources.",
                category = "Headers"
            )
        }

        if (header("X-Frame-Options").isNullOrBlank() && !csp.contains("frame-ancestors", true)) {
            findings += Finding(
                title = "Clickjacking protection not set",
                severity = Severity.MEDIUM,
                detail = "Neither X-Frame-Options nor CSP frame-ancestors is present.",
                remediation = "Add X-Frame-Options: DENY or a CSP frame-ancestors directive.",
                category = "Headers"
            )
        }

        if (!header("X-Content-Type-Options").equals("nosniff", true)) {
            findings += Finding(
                title = "MIME sniffing not disabled",
                severity = Severity.LOW,
                detail = "X-Content-Type-Options: nosniff is missing.",
                remediation = "Add: X-Content-Type-Options: nosniff",
                category = "Headers"
            )
        }

        if (header("Referrer-Policy").isNullOrBlank()) {
            findings += Finding(
                title = "No Referrer-Policy",
                severity = Severity.LOW,
                detail = "Without a Referrer-Policy, full URLs may leak to third parties.",
                remediation = "Add: Referrer-Policy: strict-origin-when-cross-origin",
                category = "Headers"
            )
        }

        if (header("Permissions-Policy").isNullOrBlank()) {
            findings += Finding(
                title = "No Permissions-Policy",
                severity = Severity.INFO,
                detail = "Permissions-Policy lets you disable powerful browser features.",
                remediation = "Consider restricting features, e.g. geolocation=(), camera=().",
                category = "Headers"
            )
        }

        val server = header("Server")
        if (!server.isNullOrBlank() && server.any { it.isDigit() }) {
            findings += Finding(
                title = "Server version disclosed",
                severity = Severity.LOW,
                detail = "Server header reveals software/version: \"$server\".",
                remediation = "Suppress version details in the Server header.",
                category = "Disclosure"
            )
        }

        val poweredBy = header("X-Powered-By")
        if (!poweredBy.isNullOrBlank()) {
            findings += Finding(
                title = "X-Powered-By disclosed",
                severity = Severity.LOW,
                detail = "X-Powered-By reveals backend technology: \"$poweredBy\".",
                remediation = "Remove the X-Powered-By header.",
                category = "Disclosure"
            )
        }

        headers.values("Set-Cookie").forEach { cookie ->
            val name = cookie.substringBefore('=').trim()
            val lower = cookie.lowercase()
            val issues = buildList {
                if (isHttps && !lower.contains("secure")) add("missing Secure")
                if (!lower.contains("httponly")) add("missing HttpOnly")
                if (!lower.contains("samesite")) add("missing SameSite")
            }
            if (issues.isNotEmpty()) {
                findings += Finding(
                    title = "Cookie \"$name\" weak attributes",
                    severity = Severity.MEDIUM,
                    detail = "Cookie set with: ${issues.joinToString(", ")}.",
                    remediation = "Set Secure; HttpOnly; SameSite on session cookies.",
                    category = "Cookies"
                )
            }
        }

        return findings
    }

    // -------------------------------------------------------------------- TLS

    private fun analyzeTls(tls: TlsInfo): List<Finding> {
        val findings = mutableListOf<Finding>()

        if (!tls.reachable) {
            findings += Finding(
                title = "TLS versions could not be profiled",
                severity = Severity.INFO,
                detail = tls.error ?: "No handshake completed.",
                remediation = "Check the host from a network that permits direct TLS connections.",
                category = "TLS"
            )
            return findings
        }

        val legacy = tls.accepted.filter { it == "TLSv1" || it == "TLSv1.1" }
        if (legacy.isNotEmpty()) {
            findings += Finding(
                title = "Deprecated TLS accepted: ${legacy.joinToString(", ")}",
                severity = Severity.HIGH,
                detail = "The server completed a handshake using ${legacy.joinToString(" and ")}. " +
                    "Both were deprecated by RFC 8996 and are rejected by current browsers.",
                remediation = "Set the minimum protocol version to TLS 1.2.",
                category = "TLS"
            )
        }

        if (!tls.accepted.contains("TLSv1.3")) {
            findings += Finding(
                title = "TLS 1.3 not offered",
                severity = Severity.LOW,
                detail = "Accepted versions: ${tls.accepted.joinToString(", ")}. " +
                    "TLS 1.3 removes legacy primitives and shortens the handshake.",
                remediation = "Enable TLS 1.3 on the listener.",
                category = "TLS"
            )
        }

        tls.certDaysRemaining?.let { days ->
            when {
                days < 0 -> findings += Finding(
                    title = "Certificate expired",
                    severity = Severity.HIGH,
                    detail = "The presented certificate expired ${-days} day(s) ago.",
                    remediation = "Renew the certificate and verify automated renewal.",
                    category = "TLS"
                )

                days <= 30 -> findings += Finding(
                    title = "Certificate expires in $days day(s)",
                    severity = if (days <= 7) Severity.MEDIUM else Severity.LOW,
                    detail = "Issuer: ${tls.certIssuer ?: "unknown"}.",
                    remediation = "Confirm that automated renewal is running.",
                    category = "TLS"
                )
            }
        }

        findings += Finding(
            title = "TLS profile",
            severity = Severity.INFO,
            detail = buildString {
                append("Accepted: ${tls.accepted.joinToString(", ")}. ")
                if (tls.rejected.isNotEmpty()) append("Refused: ${tls.rejected.joinToString(", ")}. ")
                if (tls.untestable.isNotEmpty()) {
                    append("Not testable on this device: ${tls.untestable.joinToString(", ")}. ")
                }
                tls.cipherSuite?.let { append("Negotiated suite: $it. ") }
                tls.certSubject?.let { append("Subject: $it. ") }
                if (tls.certAltNames > 0) append("${tls.certAltNames} SAN entries.")
            },
            remediation = "Informational.",
            category = "TLS"
        )

        return findings
    }

    // ----------------------------------------------------------- security.txt

    private fun analyzeSecurityTxt(txt: SecurityTxt): List<Finding> {
        if (!txt.found) {
            return listOf(
                Finding(
                    title = "No security.txt published",
                    severity = Severity.LOW,
                    detail = "Neither /.well-known/security.txt nor /security.txt returned a " +
                        "policy. RFC 9116 defines this file so researchers know where to send " +
                        "vulnerability reports.",
                    remediation = "Publish /.well-known/security.txt with Contact and Expires fields.",
                    category = "Disclosure"
                )
            )
        }

        val findings = mutableListOf<Finding>()

        if (txt.contacts.isEmpty()) {
            findings += Finding(
                title = "security.txt has no Contact field",
                severity = Severity.MEDIUM,
                detail = "RFC 9116 requires at least one Contact field; the published file has none.",
                remediation = "Add a Contact field (mailto:, https: or tel: URI).",
                category = "Disclosure"
            )
        }

        when (txt.expired) {
            true -> findings += Finding(
                title = "security.txt has expired",
                severity = Severity.LOW,
                detail = "The Expires field is ${txt.expires}, which is in the past. " +
                    "Clients are expected to disregard an expired policy.",
                remediation = "Refresh the Expires field (RFC 9116 suggests under a year out).",
                category = "Disclosure"
            )

            null -> if (txt.expires == null) {
                findings += Finding(
                    title = "security.txt has no Expires field",
                    severity = Severity.LOW,
                    detail = "Expires is a required field under RFC 9116.",
                    remediation = "Add an ISO-8601 Expires timestamp.",
                    category = "Disclosure"
                )
            } else {
                findings += Finding(
                    title = "security.txt Expires value is unparseable",
                    severity = Severity.LOW,
                    detail = "Could not read \"${txt.expires}\" as an ISO-8601 timestamp.",
                    remediation = "Use a format such as 2027-01-01T00:00:00.000Z.",
                    category = "Disclosure"
                )
            }

            false -> findings += Finding(
                title = "security.txt published",
                severity = Severity.INFO,
                detail = buildString {
                    append("Found at ${txt.url}. ")
                    append("Contact: ${txt.contacts.joinToString(", ")}. ")
                    append("Valid until ${txt.expires}.")
                    txt.policy?.let { append(" Policy: $it.") }
                },
                remediation = "Informational.",
                category = "Disclosure"
            )
        }

        return findings
    }
}
