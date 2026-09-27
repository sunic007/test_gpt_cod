package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.Finding
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.util.concurrent.TimeUnit

/**
 * Passive web-security assessment.
 *
 * The scanner performs ONE ordinary GET request to the target (the same request a
 * browser makes when you open the page) and then inspects the response metadata:
 * transport, HTTP security headers, and cookie attributes. It sends no attack
 * payloads, does not fuzz parameters, does not brute-force anything, and issues no
 * repeated/high-volume traffic. It is intended for sites you own or are explicitly
 * authorised to test.
 */
class WebScanner {

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .retryOnConnectionFailure(false)
        .build()

    /** Normalises user input into a valid absolute URL, defaulting to https://. */
    fun normalizeTarget(raw: String): String {
        val trimmed = raw.trim()
        return when {
            trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true) -> trimmed
            else -> "https://$trimmed"
        }
    }

    suspend fun scan(rawTarget: String): ScanReport = withContext(Dispatchers.IO) {
        val target = normalizeTarget(rawTarget)
        val started = System.currentTimeMillis()

        val request = Request.Builder()
            .url(target)
            .header("User-Agent", "WebSecAudit/1.0 (passive security header check)")
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            val findings = analyze(target, response)
            ScanReport(
                target = target,
                finalUrl = response.request.url.toString(),
                httpStatus = response.code,
                findings = findings.sortedByDescending { it.severity.weight },
                startedAtEpochMs = started,
                durationMs = System.currentTimeMillis() - started
            )
        }
    }

    private fun analyze(target: String, response: Response): List<Finding> {
        val findings = mutableListOf<Finding>()
        val headers = response.headers
        fun header(name: String): String? = headers[name]

        val finalUrl = response.request.url
        val isHttps = finalUrl.isHttps

        // --- Transport security -------------------------------------------------
        if (!isHttps) {
            findings += Finding(
                title = "Site not served over HTTPS",
                severity = Severity.HIGH,
                detail = "The final response was delivered over plain HTTP ($finalUrl). " +
                    "Traffic can be read or modified in transit.",
                remediation = "Serve all content over HTTPS and redirect HTTP to HTTPS."
            )
        }

        // --- HSTS ---------------------------------------------------------------
        val hsts = header("Strict-Transport-Security")
        if (isHttps && hsts.isNullOrBlank()) {
            findings += Finding(
                title = "Missing Strict-Transport-Security (HSTS)",
                severity = Severity.MEDIUM,
                detail = "No HSTS header. Browsers may fall back to HTTP on the first visit.",
                remediation = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            )
        }

        // --- Content-Security-Policy -------------------------------------------
        if (header("Content-Security-Policy").isNullOrBlank()) {
            findings += Finding(
                title = "Missing Content-Security-Policy",
                severity = Severity.MEDIUM,
                detail = "No CSP header. CSP is a key defence against XSS and data injection.",
                remediation = "Define a Content-Security-Policy tailored to your resources."
            )
        }

        // --- X-Frame-Options / frame-ancestors ---------------------------------
        val csp = header("Content-Security-Policy").orEmpty()
        if (header("X-Frame-Options").isNullOrBlank() && !csp.contains("frame-ancestors", true)) {
            findings += Finding(
                title = "Clickjacking protection not set",
                severity = Severity.MEDIUM,
                detail = "Neither X-Frame-Options nor CSP frame-ancestors is present.",
                remediation = "Add X-Frame-Options: DENY or a CSP frame-ancestors directive."
            )
        }

        // --- X-Content-Type-Options --------------------------------------------
        if (!header("X-Content-Type-Options").equals("nosniff", true)) {
            findings += Finding(
                title = "MIME sniffing not disabled",
                severity = Severity.LOW,
                detail = "X-Content-Type-Options: nosniff is missing.",
                remediation = "Add: X-Content-Type-Options: nosniff"
            )
        }

        // --- Referrer-Policy ----------------------------------------------------
        if (header("Referrer-Policy").isNullOrBlank()) {
            findings += Finding(
                title = "No Referrer-Policy",
                severity = Severity.LOW,
                detail = "Without a Referrer-Policy, full URLs may leak to third parties.",
                remediation = "Add: Referrer-Policy: strict-origin-when-cross-origin"
            )
        }

        // --- Permissions-Policy -------------------------------------------------
        if (header("Permissions-Policy").isNullOrBlank()) {
            findings += Finding(
                title = "No Permissions-Policy",
                severity = Severity.INFO,
                detail = "Permissions-Policy lets you disable powerful browser features.",
                remediation = "Consider restricting features, e.g. geolocation=(), camera=()."
            )
        }

        // --- Server / technology disclosure ------------------------------------
        val server = header("Server")
        if (!server.isNullOrBlank() && server.any { it.isDigit() }) {
            findings += Finding(
                title = "Server version disclosed",
                severity = Severity.LOW,
                detail = "Server header reveals software/version: \"$server\".",
                remediation = "Suppress version details in the Server header."
            )
        }
        val poweredBy = header("X-Powered-By")
        if (!poweredBy.isNullOrBlank()) {
            findings += Finding(
                title = "X-Powered-By disclosed",
                severity = Severity.LOW,
                detail = "X-Powered-By reveals backend technology: \"$poweredBy\".",
                remediation = "Remove the X-Powered-By header."
            )
        }

        // --- Cookie attributes --------------------------------------------------
        val cookies = headers.values("Set-Cookie")
        cookies.forEach { cookie ->
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
                    remediation = "Set Secure; HttpOnly; SameSite on session cookies."
                )
            }
        }

        if (findings.none { it.severity != Severity.INFO }) {
            findings += Finding(
                title = "No common header issues detected",
                severity = Severity.INFO,
                detail = "The passive checks found no missing security headers.",
                remediation = "Continue with authenticated and deeper testing where authorised."
            )
        }

        return findings
    }
}
