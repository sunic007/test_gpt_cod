package com.secaudit.webscan.scanner

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.Category
import com.secaudit.webscan.model.DnsInfo
import com.secaudit.webscan.model.Finding
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TlsInfo

/**
 * Turns [RawObservations] into a written report in one language.
 *
 * Nothing here touches the network, so switching language re-renders an existing
 * report instantly instead of re-scanning the target.
 */
class ReportBuilder(private val s: Strings = EnStrings) {

    private val investigator = Investigator(s)

    fun build(raw: RawObservations): ScanReport {
        val findings = buildList {
            addAll(analyzeHeaders(raw))
            addAll(analyzeAdvancedHeaders(raw))
            raw.tls?.let { addAll(analyzeTls(it)) }
            addAll(analyzeMixedContent(raw))
            addAll(analyzeSecurityTxt(raw.securityTxt))
            raw.dns?.let { addAll(analyzeDns(it)) }
        }

        val investigation = investigator.investigate(
            Evidence(
                finalUrl = raw.finalUrl,
                host = raw.host,
                isHttps = raw.isHttps,
                status = raw.status,
                headers = raw.headers,
                setCookies = raw.cookies,
                tls = raw.tls,
                securityTxt = raw.securityTxt
            )
        )

        return ScanReport(
            target = raw.target,
            finalUrl = raw.finalUrl,
            httpStatus = raw.status,
            findings = findings.sortedByDescending { it.severity.weight },
            leads = investigation.leads,
            caseSummary = investigation.summary,
            techProfile = investigation.techProfile,
            tls = raw.tls,
            securityTxt = raw.securityTxt,
            dns = raw.dns,
            startedAtEpochMs = raw.startedAtEpochMs,
            durationMs = raw.durationMs
        )
    }

    /** Builds a finding whose title, detail and fix all come from one key prefix. */
    private fun finding(
        key: String,
        severity: Severity,
        category: Category,
        titleArgs: Array<out Any?> = emptyArray(),
        detailArgs: Array<out Any?> = emptyArray()
    ) = Finding(
        title = s.t("$key.title", *titleArgs),
        severity = severity,
        detail = s.t("$key.detail", *detailArgs),
        remediation = s.t("$key.fix"),
        category = category
    )

    // ---------------------------------------------------------------- headers

    private fun analyzeHeaders(raw: RawObservations): List<Finding> {
        val findings = mutableListOf<Finding>()
        val h = raw.headers
        val isHttps = raw.isHttps

        if (!isHttps) {
            findings += finding(
                "f.nohttps", Severity.HIGH, Category.TRANSPORT,
                detailArgs = arrayOf(raw.finalUrl)
            )
        }

        if (isHttps && h["strict-transport-security"].isNullOrBlank()) {
            findings += finding("f.hsts", Severity.MEDIUM, Category.TRANSPORT)
        }

        val csp = h["content-security-policy"].orEmpty()
        if (csp.isBlank()) {
            findings += finding("f.csp", Severity.MEDIUM, Category.HEADERS)
        }

        if (h["x-frame-options"].isNullOrBlank() && !csp.contains("frame-ancestors", true)) {
            findings += finding("f.frame", Severity.MEDIUM, Category.HEADERS)
        }

        if (!h["x-content-type-options"].equals("nosniff", true)) {
            findings += finding("f.nosniff", Severity.LOW, Category.HEADERS)
        }

        if (h["referrer-policy"].isNullOrBlank()) {
            findings += finding("f.referrer", Severity.LOW, Category.HEADERS)
        }

        if (h["permissions-policy"].isNullOrBlank()) {
            findings += finding("f.permissions", Severity.INFO, Category.HEADERS)
        }

        val server = h["server"]
        if (!server.isNullOrBlank() && server.any { it.isDigit() }) {
            findings += finding(
                "f.server", Severity.LOW, Category.DISCLOSURE,
                detailArgs = arrayOf(server)
            )
        }

        val poweredBy = h["x-powered-by"]
        if (!poweredBy.isNullOrBlank()) {
            findings += finding(
                "f.powered", Severity.LOW, Category.DISCLOSURE,
                detailArgs = arrayOf(poweredBy)
            )
        }

        raw.cookies.forEach { cookie ->
            val name = cookie.substringBefore('=').trim()
            val lower = cookie.lowercase()
            val issues = buildList {
                if (isHttps && !lower.contains("secure")) add(s.t("f.cookie.issue.secure"))
                if (!lower.contains("httponly")) add(s.t("f.cookie.issue.httponly"))
                if (!lower.contains("samesite")) add(s.t("f.cookie.issue.samesite"))
            }
            if (issues.isNotEmpty()) {
                findings += finding(
                    "f.cookie", Severity.MEDIUM, Category.COOKIES,
                    titleArgs = arrayOf(name),
                    detailArgs = arrayOf(issues.joinToString(", "))
                )
            }
        }

        return findings
    }

    // ------------------------------------------------ deep header hardening

    /**
     * The pedantic layer: quality of the security headers that ARE present, plus
     * CORS, cookie prefixes and deprecated headers. All read from the one response
     * already fetched — no extra requests, nothing active.
     */
    private fun analyzeAdvancedHeaders(raw: RawObservations): List<Finding> {
        val h = raw.headers
        val findings = mutableListOf<Finding>()

        // --- Content-Security-Policy quality (only when a CSP exists) ----------
        val csp = h["content-security-policy"].orEmpty().lowercase()
        if (csp.isNotBlank()) {
            if (csp.contains("'unsafe-inline'")) {
                findings += finding("f.cspinline", Severity.MEDIUM, Category.HEADERS)
            }
            if (csp.contains("'unsafe-eval'")) {
                findings += finding("f.cspeval", Severity.MEDIUM, Category.HEADERS)
            }
            if (hasWildcardSource(csp)) {
                findings += finding("f.cspwildcard", Severity.LOW, Category.HEADERS)
            }
            if (!csp.contains("base-uri")) {
                findings += finding("f.cspbaseuri", Severity.LOW, Category.HEADERS)
            }
        }

        // --- HSTS quality (only when HSTS exists) -----------------------------
        val hsts = h["strict-transport-security"].orEmpty().lowercase()
        if (hsts.isNotBlank()) {
            val maxAge = Regex("max-age\\s*=\\s*(\\d+)").find(hsts)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
            if (maxAge < 15_552_000L) { // < 180 days
                findings += finding(
                    "f.hstsshort", Severity.LOW, Category.TRANSPORT,
                    detailArgs = arrayOf(maxAge)
                )
            }
            if (!hsts.contains("includesubdomains")) {
                findings += finding("f.hstsnosub", Severity.LOW, Category.TRANSPORT)
            }
        }

        // --- CORS -------------------------------------------------------------
        val acao = h["access-control-allow-origin"].orEmpty().trim()
        val acac = h["access-control-allow-credentials"].equals("true", true)
        if (acao == "*" || (acao.isNotBlank() && acac)) {
            if (acac && acao != "*" && acao.isNotBlank()) {
                // Reflected/explicit origin WITH credentials — a real data-exposure risk.
                findings += finding(
                    "f.corscred", Severity.HIGH, Category.HEADERS,
                    detailArgs = arrayOf(acao)
                )
            } else if (acao == "*") {
                findings += finding("f.corswildcard", Severity.LOW, Category.HEADERS)
            }
        }

        // --- Cookie prefixes & SameSite=None ----------------------------------
        raw.cookies.forEach { cookie ->
            val name = cookie.substringBefore('=').trim()
            val lower = cookie.lowercase()
            val secure = "secure" in lower
            if (name.startsWith("__Host-") && !(secure && "path=/" in lower && "domain=" !in lower)) {
                findings += finding(
                    "f.cookiehost", Severity.MEDIUM, Category.COOKIES, titleArgs = arrayOf(name)
                )
            } else if (name.startsWith("__Secure-") && !secure) {
                findings += finding(
                    "f.cookiesecpfx", Severity.MEDIUM, Category.COOKIES, titleArgs = arrayOf(name)
                )
            }
            if ("samesite=none" in lower && !secure) {
                findings += finding(
                    "f.cookiesamenone", Severity.MEDIUM, Category.COOKIES, titleArgs = arrayOf(name)
                )
            }
        }

        // --- Deprecated / dangerous headers -----------------------------------
        if (!h["public-key-pins"].isNullOrBlank()) {
            findings += finding("f.hpkp", Severity.MEDIUM, Category.HEADERS)
        }
        val xss = h["x-xss-protection"]
        if (!xss.isNullOrBlank() && !xss.trim().startsWith("0")) {
            findings += finding("f.xxss", Severity.LOW, Category.HEADERS)
        }

        return findings
    }

    /** A bare `*` used as a source in default-src or script-src. */
    private fun hasWildcardSource(csp: String): Boolean =
        csp.split(';').map { it.trim() }.any { directive ->
            (directive.startsWith("default-src") || directive.startsWith("script-src")) &&
                directive.split(Regex("\\s+")).drop(1).any { it == "*" }
        }

    // -------------------------------------------------------------------- TLS

    private fun analyzeTls(tls: TlsInfo): List<Finding> {
        if (!tls.reachable) {
            return listOf(
                Finding(
                    title = s.t("f.tlsfail.title"),
                    severity = Severity.INFO,
                    detail = tls.error ?: s.t("ui.tls.nohandshake"),
                    remediation = s.t("f.tlsfail.fix"),
                    category = Category.TLS
                )
            )
        }

        val findings = mutableListOf<Finding>()

        val legacy = tls.accepted.filter { it == "TLSv1" || it == "TLSv1.1" }
        if (legacy.isNotEmpty()) {
            findings += finding(
                "f.tlsdeprecated", Severity.HIGH, Category.TLS,
                titleArgs = arrayOf(legacy.joinToString(", ")),
                detailArgs = arrayOf(legacy.joinToString(" / "))
            )
        }

        if (!tls.accepted.contains("TLSv1.3")) {
            findings += finding(
                "f.notls13", Severity.LOW, Category.TLS,
                detailArgs = arrayOf(tls.accepted.joinToString(", "))
            )
        }

        tls.certDaysRemaining?.let { days ->
            when {
                days < 0 -> findings += finding(
                    "f.certexpired", Severity.HIGH, Category.TLS,
                    detailArgs = arrayOf(-days)
                )

                days <= 30 -> findings += finding(
                    "f.certexpiring",
                    if (days <= 7) Severity.MEDIUM else Severity.LOW,
                    Category.TLS,
                    titleArgs = arrayOf(days),
                    detailArgs = arrayOf(tls.certIssuer ?: "—")
                )
            }
        }

        // Weak signature algorithm (SHA-1 / MD5 are collision-broken).
        tls.certSigAlg?.let { alg ->
            if (alg.contains("SHA1", true) || alg.contains("MD5", true)) {
                findings += finding(
                    "f.certweaksig", Severity.HIGH, Category.TLS,
                    detailArgs = arrayOf(alg)
                )
            }
        }

        // Under-strength key for its type.
        val weakKey = when (tls.certKeyType?.uppercase()) {
            "RSA", "DSA" -> tls.certKeyBits in 1 until 2048
            "EC" -> tls.certKeyBits in 1 until 256
            else -> false
        }
        if (weakKey) {
            findings += finding(
                "f.certweakkey", Severity.HIGH, Category.TLS,
                detailArgs = arrayOf(tls.certKeyType ?: "?", tls.certKeyBits)
            )
        }

        // Presented certificate does not list the host among its SAN entries.
        if (tls.certCoversHost == false) {
            findings += finding("f.certnohost", Severity.MEDIUM, Category.TLS)
        }

        findings += Finding(
            title = s.t("f.tlsprofile.title"),
            severity = Severity.INFO,
            detail = buildString {
                append(s.t("f.tlsprofile.accepted", tls.accepted.joinToString(", ")))
                if (tls.rejected.isNotEmpty()) {
                    append(s.t("f.tlsprofile.refused", tls.rejected.joinToString(", ")))
                }
                if (tls.untestable.isNotEmpty()) {
                    append(s.t("f.tlsprofile.untestable", tls.untestable.joinToString(", ")))
                }
                tls.cipherSuite?.let { append(s.t("f.tlsprofile.suite", it)) }
                if (tls.certKeyBits > 0) {
                    append(s.t("f.tlsprofile.key", tls.certKeyType ?: "?", tls.certKeyBits))
                }
                tls.certSigAlg?.let { append(s.t("f.tlsprofile.sig", it)) }
                if (tls.certChainLength > 0) append(s.t("f.tlsprofile.chain", tls.certChainLength))
                tls.certSubject?.let { append(s.t("f.tlsprofile.subject", it)) }
                if (tls.certAltNames > 0) append(s.t("f.tlsprofile.sans", tls.certAltNames))
            },
            remediation = s.t("f.info.fix"),
            category = Category.TLS
        )

        return findings
    }

    // ------------------------------------------------------------- mixed content

    private fun analyzeMixedContent(raw: RawObservations): List<Finding> {
        if (raw.mixedContent.isEmpty()) return emptyList()
        val sample = raw.mixedContent.take(5).joinToString("\n") { "• $it" }
        return listOf(
            finding(
                "f.mixed", Severity.MEDIUM, Category.CONTENT,
                titleArgs = arrayOf(raw.mixedContent.size),
                detailArgs = arrayOf(sample)
            )
        )
    }

    // --------------------------------------------------------------------- DNS

    private fun analyzeDns(dns: DnsInfo): List<Finding> {
        if (!dns.queried || dns.error != null) return emptyList()
        val findings = mutableListOf<Finding>()

        if (!dns.hasCaa) {
            findings += finding("f.nocaa", Severity.LOW, Category.DNS)
        }
        if (!dns.dnssec) {
            findings += finding("f.nodnssec", Severity.LOW, Category.DNS)
        }
        when {
            !dns.dmarcPresent ->
                findings += finding("f.nodmarc", Severity.LOW, Category.DNS)
            dns.dmarcPolicy == "none" ->
                findings += finding("f.dmarcnone", Severity.LOW, Category.DNS)
        }
        if (dns.spf == null) {
            findings += finding("f.nospf", Severity.LOW, Category.DNS)
        }

        findings += Finding(
            title = s.t("f.dnsprofile.title"),
            severity = Severity.INFO,
            detail = buildString {
                append(s.t("f.dnsprofile.caa", if (dns.hasCaa) dns.caaRecords.size else 0))
                append(s.t("f.dnsprofile.dnssec", yesNo(dns.dnssec)))
                append(s.t("f.dnsprofile.spf", yesNo(dns.spf != null)))
                append(s.t("f.dnsprofile.dmarc", dns.dmarcPolicy ?: yesNo(false)))
            },
            remediation = s.t("f.info.fix"),
            category = Category.DNS
        )

        return findings
    }

    private fun yesNo(v: Boolean) = s.t(if (v) "word.yes" else "word.no")

    // ----------------------------------------------------------- security.txt

    private fun analyzeSecurityTxt(txt: SecurityTxt): List<Finding> {
        if (!txt.found) {
            return listOf(finding("f.nostxt", Severity.LOW, Category.DISCLOSURE))
        }

        val findings = mutableListOf<Finding>()

        if (txt.contacts.isEmpty()) {
            findings += finding("f.stxtnocontact", Severity.MEDIUM, Category.DISCLOSURE)
        }

        when (txt.expired) {
            true -> findings += finding(
                "f.stxtexpired", Severity.LOW, Category.DISCLOSURE,
                detailArgs = arrayOf(txt.expires)
            )

            null -> findings += if (txt.expires == null) {
                finding("f.stxtnoexpires", Severity.LOW, Category.DISCLOSURE)
            } else {
                finding(
                    "f.stxtbadexpires", Severity.LOW, Category.DISCLOSURE,
                    detailArgs = arrayOf(txt.expires)
                )
            }

            false -> findings += Finding(
                title = s.t("f.stxtok.title"),
                severity = Severity.INFO,
                detail = buildString {
                    append(
                        s.t(
                            "f.stxtok.detail",
                            txt.url,
                            txt.contacts.joinToString(", "),
                            txt.expires
                        )
                    )
                    txt.policy?.let { append(s.t("f.stxtok.policy", it)) }
                },
                remediation = s.t("f.info.fix"),
                category = Category.DISCLOSURE
            )
        }

        return findings
    }
}
