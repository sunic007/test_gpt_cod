package com.secaudit.webscan.scanner

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.Category
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
            raw.tls?.let { addAll(analyzeTls(it)) }
            addAll(analyzeSecurityTxt(raw.securityTxt))
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
                tls.certSubject?.let { append(s.t("f.tlsprofile.subject", it)) }
                if (tls.certAltNames > 0) append(s.t("f.tlsprofile.sans", tls.certAltNames))
            },
            remediation = s.t("f.info.fix"),
            category = Category.TLS
        )

        return findings
    }

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
