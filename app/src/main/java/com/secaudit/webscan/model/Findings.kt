package com.secaudit.webscan.model

/**
 * Severity of a single finding, used for sorting and colouring in the UI.
 * [key] resolves to the localised label; the enum itself is language-neutral.
 */
enum class Severity(val key: String, val weight: Int) {
    HIGH("sev.high", 3),
    MEDIUM("sev.medium", 2),
    LOW("sev.low", 1),
    INFO("sev.info", 0)
}

/** How strongly the collected evidence supports a correlated conclusion. */
enum class Confidence(val key: String) {
    HIGH("conf.high"),
    MEDIUM("conf.medium"),
    LOW("conf.low")
}

/** Grouping shown on a finding's chip. */
enum class Category(val key: String) {
    TRANSPORT("cat.transport"),
    HEADERS("cat.headers"),
    COOKIES("cat.cookies"),
    TLS("cat.tls"),
    DNS("cat.dns"),
    CONTENT("cat.content"),
    DISCLOSURE("cat.disclosure"),
    GENERAL("cat.general")
}

/**
 * Stable identity of a correlated conclusion, independent of the display
 * language. Tests and any future export format key off this rather than prose.
 */
enum class LeadId {
    UNMAINTAINED,
    COOKIE_PLAINTEXT_CHAIN,
    NO_HARDENING_LAYER,
    EDGE_ORIGIN_LEAK,
    FINGERPRINTABLE_NO_CONTACT,
    CERTIFICATE_EXPIRY,
    TLS_DOWNGRADE_SURFACE,
    WEAK_CIPHER
}

/**
 * A single observation produced by a passive check. Every finding is descriptive:
 * it reports what the server exposed and why it matters, plus a remediation hint.
 * No finding represents an attack or an attempt to exploit the target.
 */
data class Finding(
    val title: String,
    val severity: Severity,
    val detail: String,
    val remediation: String,
    val category: Category = Category.GENERAL
)

/**
 * A conclusion the investigator drew by combining several independent
 * observations that are individually weak but together point somewhere.
 * This is the "detective" layer: [evidence] is the chain of clues, and
 * [soWhat] explains the consequence.
 */
data class Lead(
    val id: LeadId,
    val hypothesis: String,
    val confidence: Confidence,
    val severity: Severity,
    val evidence: List<String>,
    val soWhat: String
)

/** One weak signal that hints at a technology in the stack. */
data class TechSignal(
    val source: String,
    val value: String,
    val implies: String
)

/** The stack inferred by correlating many weak [TechSignal]s. */
data class TechProfile(
    val stack: List<String>,
    val signals: List<TechSignal>
) {
    val isEmpty: Boolean get() = stack.isEmpty() && signals.isEmpty()
}

/** Result of the handshake-only TLS capability probe. */
data class TlsInfo(
    val accepted: List<String> = emptyList(),
    val rejected: List<String> = emptyList(),
    val untestable: List<String> = emptyList(),
    val bestVersion: String? = null,
    val cipherSuite: String? = null,
    val certSubject: String? = null,
    val certIssuer: String? = null,
    val certExpiresEpochMs: Long? = null,
    val certDaysRemaining: Long? = null,
    val certAltNames: Int = 0,
    val certSigAlg: String? = null,
    val certKeyType: String? = null,
    val certKeyBits: Int = 0,
    val certChainLength: Int = 0,
    val certCoversHost: Boolean? = null,
    val error: String? = null
) {
    val reachable: Boolean get() = accepted.isNotEmpty()
}

/** Parsed `/.well-known/security.txt` (RFC 9116). */
data class SecurityTxt(
    val found: Boolean = false,
    val url: String? = null,
    val contacts: List<String> = emptyList(),
    val expires: String? = null,
    val expired: Boolean? = null,
    val policy: String? = null,
    val encryption: String? = null,
    val preferredLanguages: String? = null,
    val canonical: String? = null
)

/** Aggregate result of scanning one target URL. */
data class ScanReport(
    val target: String,
    val finalUrl: String,
    val httpStatus: Int,
    val findings: List<Finding>,
    val leads: List<Lead> = emptyList(),
    val caseSummary: String = "",
    val techProfile: TechProfile = TechProfile(emptyList(), emptyList()),
    val tls: TlsInfo? = null,
    val securityTxt: SecurityTxt? = null,
    val dns: DnsInfo? = null,
    val startedAtEpochMs: Long,
    val durationMs: Long
) {
    val score: Int
        get() {
            var s = 100
            findings.forEach {
                s -= when (it.severity) {
                    Severity.HIGH -> 20
                    Severity.MEDIUM -> 10
                    Severity.LOW -> 4
                    Severity.INFO -> 0
                }
            }
            return s.coerceIn(0, 100)
        }

    val grade: Grade get() = Grade.of(score, findings.any { it.severity == Severity.HIGH })
}

/** UI state for the scan screen. */
sealed interface ScanState {
    data object Idle : ScanState
    data class Running(val message: String) : ScanState
    data class Done(val report: ScanReport) : ScanState
    data class Error(val message: String) : ScanState
}
