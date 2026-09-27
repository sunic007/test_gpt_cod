package com.secaudit.webscan.model

/** Severity of a single finding, used for sorting and colouring in the UI. */
enum class Severity(val label: String, val weight: Int) {
    HIGH("High", 3),
    MEDIUM("Medium", 2),
    LOW("Low", 1),
    INFO("Info", 0)
}

/** How strongly the collected evidence supports a correlated conclusion. */
enum class Confidence(val label: String) {
    HIGH("Strong"),
    MEDIUM("Probable"),
    LOW("Tentative")
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
    val category: String = "General"
)

/**
 * A conclusion the investigator drew by combining several independent
 * observations that are individually weak but together point somewhere.
 * This is the "detective" layer: [evidence] is the chain of clues, and
 * [soWhat] explains the consequence.
 */
data class Lead(
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
}

/** UI state for the scan screen. */
sealed interface ScanState {
    data object Idle : ScanState
    data class Running(val message: String) : ScanState
    data class Done(val report: ScanReport) : ScanState
    data class Error(val message: String) : ScanState
}
