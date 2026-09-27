package com.secaudit.webscan.model

/** Severity of a single finding, used for sorting and colouring in the UI. */
enum class Severity(val label: String, val weight: Int) {
    HIGH("High", 3),
    MEDIUM("Medium", 2),
    LOW("Low", 1),
    INFO("Info", 0)
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
    val remediation: String
)

/** Aggregate result of scanning one target URL. */
data class ScanReport(
    val target: String,
    val finalUrl: String,
    val httpStatus: Int,
    val findings: List<Finding>,
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
