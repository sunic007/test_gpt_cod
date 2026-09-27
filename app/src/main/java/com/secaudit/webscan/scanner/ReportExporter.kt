package com.secaudit.webscan.scanner

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.ScanReport
import com.secaudit.webscan.model.Severity

/**
 * Renders a finished [ScanReport] to shareable plain text.
 *
 * Pure and deterministic so it can be unit-tested; the report's findings are
 * already localised, so this only lays them out and adds a few section labels.
 */
class ReportExporter(private val s: Strings = EnStrings) {

    fun toPlainText(report: ScanReport): String = buildString {
        appendLine(s.t("ui.app.title"))
        appendLine(report.finalUrl)
        appendLine("${s.t("ui.grade")}: ${report.grade.label}   ${s.t("ui.score", report.score)}")
        appendLine(s.t("ui.meta", report.httpStatus, report.durationMs, report.findings.size))

        if (report.caseSummary.isNotBlank()) {
            appendLine()
            appendLine("== ${s.t("ui.case.title")} ==")
            appendLine(report.caseSummary)
        }

        if (report.leads.isNotEmpty()) {
            appendLine()
            appendLine("== ${s.t("ui.sec.investigation")} ==")
            report.leads.forEach { lead ->
                appendLine("[${s.t(lead.severity.key)}/${s.t(lead.confidence.key)}] ${lead.hypothesis}")
                lead.evidence.forEach { appendLine("   - $it") }
                appendLine("   => ${lead.soWhat}")
                appendLine()
            }
        }

        appendLine()
        appendLine("== ${s.t("ui.sec.observations")} ==")
        report.findings.forEach { f ->
            appendLine("[${s.t(f.severity.key)}] (${s.t(f.category.key)}) ${f.title}")
            appendLine("   ${f.detail}")
            if (f.severity != Severity.INFO) appendLine("   ${s.t("ui.fix", f.remediation)}")
        }
    }.trimEnd()
}
