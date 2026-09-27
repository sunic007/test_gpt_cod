package com.secaudit.webscan

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.RuStrings
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.TlsInfo
import com.secaudit.webscan.scanner.RawObservations
import com.secaudit.webscan.scanner.ReportBuilder
import com.secaudit.webscan.scanner.ReportExporter
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportExporterTest {

    private fun sampleReport(strings: com.secaudit.webscan.i18n.Strings) =
        ReportBuilder(strings).build(
            RawObservations(
                target = "example.test",
                finalUrl = "https://example.test/",
                host = "example.test",
                isHttps = true,
                status = 200,
                headers = emptyMap(),
                cookies = listOf("SID=x; Path=/"),
                tls = TlsInfo(accepted = listOf("TLSv1", "TLSv1.2"), bestVersion = "TLSv1.2"),
                securityTxt = SecurityTxt(found = false),
                dns = null,
                mixedContent = emptyList(),
                startedAtEpochMs = 0L,
                durationMs = 100L
            )
        )

    @Test
    fun `export contains the url, grade and findings`() {
        val report = sampleReport(EnStrings)
        val text = ReportExporter(EnStrings).toPlainText(report)

        assertTrue(text.contains("https://example.test/"))
        assertTrue(text.contains(report.grade.label))
        assertTrue(text.contains(EnStrings.t("ui.sec.observations")))
        // every finding title should appear
        assertTrue(report.findings.all { text.contains(it.title) })
    }

    @Test
    fun `export follows the chosen language`() {
        val report = sampleReport(RuStrings)
        val text = ReportExporter(RuStrings).toPlainText(report)
        assertTrue(text.contains(RuStrings.t("ui.sec.observations")))
    }
}
