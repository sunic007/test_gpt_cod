package com.secaudit.webscan

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.RuStrings
import com.secaudit.webscan.model.Category
import com.secaudit.webscan.model.DnsInfo
import com.secaudit.webscan.model.Grade
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TlsInfo
import com.secaudit.webscan.scanner.RawObservations
import com.secaudit.webscan.scanner.ReportBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportBuilderTest {

    private fun observations(
        finalUrl: String = "https://example.test/",
        isHttps: Boolean = true,
        headers: Map<String, String> = emptyMap(),
        cookies: List<String> = emptyList(),
        tls: TlsInfo? = null,
        securityTxt: SecurityTxt = SecurityTxt(found = false),
        dns: DnsInfo? = null,
        mixedContent: List<String> = emptyList()
    ) = RawObservations(
        target = finalUrl,
        finalUrl = finalUrl,
        host = "example.test",
        isHttps = isHttps,
        status = 200,
        headers = headers,
        cookies = cookies,
        tls = tls,
        securityTxt = securityTxt,
        dns = dns,
        mixedContent = mixedContent,
        startedAtEpochMs = 0L,
        durationMs = 120L
    )

    private val hardenedHeaders = mapOf(
        "strict-transport-security" to "max-age=31536000",
        "content-security-policy" to "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options" to "nosniff",
        "referrer-policy" to "strict-origin-when-cross-origin",
        "permissions-policy" to "geolocation=()"
    )

    @Test
    fun `plain HTTP is reported as a high severity transport problem`() {
        val report = ReportBuilder(EnStrings).build(
            observations(finalUrl = "http://example.test/", isHttps = false)
        )
        val finding = report.findings.first { it.category == Category.TRANSPORT }

        assertEquals(Severity.HIGH, finding.severity)
        assertTrue(finding.detail.contains("http://example.test/"))
    }

    @Test
    fun `an absent disclosure policy is reported`() {
        val report = ReportBuilder(EnStrings).build(observations(headers = hardenedHeaders))
        assertTrue(report.findings.any { it.category == Category.DISCLOSURE })
    }

    @Test
    fun `a hardened site scores well`() {
        val report = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                cookies = listOf("id=x; Secure; HttpOnly; SameSite=Lax"),
                tls = TlsInfo(
                    accepted = listOf("TLSv1.2", "TLSv1.3"),
                    bestVersion = "TLSv1.3",
                    cipherSuite = "TLS_AES_256_GCM_SHA384",
                    certDaysRemaining = 200
                ),
                securityTxt = SecurityTxt(
                    found = true,
                    contacts = listOf("mailto:security@example.test"),
                    expires = "2027-01-01T00:00:00.000Z",
                    expired = false
                )
            )
        )

        assertTrue("score was ${report.score}", report.score >= 90)
        assertTrue(report.leads.isEmpty())
        assertFalse(report.findings.any { it.severity == Severity.HIGH })
    }

    @Test
    fun `switching language rewords the report without changing its conclusions`() {
        val raw = observations(
            headers = mapOf("server" to "nginx/1.18.0", "x-powered-by" to "PHP/7.4"),
            cookies = listOf("PHPSESSID=abc; Path=/"),
            tls = TlsInfo(accepted = listOf("TLSv1", "TLSv1.2"), bestVersion = "TLSv1.2")
        )

        val en = ReportBuilder(EnStrings).build(raw)
        val ru = ReportBuilder(RuStrings).build(raw)

        assertEquals(en.score, ru.score)
        assertEquals(en.findings.map { it.severity }, ru.findings.map { it.severity })
        assertEquals(en.findings.map { it.category }, ru.findings.map { it.category })
        assertEquals(en.leads.map { it.id }, ru.leads.map { it.id })

        // And the prose really did change.
        assertTrue(en.findings.isNotEmpty())
        assertTrue(en.caseSummary != ru.caseSummary)
        assertTrue(
            en.findings.zip(ru.findings).any { (a, b) -> a.title != b.title }
        )
    }

    @Test
    fun `deprecated TLS surfaces as a high severity finding`() {
        val report = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                tls = TlsInfo(accepted = listOf("TLSv1", "TLSv1.2"), bestVersion = "TLSv1.2")
            )
        )
        val tlsFindings = report.findings.filter { it.category == Category.TLS }

        assertTrue(tlsFindings.any { it.severity == Severity.HIGH })
        assertTrue(tlsFindings.any { it.severity == Severity.INFO })
    }

    @Test
    fun `a weak certificate signature and key are high severity`() {
        val report = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                tls = TlsInfo(
                    accepted = listOf("TLSv1.2", "TLSv1.3"),
                    certSigAlg = "SHA1withRSA",
                    certKeyType = "RSA",
                    certKeyBits = 1024
                )
            )
        )
        val tls = report.findings.filter { it.category == Category.TLS }
        assertTrue(tls.any { it.severity == Severity.HIGH && it.title.contains("signature") })
        assertTrue(tls.any { it.severity == Severity.HIGH && it.title.contains("key") })
    }

    @Test
    fun `a certificate not covering the host is flagged`() {
        val report = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                tls = TlsInfo(accepted = listOf("TLSv1.3"), certCoversHost = false)
            )
        )
        assertTrue(report.findings.any { it.title.contains("Host not listed") })
    }

    @Test
    fun `mixed content is reported with a count`() {
        val report = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                mixedContent = listOf("http://a.test/x.js", "http://a.test/y.css")
            )
        )
        val mixed = report.findings.first { it.category == Category.CONTENT }
        assertEquals(Severity.MEDIUM, mixed.severity)
        assertTrue(mixed.detail.contains("http://a.test/x.js"))
    }

    @Test
    fun `dns gaps are reported and a clean domain is not`() {
        val weak = ReportBuilder(EnStrings).build(
            observations(headers = hardenedHeaders, dns = DnsInfo(queried = true))
        )
        assertTrue(weak.findings.any { it.category == Category.DNS && it.title.contains("SPF") })
        assertTrue(weak.findings.any { it.category == Category.DNS && it.title.contains("DMARC") })

        val clean = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                dns = DnsInfo(
                    queried = true,
                    caaRecords = listOf("0 issue \"letsencrypt.org\""),
                    dnssec = true,
                    spf = "v=spf1 -all",
                    dmarcPresent = true,
                    dmarcPolicy = "reject"
                )
            )
        )
        // Only the INFO profile line remains, no LOW gaps.
        assertTrue(clean.findings.none { it.category == Category.DNS && it.severity == Severity.LOW })
    }

    @Test
    fun `a failed dns lookup adds no findings`() {
        val report = ReportBuilder(EnStrings).build(
            observations(headers = hardenedHeaders, dns = DnsInfo(queried = true, error = "boom"))
        )
        assertTrue(report.findings.none { it.category == Category.DNS })
    }

    @Test
    fun `grade reflects severity`() {
        val bad = ReportBuilder(EnStrings).build(
            observations(finalUrl = "http://example.test/", isHttps = false)
        )
        // Plain HTTP is a HIGH finding, so the grade cannot be an A.
        assertTrue(bad.grade.ordinal >= Grade.C.ordinal)
    }

    @Test
    fun `an expired security policy is reported as expired`() {
        val report = ReportBuilder(EnStrings).build(
            observations(
                headers = hardenedHeaders,
                securityTxt = SecurityTxt(
                    found = true,
                    url = "https://example.test/.well-known/security.txt",
                    contacts = listOf("mailto:security@example.test"),
                    expires = "2020-01-01T00:00:00.000Z",
                    expired = true
                )
            )
        )

        assertTrue(report.findings.any { it.detail.contains("2020-01-01T00:00:00.000Z") })
    }
}
