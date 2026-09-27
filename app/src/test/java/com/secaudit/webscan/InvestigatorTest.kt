package com.secaudit.webscan

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.RuStrings
import com.secaudit.webscan.model.Confidence
import com.secaudit.webscan.model.LeadId
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TlsInfo
import com.secaudit.webscan.scanner.Evidence
import com.secaudit.webscan.scanner.Investigator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InvestigatorTest {

    private val investigator = Investigator(EnStrings)

    private fun evidence(
        isHttps: Boolean = true,
        headers: Map<String, String> = emptyMap(),
        cookies: List<String> = emptyList(),
        tls: TlsInfo? = null,
        securityTxt: SecurityTxt? = null
    ) = Evidence(
        finalUrl = "https://example.test/",
        host = "example.test",
        isHttps = isHttps,
        status = 200,
        headers = headers,
        setCookies = cookies,
        tls = tls,
        securityTxt = securityTxt
    )

    private val hardenedHeaders = mapOf(
        "strict-transport-security" to "max-age=31536000",
        "content-security-policy" to "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options" to "nosniff",
        "referrer-policy" to "strict-origin-when-cross-origin",
        "permissions-policy" to "geolocation=()"
    )

    private fun leadIds(evidence: Evidence) =
        investigator.investigate(evidence).leads.map { it.id }

    private fun lead(evidence: Evidence, id: LeadId) =
        investigator.investigate(evidence).leads.first { it.id == id }

    @Test
    fun `insecure cookie without HSTS is reported as a high severity chain`() {
        val lead = lead(
            evidence(cookies = listOf("SESSIONID=abc; Path=/")),
            LeadId.COOKIE_PLAINTEXT_CHAIN
        )

        assertEquals(Severity.HIGH, lead.severity)
        assertEquals(Confidence.HIGH, lead.confidence)
        assertTrue(lead.evidence.any { it.contains("SESSIONID") })
        assertTrue(lead.evidence.any { it.contains("Strict-Transport-Security") })
    }

    @Test
    fun `HSTS downgrades the cookie chain but does not clear it`() {
        val lead = lead(
            evidence(
                headers = mapOf("strict-transport-security" to "max-age=31536000"),
                cookies = listOf("SESSIONID=abc; Path=/")
            ),
            LeadId.COOKIE_PLAINTEXT_CHAIN
        )

        assertEquals(Severity.MEDIUM, lead.severity)
        assertEquals(Confidence.MEDIUM, lead.confidence)
    }

    @Test
    fun `a cookie marked Secure produces no exposure chain`() {
        val ids = leadIds(
            evidence(
                headers = hardenedHeaders,
                cookies = listOf("SESSIONID=abc; Secure; HttpOnly; SameSite=Lax")
            )
        )
        assertFalse(ids.contains(LeadId.COOKIE_PLAINTEXT_CHAIN))
    }

    @Test
    fun `four or more absent headers imply no hardening layer was configured`() {
        assertTrue(leadIds(evidence()).contains(LeadId.NO_HARDENING_LAYER))
    }

    @Test
    fun `fully hardened headers produce no hardening lead`() {
        assertFalse(leadIds(evidence(headers = hardenedHeaders)).contains(LeadId.NO_HARDENING_LAYER))
    }

    @Test
    fun `legacy and modern TLS together are flagged as a downgrade surface`() {
        val lead = lead(
            evidence(
                headers = hardenedHeaders,
                tls = TlsInfo(
                    accepted = listOf("TLSv1", "TLSv1.1", "TLSv1.2"),
                    bestVersion = "TLSv1.2"
                )
            ),
            LeadId.TLS_DOWNGRADE_SURFACE
        )

        assertEquals(Severity.HIGH, lead.severity)
        assertTrue(lead.evidence.any { it.contains("TLSv1.1") })
    }

    @Test
    fun `stale signals combine into an unmaintained deployment hypothesis`() {
        val lead = lead(
            evidence(
                headers = hardenedHeaders + ("server" to "nginx/1.18.0"),
                tls = TlsInfo(accepted = listOf("TLSv1", "TLSv1.2"), bestVersion = "TLSv1.2")
            ),
            LeadId.UNMAINTAINED
        )

        assertEquals(Confidence.HIGH, lead.confidence)
        assertTrue(lead.evidence.any { it.contains("nginx 1.18.0") })
        assertTrue(lead.evidence.any { it.contains("TLSv1") })
    }

    @Test
    fun `a current server version is not treated as outdated`() {
        val ids = leadIds(
            evidence(
                headers = hardenedHeaders + ("server" to "nginx/1.27.0"),
                tls = TlsInfo(accepted = listOf("TLSv1.2", "TLSv1.3"), bestVersion = "TLSv1.3")
            )
        )
        assertFalse(ids.contains(LeadId.UNMAINTAINED))
    }

    @Test
    fun `origin fingerprint passing through a CDN is correlated`() {
        val lead = lead(
            evidence(
                headers = hardenedHeaders + mapOf(
                    "cf-ray" to "7d2b",
                    "x-powered-by" to "PHP/8.3.0"
                )
            ),
            LeadId.EDGE_ORIGIN_LEAK
        )

        assertTrue(lead.evidence.any { it.contains("Cloudflare") })
        assertTrue(lead.evidence.any { it.contains("PHP/8.3.0") })
    }

    @Test
    fun `identifiable stack with no disclosure contact is correlated`() {
        val lead = lead(
            evidence(
                headers = hardenedHeaders + mapOf(
                    "server" to "nginx/1.27.0",
                    "x-powered-by" to "PHP/8.3.0"
                ),
                securityTxt = SecurityTxt(found = false)
            ),
            LeadId.FINGERPRINTABLE_NO_CONTACT
        )

        assertEquals(Severity.LOW, lead.severity)
        assertTrue(lead.evidence.any { it.contains("security.txt") })
    }

    @Test
    fun `a published contact clears the disclosure lead`() {
        val ids = leadIds(
            evidence(
                headers = hardenedHeaders + mapOf(
                    "server" to "nginx/1.27.0",
                    "x-powered-by" to "PHP/8.3.0"
                ),
                securityTxt = SecurityTxt(
                    found = true,
                    contacts = listOf("mailto:security@example.test"),
                    expired = false
                )
            )
        )
        assertFalse(ids.contains(LeadId.FINGERPRINTABLE_NO_CONTACT))
    }

    @Test
    fun `an expiring certificate is raised together with the missing contact`() {
        val lead = lead(
            evidence(
                headers = hardenedHeaders,
                tls = TlsInfo(
                    accepted = listOf("TLSv1.2", "TLSv1.3"),
                    certIssuer = "Example CA",
                    certDaysRemaining = 3
                )
            ),
            LeadId.CERTIFICATE_EXPIRY
        )

        assertEquals(Severity.HIGH, lead.severity)
        assertEquals(3, lead.evidence.size)
    }

    @Test
    fun `cookie names are used to infer the framework`() {
        val profile = investigator.investigate(
            evidence(
                headers = hardenedHeaders,
                cookies = listOf("laravel_session=x; Secure; HttpOnly; SameSite=Lax")
            )
        ).techProfile

        assertTrue(profile.stack.contains("Laravel"))
        assertEquals(1, profile.signals.size)
    }

    @Test
    fun `a clean target yields no leads`() {
        val investigation = investigator.investigate(cleanEvidence())

        assertTrue(investigation.leads.isEmpty())
        assertTrue(investigation.summary.isNotBlank())
    }

    @Test
    fun `the same evidence reaches the same conclusions in either language`() {
        val messy = evidence(
            headers = mapOf("server" to "nginx/1.18.0", "cf-ray" to "7d2b", "x-powered-by" to "PHP/7.4"),
            cookies = listOf("PHPSESSID=abc; Path=/"),
            tls = TlsInfo(
                accepted = listOf("TLSv1", "TLSv1.2"),
                bestVersion = "TLSv1.2",
                cipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA",
                certDaysRemaining = 2
            ),
            securityTxt = SecurityTxt(found = false)
        )

        val en = Investigator(EnStrings).investigate(messy)
        val ru = Investigator(RuStrings).investigate(messy)

        assertEquals(en.leads.map { it.id }, ru.leads.map { it.id })
        assertEquals(en.leads.map { it.severity }, ru.leads.map { it.severity })
        assertEquals(en.leads.map { it.confidence }, ru.leads.map { it.confidence })
        assertEquals(
            en.leads.map { it.evidence.size },
            ru.leads.map { it.evidence.size }
        )
        // The wording must actually differ, or nothing was translated.
        assertTrue(en.leads.isNotEmpty())
        assertTrue(en.leads.zip(ru.leads).all { (a, b) -> a.hypothesis != b.hypothesis })
    }

    @Test
    fun `a clean target reaches the same empty conclusion in either language`() {
        assertTrue(Investigator(RuStrings).investigate(cleanEvidence()).leads.isEmpty())
    }

    private fun cleanEvidence() = evidence(
        headers = hardenedHeaders + ("server" to "nginx/1.27.0"),
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
            expired = false
        )
    )
}
