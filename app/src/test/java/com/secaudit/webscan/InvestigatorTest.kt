package com.secaudit.webscan

import com.secaudit.webscan.model.Confidence
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TlsInfo
import com.secaudit.webscan.scanner.Evidence
import com.secaudit.webscan.scanner.Investigator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InvestigatorTest {

    private val investigator = Investigator()

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

    private fun leadTitles(evidence: Evidence) =
        investigator.investigate(evidence).leads.map { it.hypothesis }

    @Test
    fun `insecure cookie without HSTS is reported as a high severity chain`() {
        val lead = investigator.investigate(
            evidence(cookies = listOf("SESSIONID=abc; Path=/"))
        ).leads.first { it.hypothesis.contains("plaintext") }

        assertEquals(Severity.HIGH, lead.severity)
        assertEquals(Confidence.HIGH, lead.confidence)
        assertTrue(lead.evidence.any { it.contains("SESSIONID") })
        assertTrue(lead.evidence.any { it.contains("Strict-Transport-Security") })
    }

    @Test
    fun `HSTS downgrades the cookie chain but does not clear it`() {
        val lead = investigator.investigate(
            evidence(
                headers = mapOf("strict-transport-security" to "max-age=31536000"),
                cookies = listOf("SESSIONID=abc; Path=/")
            )
        ).leads.first { it.hypothesis.contains("plaintext") }

        assertEquals(Severity.MEDIUM, lead.severity)
        assertEquals(Confidence.MEDIUM, lead.confidence)
    }

    @Test
    fun `a cookie marked Secure produces no exposure chain`() {
        val titles = leadTitles(
            evidence(
                headers = hardenedHeaders,
                cookies = listOf("SESSIONID=abc; Secure; HttpOnly; SameSite=Lax")
            )
        )
        assertTrue(titles.none { it.contains("plaintext") })
    }

    @Test
    fun `four or more absent headers imply no hardening layer was configured`() {
        val titles = leadTitles(evidence())
        assertTrue(titles.any { it.contains("browser-hardening layer") })
    }

    @Test
    fun `fully hardened headers produce no hardening lead`() {
        val titles = leadTitles(evidence(headers = hardenedHeaders))
        assertTrue(titles.none { it.contains("browser-hardening layer") })
    }

    @Test
    fun `legacy and modern TLS together are flagged as a downgrade surface`() {
        val lead = investigator.investigate(
            evidence(
                headers = hardenedHeaders,
                tls = TlsInfo(
                    accepted = listOf("TLSv1", "TLSv1.1", "TLSv1.2"),
                    bestVersion = "TLSv1.2"
                )
            )
        ).leads.first { it.hypothesis.contains("deprecated versions") }

        assertEquals(Severity.HIGH, lead.severity)
        assertTrue(lead.evidence.any { it.contains("TLSv1.1") })
    }

    @Test
    fun `stale signals combine into an unmaintained deployment hypothesis`() {
        val investigation = investigator.investigate(
            evidence(
                headers = hardenedHeaders + ("server" to "nginx/1.18.0"),
                tls = TlsInfo(accepted = listOf("TLSv1", "TLSv1.2"), bestVersion = "TLSv1.2")
            )
        )
        val lead = investigation.leads.first { it.hypothesis.contains("not been maintained") }

        assertEquals(Confidence.HIGH, lead.confidence)
        assertTrue(lead.evidence.any { it.contains("nginx 1.18.0") })
        assertTrue(lead.evidence.any { it.contains("TLSv1") })
    }

    @Test
    fun `a current server version is not treated as outdated`() {
        val titles = leadTitles(
            evidence(
                headers = hardenedHeaders + ("server" to "nginx/1.27.0"),
                tls = TlsInfo(accepted = listOf("TLSv1.2", "TLSv1.3"), bestVersion = "TLSv1.3")
            )
        )
        assertTrue(titles.none { it.contains("not been maintained") })
    }

    @Test
    fun `origin fingerprint passing through a CDN is correlated`() {
        val lead = investigator.investigate(
            evidence(
                headers = hardenedHeaders + mapOf(
                    "cf-ray" to "7d2b",
                    "x-powered-by" to "PHP/8.3.0"
                )
            )
        ).leads.first { it.hypothesis.contains("fingerprint passes straight through") }

        assertTrue(lead.evidence.any { it.contains("Cloudflare") })
        assertTrue(lead.evidence.any { it.contains("PHP/8.3.0") })
    }

    @Test
    fun `identifiable stack with no disclosure contact is correlated`() {
        val lead = investigator.investigate(
            evidence(
                headers = hardenedHeaders + mapOf(
                    "server" to "nginx/1.27.0",
                    "x-powered-by" to "PHP/8.3.0"
                ),
                securityTxt = SecurityTxt(found = false)
            )
        ).leads.first { it.hypothesis.contains("no published way to report") }

        assertEquals(Severity.LOW, lead.severity)
        assertTrue(lead.evidence.any { it.contains("No security.txt") })
    }

    @Test
    fun `a published contact clears the disclosure lead`() {
        val titles = leadTitles(
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
        assertTrue(titles.none { it.contains("no published way to report") })
    }

    @Test
    fun `an expiring certificate is raised together with the missing contact`() {
        val lead = investigator.investigate(
            evidence(
                headers = hardenedHeaders,
                tls = TlsInfo(
                    accepted = listOf("TLSv1.2", "TLSv1.3"),
                    certIssuer = "Example CA",
                    certDaysRemaining = 3
                )
            )
        ).leads.first { it.hypothesis.contains("close to expiry") }

        assertEquals(Severity.HIGH, lead.severity)
        assertTrue(lead.evidence.any { it.contains("No published security contact") })
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
        assertTrue(profile.signals.any { it.source == "Cookie name" })
    }

    @Test
    fun `a clean target yields no leads and says so`() {
        val investigation = investigator.investigate(
            evidence(
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
        )

        assertTrue(investigation.leads.isEmpty())
        assertTrue(investigation.summary.contains("not a clean bill of health"))
    }
}
