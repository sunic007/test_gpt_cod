package com.secaudit.webscan

import com.secaudit.webscan.scanner.TlsProbe
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards the SNI decision. A crash here would have mislabelled a perfectly
 * reachable IP-addressed or underscore-named host as refusing every TLS version.
 */
class TlsProbeTest {

    @Test
    fun `real hostnames use SNI`() {
        assertTrue(TlsProbe.isValidSniHost("example.com"))
        assertTrue(TlsProbe.isValidSniHost("sub.example.co.uk"))
        assertTrue(TlsProbe.isValidSniHost("xn--80ak6aa92e.com"))
        assertTrue(TlsProbe.isValidSniHost("a.b"))
    }

    @Test
    fun `ip literals do not use SNI`() {
        assertFalse(TlsProbe.isValidSniHost("192.168.0.1"))
        assertFalse(TlsProbe.isValidSniHost("8.8.8.8"))
        assertFalse(TlsProbe.isValidSniHost("::1"))
        assertFalse(TlsProbe.isValidSniHost("2001:db8::1"))
    }

    @Test
    fun `names sni cannot carry are rejected`() {
        assertFalse(TlsProbe.isValidSniHost(""))
        assertFalse(TlsProbe.isValidSniHost("   "))
        assertFalse(TlsProbe.isValidSniHost("example.com."))
        assertFalse(TlsProbe.isValidSniHost("under_score.example.com"))
        assertFalse(TlsProbe.isValidSniHost("-leadinghyphen.com"))
        assertFalse(TlsProbe.isValidSniHost("a".repeat(254)))
    }

    @Test
    fun `exact san entries match the host`() {
        assertTrue(TlsProbe.hostMatchesSan("example.com", listOf("example.com")))
        assertTrue(TlsProbe.hostMatchesSan("EXAMPLE.com", listOf("example.com.")))
        assertFalse(TlsProbe.hostMatchesSan("example.com", listOf("other.com")))
    }

    @Test
    fun `wildcard san covers one label only`() {
        val san = listOf("*.example.com")
        assertTrue(TlsProbe.hostMatchesSan("api.example.com", san))
        assertFalse(TlsProbe.hostMatchesSan("example.com", san))         // apex not covered
        assertFalse(TlsProbe.hostMatchesSan("a.b.example.com", san))     // two labels
    }

    @Test
    fun `host is matched against any san entry`() {
        val san = listOf("www.example.com", "*.cdn.example.com")
        assertTrue(TlsProbe.hostMatchesSan("x.cdn.example.com", san))
        assertTrue(TlsProbe.hostMatchesSan("www.example.com", san))
        assertFalse(TlsProbe.hostMatchesSan("example.com", san))
    }
}
