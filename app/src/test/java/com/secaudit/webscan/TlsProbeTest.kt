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
}
