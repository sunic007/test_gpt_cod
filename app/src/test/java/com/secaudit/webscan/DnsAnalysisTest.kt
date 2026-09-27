package com.secaudit.webscan

import com.secaudit.webscan.scanner.DnsAnalysis
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsAnalysisTest {

    @Test
    fun `extracts spf dmarc caa and dnssec`() {
        val info = DnsAnalysis.interpret(
            caa = listOf("0 issue \"letsencrypt.org\""),
            apexTxt = listOf("\"v=spf1 include:_spf.example.com -all\"", "\"other=1\""),
            dmarcTxt = listOf("\"v=DMARC1; p=reject; rua=mailto:a@b.test\""),
            dnssecAuthenticated = true
        )

        assertTrue(info.queried)
        assertTrue(info.hasCaa)
        assertTrue(info.dnssec)
        assertEquals("v=spf1 include:_spf.example.com -all", info.spf)
        assertTrue(info.dmarcPresent)
        assertEquals("reject", info.dmarcPolicy)
    }

    @Test
    fun `absent records are reported as missing`() {
        val info = DnsAnalysis.interpret(
            caa = emptyList(),
            apexTxt = listOf("\"google-site-verification=abc\""),
            dmarcTxt = emptyList(),
            dnssecAuthenticated = false
        )

        assertFalse(info.hasCaa)
        assertFalse(info.dnssec)
        assertNull(info.spf)
        assertFalse(info.dmarcPresent)
        assertNull(info.dmarcPolicy)
    }

    @Test
    fun `dmarc policy is parsed case-insensitively and trimmed`() {
        val info = DnsAnalysis.interpret(
            caa = emptyList(),
            apexTxt = emptyList(),
            dmarcTxt = listOf("\"v=DMARC1; p = Quarantine ;\""),
            dnssecAuthenticated = false
        )
        assertEquals("quarantine", info.dmarcPolicy)
    }

    @Test
    fun `an error short-circuits interpretation`() {
        val info = DnsAnalysis.interpret(
            caa = listOf("x"),
            apexTxt = listOf("y"),
            dmarcTxt = listOf("z"),
            dnssecAuthenticated = true,
            error = "network down"
        )
        assertEquals("network down", info.error)
        assertFalse(info.hasCaa)
    }
}
