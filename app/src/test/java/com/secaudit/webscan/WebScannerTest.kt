package com.secaudit.webscan

import com.secaudit.webscan.scanner.WebScanner
import org.junit.Assert.assertEquals
import org.junit.Test

class WebScannerTest {

    private val scanner = WebScanner()

    @Test
    fun `bare host defaults to https`() {
        assertEquals("https://example.com", scanner.normalizeTarget("example.com"))
    }

    @Test
    fun `existing scheme is preserved`() {
        assertEquals("http://example.com", scanner.normalizeTarget("http://example.com"))
        assertEquals("https://example.com/a", scanner.normalizeTarget("https://example.com/a"))
    }

    @Test
    fun `whitespace is trimmed`() {
        assertEquals("https://example.com", scanner.normalizeTarget("  example.com  "))
    }
}
