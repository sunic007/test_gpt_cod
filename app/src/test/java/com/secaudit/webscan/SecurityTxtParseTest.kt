package com.secaudit.webscan

import com.secaudit.webscan.scanner.SecurityTxtCheck
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityTxtParseTest {

    private val check = SecurityTxtCheck(OkHttpClient())
    private val url = "https://example.test/.well-known/security.txt"

    @Test
    fun `parses contacts comments and fields`() {
        val body = """
            # Our disclosure policy
            Contact: mailto:security@example.test
            Contact: https://example.test/report
            Expires: 2035-01-01T00:00:00.000Z
            Policy: https://example.test/policy
            Preferred-Languages: en, ru

        """.trimIndent()

        val txt = check.parse(url, body)

        assertTrue(txt.found)
        assertEquals(
            listOf("mailto:security@example.test", "https://example.test/report"),
            txt.contacts
        )
        assertEquals("https://example.test/policy", txt.policy)
        assertEquals("en, ru", txt.preferredLanguages)
        assertEquals(false, txt.expired)
    }

    @Test
    fun `a colon inside a value is preserved`() {
        val txt = check.parse(url, "Contact: mailto:security@example.test")
        assertEquals(listOf("mailto:security@example.test"), txt.contacts)
    }

    @Test
    fun `field names are case-insensitive`() {
        val txt = check.parse(url, "CONTACT: mailto:a@b.test\nexpires: 2035-01-01T00:00:00Z")
        assertEquals(listOf("mailto:a@b.test"), txt.contacts)
        assertEquals("2035-01-01T00:00:00Z", txt.expires)
    }

    @Test
    fun `a past expiry is detected`() {
        val txt = check.parse(url, "Contact: mailto:a@b.test\nExpires: 2000-01-01T00:00:00Z")
        assertEquals(true, txt.expired)
    }

    @Test
    fun `an unparseable expiry is reported as unknown, not a crash`() {
        val txt = check.parse(url, "Contact: mailto:a@b.test\nExpires: whenever")
        assertNull(txt.expired)
        assertEquals("whenever", txt.expires)
    }

    @Test
    fun `an empty contact value is dropped`() {
        val txt = check.parse(url, "Contact:\nExpires: 2035-01-01T00:00:00Z")
        assertTrue(txt.contacts.isEmpty())
    }

    @Test
    fun `blank lines and stray text do not break parsing`() {
        val txt = check.parse(url, "\n\nnot a field line\n\nContact: mailto:a@b.test\n")
        assertEquals(listOf("mailto:a@b.test"), txt.contacts)
        assertFalse(txt.contacts.isEmpty())
    }
}
