package com.secaudit.webscan

import com.secaudit.webscan.scanner.MixedContent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MixedContentTest {

    @Test
    fun `finds http src and href and action`() {
        val html = """
            <script src="http://cdn.example.com/a.js"></script>
            <link href='http://cdn.example.com/a.css'>
            <form action=http://example.com/post>
            <img src="https://ok.example.com/x.png">
        """.trimIndent()

        val found = MixedContent.find(html)

        assertTrue(found.contains("http://cdn.example.com/a.js"))
        assertTrue(found.contains("http://cdn.example.com/a.css"))
        assertTrue(found.contains("http://example.com/post"))
        assertEquals(3, found.size)
    }

    @Test
    fun `https-only page yields nothing`() {
        val html = "<img src=\"https://a.test/x.png\"><a href=\"https://a.test\">go</a>"
        assertTrue(MixedContent.find(html).isEmpty())
    }

    @Test
    fun `duplicates are collapsed and the list is capped`() {
        val many = (1..40).joinToString("") { "<img src=\"http://a.test/$it.png\">" }
        val dup = "<img src=\"http://a.test/x.png\">".repeat(3)
        assertEquals(1, MixedContent.find(dup).size)
        assertEquals(25, MixedContent.find(many).size)
    }

    @Test
    fun `xml namespaces are ignored`() {
        val html = "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"
        assertTrue(MixedContent.find(html).isEmpty())
    }

    @Test
    fun `blank input is safe`() {
        assertTrue(MixedContent.find("").isEmpty())
    }
}
