package com.secaudit.webscan

import com.secaudit.webscan.model.HistoryEntry
import com.secaudit.webscan.scanner.HistoryCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryCodecTest {

    @Test
    fun `round trips a list of entries`() {
        val entries = listOf(
            HistoryEntry("example.com", "https://example.com/", "A", 92, 1_700_000_000_000),
            HistoryEntry("test.org", "http://test.org/", "F", 20, 1_700_000_100_000)
        )
        assertEquals(entries, HistoryCodec.decode(HistoryCodec.encode(entries)))
    }

    @Test
    fun `tabs and newlines in a field cannot break the row format`() {
        val entry = HistoryEntry("a\tb\nc", "https://x/\t\n", "B", 70, 1L)
        val decoded = HistoryCodec.decode(HistoryCodec.encode(listOf(entry)))
        assertEquals(1, decoded.size)
        assertEquals(70, decoded[0].score)
        assertTrue(!decoded[0].target.contains('\t'))
    }

    @Test
    fun `malformed lines are skipped, not fatal`() {
        val text = "not enough columns\n1\tA\t90\ttarget\thttps://t/\n\n"
        val decoded = HistoryCodec.decode(text)
        assertEquals(1, decoded.size)
        assertEquals("target", decoded[0].target)
    }

    @Test
    fun `empty input decodes to empty list`() {
        assertTrue(HistoryCodec.decode("").isEmpty())
    }
}
