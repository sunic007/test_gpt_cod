package com.secaudit.webscan

import com.secaudit.webscan.ai.GeminiClient
import okhttp3.OkHttpClient
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GeminiClientTest {

    private val client = GeminiClient(OkHttpClient())

    @Test
    fun `parses and joins text parts`() {
        val json = """
            {"candidates":[{"content":{"parts":[{"text":"Hello"},{"text":" world"}]}}]}
        """.trimIndent()
        assertEquals("Hello world", client.parseText(json))
    }

    @Test
    fun `an empty or blocked response yields empty text`() {
        assertEquals("", client.parseText("""{"candidates":[]}"""))
        assertEquals("", client.parseText("""{"promptFeedback":{"blockReason":"SAFETY"}}"""))
    }

    @Test
    fun `malformed json does not crash`() {
        assertEquals("", client.parseText("not json at all"))
    }

    @Test
    fun `error message is extracted, else the http code`() {
        val err = """{"error":{"code":400,"message":"API key not valid"}}"""
        assertEquals("API key not valid", client.extractError(err, 400))
        assertEquals("HTTP 403", client.extractError("{}", 403))
        assertEquals("HTTP 500", client.extractError("garbage", 500))
    }

    @Test
    fun `request body carries the prompt and generation config`() {
        val body = JSONObject(client.requestBody("explain this"))
        val text = body.getJSONArray("contents")
            .getJSONObject(0).getJSONArray("parts")
            .getJSONObject(0).getString("text")
        assertEquals("explain this", text)
        assertTrue(body.getJSONObject("generationConfig").has("maxOutputTokens"))
    }
}
