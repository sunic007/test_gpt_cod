package com.secaudit.webscan

import com.secaudit.webscan.ai.GeminiClient
import okhttp3.OkHttpClient
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    fun `parses the model list and strips the models prefix`() {
        val json = """
            {"models":[
              {"name":"models/gemini-2.5-flash","supportedGenerationMethods":["generateContent"]},
              {"name":"models/text-embedding-004","supportedGenerationMethods":["embedContent"]}
            ]}
        """.trimIndent()
        val models = client.parseModels(json)
        assertEquals(2, models.size)
        assertEquals("gemini-2.5-flash", models[0].name)
        assertTrue(models[0].methods.contains("generateContent"))
    }

    @Test
    fun `pickCandidates prefers newer flash text models and drops special-purpose ones`() {
        val models = listOf(
            GeminiClient.ModelInfo("gemini-1.5-flash", listOf("generateContent")),
            GeminiClient.ModelInfo("gemini-2.5-flash", listOf("generateContent")),
            GeminiClient.ModelInfo("gemini-2.5-pro", listOf("generateContent")),
            GeminiClient.ModelInfo("gemini-2.0-flash-thinking-exp", listOf("generateContent")),
            GeminiClient.ModelInfo("text-embedding-004", listOf("embedContent"))
        )
        val picks = client.pickCandidates(models)

        assertEquals("gemini-2.5-flash", picks.first())          // newest flash first
        assertTrue(picks.contains("gemini-1.5-flash"))
        assertFalse(picks.contains("text-embedding-004"))         // no generateContent
        // the experimental thinking variant is deprioritised below the plain models
        assertTrue(picks.indexOf("gemini-2.0-flash-thinking-exp") > picks.indexOf("gemini-2.5-pro"))
    }

    @Test
    fun `empty or malformed model list is safe`() {
        assertTrue(client.parseModels("{}").isEmpty())
        assertTrue(client.parseModels("garbage").isEmpty())
        assertTrue(client.pickCandidates(emptyList()).isEmpty())
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
