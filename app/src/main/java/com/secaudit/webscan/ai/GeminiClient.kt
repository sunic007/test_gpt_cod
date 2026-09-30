package com.secaudit.webscan.ai

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

/**
 * Thin client for Google's Gemini `generateContent` REST API.
 *
 * The user supplies their own API key (kept on-device); the app never ships one.
 * Only the finding text and a short instruction are sent — no secrets beyond the
 * user's own key, which goes to Google as expected. Request building and JSON
 * parsing are split out so the parsing can be unit-tested without the network.
 */
class GeminiClient(private val client: OkHttpClient) {

    companion object {
        /** Change here if Google renames the model. */
        const val MODEL = "gemini-2.0-flash"
        private const val ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"
        private val JSON = "application/json".toMediaType()
    }

    suspend fun generate(apiKey: String, prompt: String): Result<String> =
        withContext(Dispatchers.IO) {
            if (apiKey.isBlank()) return@withContext Result.failure(IllegalStateException("No API key"))
            try {
                val request = Request.Builder()
                    .url("$ENDPOINT/$MODEL:generateContent?key=$apiKey")
                    .post(requestBody(prompt).toRequestBody(JSON))
                    .build()
                client.newCall(request).execute().use { response ->
                    val body = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        Result.failure(Exception(extractError(body, response.code)))
                    } else {
                        val text = parseText(body)
                        if (text.isBlank()) {
                            Result.failure(Exception("Empty response from Gemini"))
                        } else {
                            Result.success(text)
                        }
                    }
                }
            } catch (t: Throwable) {
                Result.failure(t)
            }
        }

    /** Builds the generateContent request body. */
    internal fun requestBody(prompt: String): String = JSONObject()
        .put(
            "contents",
            JSONArray().put(
                JSONObject().put("parts", JSONArray().put(JSONObject().put("text", prompt)))
            )
        )
        .put(
            "generationConfig",
            JSONObject().put("temperature", 0.3).put("maxOutputTokens", 700)
        )
        .toString()

    /** Extracts the generated text from a successful response, joining all parts. */
    internal fun parseText(json: String): String = try {
        val candidates = JSONObject(json).optJSONArray("candidates") ?: JSONArray()
        val parts = candidates.optJSONObject(0)
            ?.optJSONObject("content")
            ?.optJSONArray("parts")
            ?: JSONArray()
        buildString {
            for (i in 0 until parts.length()) {
                parts.optJSONObject(i)?.optString("text")?.let { append(it) }
            }
        }.trim()
    } catch (t: Throwable) {
        ""
    }

    /** Pulls a human-readable message out of an error response, or falls back to the code. */
    internal fun extractError(json: String, code: Int): String = try {
        JSONObject(json).optJSONObject("error")?.optString("message").takeUnless { it.isNullOrBlank() }
            ?: "HTTP $code"
    } catch (t: Throwable) {
        "HTTP $code"
    }
}
