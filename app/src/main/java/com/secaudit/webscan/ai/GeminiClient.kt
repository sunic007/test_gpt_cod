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
        /** Static fallbacks used only if the live model list cannot be fetched. */
        const val DEFAULT_MODEL = "gemini-flash-latest"
        val FALLBACK_MODELS = listOf(
            "gemini-flash-latest",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-flash"
        )
        private const val ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"
        private val JSON = "application/json".toMediaType()
    }

    /** One model as returned by the ListModels endpoint. */
    data class ModelInfo(val name: String, val methods: List<String>)

    /**
     * Asks the API which models this key can use. Lets the app pick a working
     * model automatically instead of hard-coding one Google may rename or retire.
     */
    suspend fun listModels(apiKey: String): Result<List<ModelInfo>> =
        withContext(Dispatchers.IO) {
            if (apiKey.isBlank()) return@withContext Result.failure(IllegalStateException("No API key"))
            try {
                val request = Request.Builder()
                    .url("$ENDPOINT?key=$apiKey&pageSize=1000")
                    .get()
                    .build()
                client.newCall(request).execute().use { response ->
                    val body = response.body?.string().orEmpty()
                    if (!response.isSuccessful) {
                        Result.failure(Exception(extractError(body, response.code)))
                    } else {
                        Result.success(parseModels(body))
                    }
                }
            } catch (t: Throwable) {
                Result.failure(t)
            }
        }

    suspend fun generate(
        apiKey: String,
        prompt: String,
        model: String = DEFAULT_MODEL
    ): Result<String> =
        withContext(Dispatchers.IO) {
            if (apiKey.isBlank()) return@withContext Result.failure(IllegalStateException("No API key"))
            val chosen = model.ifBlank { DEFAULT_MODEL }
            try {
                val request = Request.Builder()
                    .url("$ENDPOINT/$chosen:generateContent?key=$apiKey")
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

    /** Parses the ListModels response into name + supported methods. */
    internal fun parseModels(json: String): List<GeminiClient.ModelInfo> = try {
        val models = JSONObject(json).optJSONArray("models") ?: JSONArray()
        buildList {
            for (i in 0 until models.length()) {
                val m = models.optJSONObject(i) ?: continue
                val name = m.optString("name").removePrefix("models/")
                if (name.isBlank()) continue
                val methodsArr = m.optJSONArray("supportedGenerationMethods") ?: JSONArray()
                val methods = (0 until methodsArr.length()).map { methodsArr.optString(it) }
                add(ModelInfo(name, methods))
            }
        }
    } catch (t: Throwable) {
        emptyList()
    }

    /**
     * Orders the models that can do generateContent best-first for our use:
     * prefer fast "flash" text models and newer versions, and push aside
     * special-purpose variants (vision/embedding/tts/image/live/experimental).
     */
    internal fun pickCandidates(models: List<ModelInfo>, limit: Int = 5): List<String> {
        fun score(name: String): Int {
            val n = name.lowercase()
            var s = 0
            if ("flash" in n) s += 100
            if ("lite" in n) s += 5
            if ("latest" in n) s += 30
            Regex("(\\d+(?:\\.\\d+)?)").find(n)?.groupValues?.get(1)?.toDoubleOrNull()
                ?.let { s += (it * 4).toInt() }
            listOf("vision", "embedding", "aqa", "tts", "image", "live", "exp", "thinking", "learnlm")
                .forEach { if (it in n) s -= 500 }
            return s
        }
        return models
            .filter { "generateContent" in it.methods }
            .map { it.name }
            .distinct()
            .sortedByDescending { score(it) }
            .take(limit)
    }

    /** Pulls a human-readable message out of an error response, or falls back to the code. */
    internal fun extractError(json: String, code: Int): String = try {
        JSONObject(json).optJSONObject("error")?.optString("message").takeUnless { it.isNullOrBlank() }
            ?: "HTTP $code"
    } catch (t: Throwable) {
        "HTTP $code"
    }
}
