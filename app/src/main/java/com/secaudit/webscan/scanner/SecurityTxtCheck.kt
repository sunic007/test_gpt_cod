package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.SecurityTxt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.time.OffsetDateTime

/**
 * Looks for a security disclosure policy as described by RFC 9116.
 *
 * The well-known location is checked first, then the legacy root path. Both are
 * public, static documents published specifically so that they can be read.
 */
class SecurityTxtCheck(private val client: OkHttpClient) {

    private companion object {
        const val MAX_BODY_BYTES = 64L * 1024
        val PATHS = listOf("/.well-known/security.txt", "/security.txt")
    }

    suspend fun fetch(base: HttpUrl): SecurityTxt = withContext(Dispatchers.IO) {
        for (path in PATHS) {
            val url = base.newBuilder().encodedPath(path).query(null).fragment(null).build()
            val body = get(url.toString()) ?: continue
            return@withContext parse(url.toString(), body)
        }
        SecurityTxt(found = false)
    }

    private fun get(url: String): String? = try {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", WebScanner.USER_AGENT)
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            val contentType = response.header("Content-Type").orEmpty()
            // A site that serves its SPA shell for every unknown path would
            // otherwise be misread as publishing a policy.
            when {
                !response.isSuccessful -> null
                contentType.contains("html", ignoreCase = true) -> null
                else -> response.peekBody(MAX_BODY_BYTES).string().takeIf {
                    it.contains("Contact:", ignoreCase = true) ||
                        it.contains("Expires:", ignoreCase = true)
                }
            }
        }
    } catch (t: Throwable) {
        null
    }

    private fun parse(url: String, body: String): SecurityTxt {
        val fields = mutableMapOf<String, MutableList<String>>()
        body.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .forEach { line ->
                val separator = line.indexOf(':')
                if (separator > 0) {
                    val key = line.substring(0, separator).trim().lowercase()
                    val value = line.substring(separator + 1).trim()
                    if (value.isNotEmpty()) {
                        fields.getOrPut(key) { mutableListOf() }.add(value)
                    }
                }
            }

        val expires = fields["expires"]?.firstOrNull()
        return SecurityTxt(
            found = true,
            url = url,
            contacts = fields["contact"].orEmpty(),
            expires = expires,
            expired = expires?.let(::isExpired),
            policy = fields["policy"]?.firstOrNull(),
            encryption = fields["encryption"]?.firstOrNull(),
            preferredLanguages = fields["preferred-languages"]?.firstOrNull(),
            canonical = fields["canonical"]?.firstOrNull()
        )
    }

    /** `Expires` is an ISO-8601 timestamp; unparseable values are reported as unknown. */
    private fun isExpired(raw: String): Boolean? = try {
        OffsetDateTime.parse(raw).isBefore(OffsetDateTime.now())
    } catch (t: Throwable) {
        null
    }
}
