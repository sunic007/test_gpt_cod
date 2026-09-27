package com.secaudit.webscan.scanner

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.TlsInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Raw, language-neutral record of what the target published about itself.
 *
 * Keeping the collected facts separate from their write-up means the report can
 * be re-rendered in another language without touching the network again.
 */
data class RawObservations(
    val target: String,
    val finalUrl: String,
    val host: String,
    val isHttps: Boolean,
    val status: Int,
    val headers: Map<String, String>,
    val cookies: List<String>,
    val tls: TlsInfo?,
    val securityTxt: SecurityTxt,
    val startedAtEpochMs: Long,
    val durationMs: Long
)

/**
 * Passive web-security collection.
 *
 * Evidence comes from three sources, all of which observe what the target
 * publishes about itself:
 *
 *  1. one ordinary GET of the target (the request a browser makes to open it),
 *  2. handshake-only TLS probes to see which protocol versions are accepted,
 *  3. the site's RFC 9116 disclosure policy, if it publishes one.
 *
 * No attack payloads are sent, nothing is fuzzed or brute-forced, and the whole
 * run costs fewer requests than loading the site's home page in a browser. It is
 * intended for sites you own or are explicitly authorised to test.
 *
 * [Strings] is used only for the progress messages; the findings themselves are
 * worded later by [ReportBuilder].
 */
class WebScanner {

    companion object {
        const val USER_AGENT = "WebSecAudit/1.2 (passive configuration review)"
    }

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .retryOnConnectionFailure(false)
        .build()

    private val tlsProbe = TlsProbe()
    private val securityTxtCheck = SecurityTxtCheck(client)

    /** Response metadata copied out before the response body is closed. */
    private data class Head(
        val url: HttpUrl,
        val status: Int,
        val headers: Map<String, String>,
        val cookies: List<String>
    )

    /** Normalises user input into a valid absolute URL, defaulting to https://. */
    fun normalizeTarget(raw: String): String {
        val trimmed = raw.trim()
        return when {
            trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true) -> trimmed
            else -> "https://$trimmed"
        }
    }

    suspend fun collect(
        rawTarget: String,
        s: Strings = EnStrings,
        onProgress: (String) -> Unit = {}
    ): RawObservations = withContext(Dispatchers.IO) {
        val target = normalizeTarget(rawTarget)
        val started = System.currentTimeMillis()

        onProgress(s.t("prog.request", target))
        val request = Request.Builder()
            .url(target)
            .header("User-Agent", USER_AGENT)
            .get()
            .build()

        val head = client.newCall(request).execute().use { response ->
            Head(
                url = response.request.url,
                status = response.code,
                headers = response.headers.names()
                    .associate { it.lowercase() to response.headers[it].orEmpty() },
                cookies = response.headers.values("Set-Cookie")
            )
        }

        val tls: TlsInfo? = if (head.url.isHttps) {
            onProgress(s.t("prog.tls", head.url.host))
            tlsProbe.probe(head.url.host, head.url.port)
        } else {
            null
        }

        onProgress(s.t("prog.stxt"))
        val securityTxt = securityTxtCheck.fetch(head.url)

        onProgress(s.t("prog.correlate"))
        RawObservations(
            target = target,
            finalUrl = head.url.toString(),
            host = head.url.host,
            isHttps = head.url.isHttps,
            status = head.status,
            headers = head.headers,
            cookies = head.cookies,
            tls = tls,
            securityTxt = securityTxt,
            startedAtEpochMs = started,
            durationMs = System.currentTimeMillis() - started
        )
    }
}
