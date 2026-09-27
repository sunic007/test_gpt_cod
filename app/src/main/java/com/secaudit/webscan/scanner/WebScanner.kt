package com.secaudit.webscan.scanner

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.DnsInfo
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
    val dns: DnsInfo?,
    val mixedContent: List<String>,
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
        private const val MAX_HTML_BYTES = 512L * 1024
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
    private val dnsCheck = DnsCheck(client)

    /** Response metadata copied out before the response body is closed. */
    private data class Head(
        val url: HttpUrl,
        val status: Int,
        val headers: Map<String, String>,
        val cookies: List<String>,
        val bodySample: String
    )

    /** One GET, with headers, cookies and a capped HTML sample copied out. */
    private fun fetchHead(url: String): Head {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .get()
            .build()
        return client.newCall(request).execute().use { response ->
            val contentType = response.header("Content-Type").orEmpty()
            val body = if (contentType.contains("html", ignoreCase = true)) {
                runCatching { response.peekBody(MAX_HTML_BYTES).string() }.getOrDefault("")
            } else {
                ""
            }
            Head(
                url = response.request.url,
                status = response.code,
                headers = response.headers.names()
                    .associate { it.lowercase() to response.headers[it].orEmpty() },
                cookies = response.headers.values("Set-Cookie"),
                bodySample = body
            )
        }
    }

    /** True when the failure looks like TLS was tried against a plain-HTTP server. */
    private fun isTlsMismatch(e: Throwable): Boolean {
        if (e is javax.net.ssl.SSLException) return true
        val msg = generateSequence(e as Throwable?) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" ")
            .lowercase()
        return "tls" in msg || "ssl" in msg || "handshake" in msg || "plaintext" in msg
    }

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
        val hadScheme = rawTarget.trim().let {
            it.startsWith("http://", true) || it.startsWith("https://", true)
        }
        val target = normalizeTarget(rawTarget)
        val started = System.currentTimeMillis()

        onProgress(s.t("prog.request", target))
        val head = try {
            fetchHead(target)
        } catch (e: Exception) {
            // A plain-HTTP server (e.g. a local lab) speaks HTTP to our auto-added
            // https:// and the handshake fails. If the user did not pick a scheme,
            // retry once over http:// so localhost targets just work.
            if (!hadScheme && isTlsMismatch(e)) {
                val httpUrl = target.replaceFirst("https://", "http://", ignoreCase = true)
                onProgress(s.t("prog.request", httpUrl))
                fetchHead(httpUrl)
            } else {
                throw e
            }
        }

        val tls: TlsInfo? = if (head.url.isHttps) {
            onProgress(s.t("prog.tls", head.url.host))
            tlsProbe.probe(head.url.host, head.url.port)
        } else {
            null
        }

        onProgress(s.t("prog.dns", head.url.host))
        val dns: DnsInfo = dnsCheck.lookup(head.url.host)

        onProgress(s.t("prog.stxt"))
        val securityTxt = securityTxtCheck.fetch(head.url)

        val mixed = if (head.url.isHttps) MixedContent.find(head.bodySample) else emptyList()

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
            dns = dns,
            mixedContent = mixed,
            startedAtEpochMs = started,
            durationMs = System.currentTimeMillis() - started
        )
    }
}
