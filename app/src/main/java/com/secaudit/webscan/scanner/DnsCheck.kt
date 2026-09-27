package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.DnsInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

/**
 * Reads a domain's DNS hygiene records over DNS-over-HTTPS.
 *
 * DoH is an ordinary public lookup (the same records any resolver returns); it is
 * used here only because Android has no built-in API for CAA/TXT queries. The
 * domain is sent to the DoH resolver, which is noted in the app's privacy text.
 * Parsing is thin; the interpretation lives in [DnsAnalysis] so it can be tested.
 */
class DnsCheck(private val client: OkHttpClient, private val resolver: String = DEFAULT_RESOLVER) {

    companion object {
        const val DEFAULT_RESOLVER = "https://dns.google/resolve"
        private const val TYPE_TXT = 16
        private const val TYPE_CAA = 257
    }

    suspend fun lookup(host: String): DnsInfo = withContext(Dispatchers.IO) {
        try {
            val caa = query(host, TYPE_CAA)
            val apexTxt = query(host, TYPE_TXT)
            val dmarcTxt = query("_dmarc.$host", TYPE_TXT)
            DnsAnalysis.interpret(
                caa = caa.data,
                apexTxt = apexTxt.data,
                dmarcTxt = dmarcTxt.data,
                dnssecAuthenticated = apexTxt.authenticated || caa.authenticated
            )
        } catch (t: Throwable) {
            DnsInfo(queried = true, error = t.message ?: "DNS lookup failed")
        }
    }

    private class Answer(val data: List<String>, val authenticated: Boolean)

    private fun query(name: String, type: Int): Answer {
        val url = "$resolver?name=${name}&type=$type"
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/dns-json")
            .header("User-Agent", WebScanner.USER_AGENT)
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) return Answer(emptyList(), false)
            val json = JSONObject(response.body?.string().orEmpty())
            val authenticated = json.optBoolean("AD", false)
            val answers = json.optJSONArray("Answer") ?: return Answer(emptyList(), authenticated)
            val data = buildList {
                for (i in 0 until answers.length()) {
                    val entry = answers.optJSONObject(i) ?: continue
                    if (entry.optInt("type") != type) continue
                    entry.optString("data").takeIf { it.isNotBlank() }?.let { add(it) }
                }
            }
            return Answer(data, authenticated)
        }
    }
}
