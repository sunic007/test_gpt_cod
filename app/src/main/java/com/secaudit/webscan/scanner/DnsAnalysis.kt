package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.DnsInfo

/**
 * Interprets raw DNS records into [DnsInfo].
 *
 * Kept separate from the network so the interpretation — which record means what —
 * can be unit-tested with hand-written record lists, no DNS required.
 */
object DnsAnalysis {

    fun interpret(
        caa: List<String>,
        apexTxt: List<String>,
        dmarcTxt: List<String>,
        dnssecAuthenticated: Boolean,
        error: String? = null
    ): DnsInfo {
        if (error != null) return DnsInfo(queried = true, error = error)

        val spf = apexTxt.map(::unquote).firstOrNull { it.startsWith("v=spf1", ignoreCase = true) }

        val dmarc = dmarcTxt.map(::unquote)
            .firstOrNull { it.startsWith("v=DMARC1", ignoreCase = true) }
        val dmarcPolicy = dmarc?.let { record ->
            Regex("[;\\s]p\\s*=\\s*([a-zA-Z]+)").find(record)?.groupValues?.get(1)?.lowercase()
        }

        return DnsInfo(
            queried = true,
            caaRecords = caa.map { it.trim() }.filter { it.isNotEmpty() },
            dnssec = dnssecAuthenticated,
            spf = spf,
            dmarcPresent = dmarc != null,
            dmarcPolicy = dmarcPolicy
        )
    }

    /** DoH returns TXT values wrapped in quotes and sometimes split into chunks. */
    private fun unquote(raw: String): String =
        raw.trim().removeSurrounding("\"").replace("\" \"", "").trim()
}
