package com.secaudit.webscan.model

/**
 * DNS-level hygiene, gathered over DNS-over-HTTPS (a normal public lookup).
 *
 * All fields describe records the domain publishes for anyone to read; none of
 * this probes the target's own servers.
 */
data class DnsInfo(
    val queried: Boolean = false,
    val caaRecords: List<String> = emptyList(),
    val dnssec: Boolean = false,
    val spf: String? = null,
    val dmarcPolicy: String? = null,   // none / quarantine / reject
    val dmarcPresent: Boolean = false,
    val error: String? = null
) {
    val hasCaa: Boolean get() = caaRecords.isNotEmpty()
}
