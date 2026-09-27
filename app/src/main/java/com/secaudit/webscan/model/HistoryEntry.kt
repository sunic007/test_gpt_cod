package com.secaudit.webscan.model

/** One past scan, as kept in local history. */
data class HistoryEntry(
    val target: String,
    val finalUrl: String,
    val grade: String,
    val score: Int,
    val epochMs: Long
)
