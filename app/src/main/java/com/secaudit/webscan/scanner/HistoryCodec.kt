package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.HistoryEntry

/**
 * Serialises scan history to a simple tab-separated line format and back.
 *
 * Kept pure and dependency-free (no JSON, no Android) so the round-trip can be
 * unit-tested; the Android store just reads and writes the text this produces.
 * Any tab or newline inside a field is neutralised so one record is always one
 * line with a fixed column count.
 */
object HistoryCodec {

    private const val SEP = '\t'
    private const val COLUMNS = 5

    fun encode(entries: List<HistoryEntry>): String =
        entries.joinToString("\n") { e ->
            listOf(e.epochMs.toString(), e.grade, e.score.toString(), clean(e.target), clean(e.finalUrl))
                .joinToString(SEP.toString())
        }

    fun decode(text: String): List<HistoryEntry> =
        text.lineSequence()
            .map { it.trimEnd('\r') }
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val parts = line.split(SEP)
                if (parts.size != COLUMNS) return@mapNotNull null
                val epoch = parts[0].toLongOrNull() ?: return@mapNotNull null
                val score = parts[2].toIntOrNull() ?: return@mapNotNull null
                HistoryEntry(
                    target = parts[3],
                    finalUrl = parts[4],
                    grade = parts[1],
                    score = score,
                    epochMs = epoch
                )
            }
            .toList()

    private fun clean(s: String): String = s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
}
