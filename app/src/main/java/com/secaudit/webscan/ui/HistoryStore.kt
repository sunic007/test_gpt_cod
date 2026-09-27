package com.secaudit.webscan.ui

import android.content.Context
import com.secaudit.webscan.model.HistoryEntry
import com.secaudit.webscan.scanner.HistoryCodec
import java.io.File

/**
 * Local, on-device scan history. Stored as a plain text file in the app's private
 * files directory via [HistoryCodec]; nothing leaves the device and no other app
 * can read it. Newest first, capped so it cannot grow without bound.
 */
class HistoryStore(context: Context, private val max: Int = 50) {

    private val file = File(context.filesDir, "scan_history.tsv")

    fun load(): List<HistoryEntry> = try {
        if (file.exists()) HistoryCodec.decode(file.readText()) else emptyList()
    } catch (t: Throwable) {
        emptyList()
    }

    /** Adds [entry] to the front, de-duplicating by target (keeps the latest). */
    fun add(entry: HistoryEntry): List<HistoryEntry> {
        val updated = (listOf(entry) + load().filterNot { it.target == entry.target }).take(max)
        save(updated)
        return updated
    }

    fun clear(): List<HistoryEntry> {
        runCatching { if (file.exists()) file.delete() }
        return emptyList()
    }

    private fun save(entries: List<HistoryEntry>) {
        runCatching { file.writeText(HistoryCodec.encode(entries)) }
    }
}
