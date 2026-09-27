package com.secaudit.webscan.i18n

import java.util.Locale

/** Languages the app ships with. */
enum class Lang(val code: String, val short: String) {
    RU("ru", "РУС"),
    EN("en", "ENG");

    companion object {
        fun fromTag(tag: String): Lang = if (tag.lowercase().startsWith("ru")) RU else EN

        /** Picks the device language, falling back to English. */
        fun fromSystem(): Lang = fromTag(Locale.getDefault().language)
    }
}

/**
 * Localised text for everything the user reads, including the findings and the
 * correlated leads.
 *
 * Text lives in a key/template map rather than in Android string resources so
 * that the scanner and the investigator stay free of Android dependencies and
 * can be unit-tested on a plain JVM. `StringsParityTest` asserts that both
 * languages define exactly the same keys, which is what makes the map safe.
 */
abstract class Strings {

    abstract val lang: Lang
    protected abstract val map: Map<String, String>

    /** Resolves [key], substituting [args]. An unknown key returns itself, never crashes. */
    fun t(key: String, vararg args: Any?): String {
        val template = map[key] ?: return key
        if (args.isEmpty()) return template
        return runCatching { String.format(Locale.ROOT, template, *args) }.getOrDefault(template)
    }

    /** Exposed so a test can compare the key sets of the two languages. */
    fun keys(): Set<String> = map.keys

    companion object {
        fun of(lang: Lang): Strings = when (lang) {
            Lang.RU -> RuStrings
            Lang.EN -> EnStrings
        }
    }
}
