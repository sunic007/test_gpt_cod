package com.secaudit.webscan

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Lang
import com.secaudit.webscan.i18n.RuStrings
import com.secaudit.webscan.i18n.Strings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The translation layer is a map, so nothing at compile time stops a key from
 * being added to one language and forgotten in the other, or from carrying a
 * different set of placeholders. These tests are what make that safe.
 */
class StringsParityTest {

    private val formatSpecifier = Regex("%[a-zA-Z]")

    @Test
    fun `both languages define exactly the same keys`() {
        val missingInRu = EnStrings.keys() - RuStrings.keys()
        val missingInEn = RuStrings.keys() - EnStrings.keys()

        assertEquals("keys missing from RuStrings", emptySet<String>(), missingInRu)
        assertEquals("keys missing from EnStrings", emptySet<String>(), missingInEn)
    }

    @Test
    fun `each key uses the same placeholders in both languages`() {
        val mismatched = EnStrings.keys().filter { key ->
            specifiers(EnStrings, key) != specifiers(RuStrings, key)
        }
        assertEquals(
            "placeholder sequences differ between languages",
            emptyList<String>(),
            mismatched
        )
    }

    @Test
    fun `no translation is blank`() {
        listOf(EnStrings, RuStrings).forEach { strings ->
            val blank = strings.keys().filter { strings.t(it).isBlank() }
            assertEquals("blank values in ${strings.lang}", emptyList<String>(), blank)
        }
    }

    @Test
    fun `russian lead prose is actually translated`() {
        val cyrillic = Regex("[А-Яа-яЁё]")
        // Header names and protocol labels stay in their original form on purpose,
        // so this checks the lead prose, which is always narrative text.
        val prose = RuStrings.keys().filter { it.startsWith("l.") }
        assertTrue(prose.isNotEmpty())
        prose.forEach { key ->
            assertTrue("$key is not translated", cyrillic.containsMatchIn(RuStrings.t(key)))
        }
    }

    @Test
    fun `placeholders are substituted`() {
        assertEquals("Requesting https://a.test …", EnStrings.t("prog.request", "https://a.test"))
        assertTrue(RuStrings.t("prog.request", "https://a.test").contains("https://a.test"))
    }

    @Test
    fun `an unknown key returns itself instead of crashing`() {
        assertEquals("no.such.key", EnStrings.t("no.such.key"))
    }

    @Test
    fun `a template called without arguments keeps its placeholder`() {
        assertTrue(EnStrings.t("prog.request").contains("%s"))
    }

    @Test
    fun `a wrongly typed argument falls back to the template instead of crashing`() {
        // Better a visible placeholder than an exception mid-report.
        assertEquals(
            EnStrings.t("ui.tls.daysLeft"),
            EnStrings.t("ui.tls.daysLeft", "not-a-number")
        )
    }

    @Test
    fun `language is selected from a locale tag`() {
        assertEquals(Lang.RU, Lang.fromTag("ru"))
        assertEquals(Lang.RU, Lang.fromTag("ru-RU"))
        assertEquals(Lang.EN, Lang.fromTag("en"))
        assertEquals(Lang.EN, Lang.fromTag("de"))
    }

    @Test
    fun `strings resolve by language`() {
        assertEquals(RuStrings, Strings.of(Lang.RU))
        assertEquals(EnStrings, Strings.of(Lang.EN))
    }

    private fun specifiers(strings: Strings, key: String): List<String> =
        formatSpecifier.findAll(strings.t(key)).map { it.value }.toList()
}
