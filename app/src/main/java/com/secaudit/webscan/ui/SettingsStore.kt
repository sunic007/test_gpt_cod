package com.secaudit.webscan.ui

import android.content.Context

/** Small on-device settings store (Gemini API key and model). */
class SettingsStore(context: Context) {

    private val prefs = context.getSharedPreferences("secaudit_settings", Context.MODE_PRIVATE)

    fun apiKey(): String = prefs.getString(KEY_GEMINI, "").orEmpty()

    fun setApiKey(value: String) {
        prefs.edit().putString(KEY_GEMINI, value.trim()).apply()
    }

    /** The Gemini model id; blank input falls back to the default so it is never empty. */
    fun model(): String = prefs.getString(KEY_MODEL, DEFAULT_MODEL).orEmpty().ifBlank { DEFAULT_MODEL }

    fun setModel(value: String) {
        prefs.edit().putString(KEY_MODEL, value.trim().ifBlank { DEFAULT_MODEL }).apply()
    }

    companion object {
        /** Google renames models often; this is just the default and is user-overridable. */
        const val DEFAULT_MODEL = "gemini-3.8-flash"
        private const val KEY_GEMINI = "gemini_api_key"
        private const val KEY_MODEL = "gemini_model"
    }
}
