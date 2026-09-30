package com.secaudit.webscan.ui

import android.content.Context

/** Small on-device settings store (currently just the user's Gemini API key). */
class SettingsStore(context: Context) {

    private val prefs = context.getSharedPreferences("secaudit_settings", Context.MODE_PRIVATE)

    fun apiKey(): String = prefs.getString(KEY_GEMINI, "").orEmpty()

    fun setApiKey(value: String) {
        prefs.edit().putString(KEY_GEMINI, value.trim()).apply()
    }

    private companion object {
        const val KEY_GEMINI = "gemini_api_key"
    }
}
