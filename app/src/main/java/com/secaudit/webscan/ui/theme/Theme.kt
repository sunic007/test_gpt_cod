package com.secaudit.webscan.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = Color(0xFF7CC4FF),
    secondary = Color(0xFF9FD8A8),
    background = Color(0xFF101418),
    surface = Color(0xFF171C22)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF0B5FA5),
    secondary = Color(0xFF2E7D32),
    background = Color(0xFFF7F9FC),
    surface = Color(0xFFFFFFFF)
)

@Composable
fun WebSecAuditTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content
    )
}
