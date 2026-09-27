package com.secaudit.webscan.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * Terminal palette. The app is dark only by design: the report is dense
 * technical text, and one consistent dark surface keeps the severity colours
 * readable instead of having them fight a light background.
 */
object Term {
    val Bg = Color(0xFF070B10)
    val Surface = Color(0xFF0E141B)
    val SurfaceAlt = Color(0xFF131C25)
    val Border = Color(0xFF1E2B38)
    val BorderBright = Color(0xFF2C3E4F)
    val Text = Color(0xFFD9E5F1)
    val TextDim = Color(0xFF8798A9)
    val Accent = Color(0xFF4ADE80)
    val Accent2 = Color(0xFF38BDF8)

    val High = Color(0xFFFF5F56)
    val Medium = Color(0xFFFFB454)
    val Low = Color(0xFF4ADE80)
    val Info = Color(0xFF7FA8CC)
}

private val TermColors = darkColorScheme(
    primary = Term.Accent,
    onPrimary = Term.Bg,
    secondary = Term.Accent2,
    onSecondary = Term.Bg,
    background = Term.Bg,
    onBackground = Term.Text,
    surface = Term.Surface,
    onSurface = Term.Text,
    surfaceVariant = Term.SurfaceAlt,
    onSurfaceVariant = Term.TextDim,
    outline = Term.Border,
    error = Term.High,
    onError = Term.Bg
)

private val TermShapes = Shapes(
    extraSmall = RoundedCornerShape(3.dp),
    small = RoundedCornerShape(4.dp),
    medium = RoundedCornerShape(6.dp),
    large = RoundedCornerShape(8.dp)
)

@Composable
fun WebSecAuditTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = TermColors,
        shapes = TermShapes,
        content = content
    )
}
