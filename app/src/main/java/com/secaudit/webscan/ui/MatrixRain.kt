package com.secaudit.webscan.ui

import android.graphics.Paint
import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameMillis
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.secaudit.webscan.ui.theme.Term
import kotlin.random.Random

/**
 * The "digital rain" backdrop shown while a scan runs.
 *
 * Columns of glyphs fall at independent speeds; each column has a bright head and
 * a fading tail. It is purely decorative — it renders nothing about the target
 * and does no work beyond drawing — so it is safe to stop the moment [running]
 * goes false, which frees the frame loop.
 */
@Composable
fun MatrixRain(modifier: Modifier = Modifier, running: Boolean) {
    val glyphs = remember {
        // Katakana (the canonical look) plus hex digits and a few symbols.
        ("アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワン" +
            "0123456789ABCDEF<>*+=/\\").toCharArray()
    }

    BoxWithConstraints(modifier) {
        val density = LocalDensity.current
        val cellPx = with(density) { 14.dp.toPx() }
        val cols = ((constraints.maxWidth / cellPx).toInt()).coerceAtLeast(1)
        val rows = ((constraints.maxHeight / cellPx).toInt()).coerceAtLeast(1)

        // Mutable, per-column animation state; re-seeded whenever the grid resizes.
        val heads = remember(cols, rows) {
            FloatArray(cols) { -Random.nextInt(rows).toFloat() }
        }
        val speeds = remember(cols) { FloatArray(cols) { 0.25f + Random.nextFloat() * 0.65f } }
        val tails = remember(cols, rows) {
            IntArray(cols) { (rows * (0.35f + Random.nextFloat() * 0.5f)).toInt().coerceAtLeast(4) }
        }
        val chars = remember(cols, rows) {
            Array(cols) { CharArray(rows) { glyphs[Random.nextInt(glyphs.size)] } }
        }

        // A frame counter is the single state the Canvas reads, so each tick redraws.
        var frame by remember { mutableIntStateOf(0) }

        LaunchedFrameLoop(running) {
            for (c in 0 until cols) {
                heads[c] += speeds[c]
                if (heads[c] - tails[c] > rows) {
                    heads[c] = -Random.nextInt(rows / 2 + 1).toFloat()
                    speeds[c] = 0.25f + Random.nextFloat() * 0.65f
                }
                // Occasionally mutate a glyph so columns shimmer rather than scroll rigidly.
                if (Random.nextInt(100) < 12) {
                    val r = Random.nextInt(rows)
                    chars[c][r] = glyphs[Random.nextInt(glyphs.size)]
                }
            }
            frame++
        }

        Canvas(Modifier.matchParentSize()) {
            frame // read to tie redraw to the frame loop
            drawIntoCanvas { canvas ->
                val native = canvas.nativeCanvas
                val paint = Paint().apply {
                    isAntiAlias = true
                    textSize = cellPx * 0.92f
                    typeface = Typeface.MONOSPACE
                }
                for (c in 0 until cols) {
                    val head = heads[c]
                    val x = c * cellPx
                    val tail = tails[c]
                    for (r in 0 until rows) {
                        val dist = head - r
                        if (dist < 0 || dist > tail) continue
                        val y = (r + 1) * cellPx
                        val ch = chars[c][r].toString()
                        when {
                            dist < 1f -> {
                                paint.color = HEAD
                                paint.alpha = 255
                            }
                            else -> {
                                paint.color = BODY
                                paint.alpha = (220 * (1f - dist / tail)).toInt().coerceIn(12, 220)
                            }
                        }
                        native.drawText(ch, x, y, paint)
                    }
                }
            }
        }
    }
}

/** Runs [onFrame] once per display frame while [running]; stops cleanly otherwise. */
@Composable
private fun LaunchedFrameLoop(running: Boolean, onFrame: () -> Unit) {
    LaunchedEffect(running) {
        if (!running) return@LaunchedEffect
        while (true) {
            withFrameMillis { onFrame() }
        }
    }
}

private val HEAD = Color(0xFFE8FFF2).toArgb()
private val BODY = Term.Accent.toArgb()
