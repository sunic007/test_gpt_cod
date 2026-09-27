package com.secaudit.webscan

import com.secaudit.webscan.model.Grade
import org.junit.Assert.assertEquals
import org.junit.Test

class GradeTest {

    @Test
    fun `score maps to the expected letter`() {
        assertEquals(Grade.A_PLUS, Grade.of(100, hasHigh = false))
        assertEquals(Grade.A_PLUS, Grade.of(95, hasHigh = false))
        assertEquals(Grade.A, Grade.of(90, hasHigh = false))
        assertEquals(Grade.B, Grade.of(72, hasHigh = false))
        assertEquals(Grade.C, Grade.of(60, hasHigh = false))
        assertEquals(Grade.D, Grade.of(45, hasHigh = false))
        assertEquals(Grade.E, Grade.of(25, hasHigh = false))
        assertEquals(Grade.F, Grade.of(0, hasHigh = false))
    }

    @Test
    fun `a HIGH finding caps the grade at C`() {
        assertEquals(Grade.C, Grade.of(100, hasHigh = true))
        assertEquals(Grade.C, Grade.of(88, hasHigh = true))
    }

    @Test
    fun `a HIGH finding does not raise an already-low grade`() {
        assertEquals(Grade.D, Grade.of(45, hasHigh = true))
        assertEquals(Grade.F, Grade.of(10, hasHigh = true))
    }
}
