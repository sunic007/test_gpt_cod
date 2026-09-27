package com.secaudit.webscan.model

/**
 * A familiar letter grade, in the spirit of securityheaders.com / SSL Labs.
 *
 * The numeric [ScanReport.score] stays the primary signal; the grade is a quick
 * glance on top of it. A single unresolved HIGH finding caps the grade at C, so a
 * site cannot show an A while leaking cookies in plaintext or speaking TLS 1.0.
 */
enum class Grade(val label: String) {
    A_PLUS("A+"),
    A("A"),
    B("B"),
    C("C"),
    D("D"),
    E("E"),
    F("F");

    companion object {
        fun of(score: Int, hasHigh: Boolean): Grade {
            val base = when {
                score >= 95 -> A_PLUS
                score >= 85 -> A
                score >= 70 -> B
                score >= 55 -> C
                score >= 40 -> D
                score >= 20 -> E
                else -> F
            }
            // A HIGH finding means a concrete, exploitable weakness — never an A.
            return if (hasHigh && base.ordinal < C.ordinal) C else base
        }
    }
}
