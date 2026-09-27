package com.secaudit.webscan.scanner

/**
 * Finds plain-HTTP subresources referenced by an HTTPS page.
 *
 * A page served over HTTPS that pulls scripts, styles, iframes or images over
 * `http://` undoes much of the transport protection: those requests are still
 * interceptable. This is a passive read of the already-downloaded HTML — it does
 * not fetch any of the referenced resources.
 */
object MixedContent {

    // src=, href= and action= (and their single-quoted / unquoted forms) pointing at http://
    private val ATTR = Regex(
        "(?:src|href|action)\\s*=\\s*[\"']?\\s*(http://[^\"'\\s>]+)",
        RegexOption.IGNORE_CASE
    )

    /** Returns the distinct http:// resource URLs, ignoring safe cases. */
    fun find(html: String, limit: Int = 25): List<String> {
        if (html.isBlank()) return emptyList()
        return ATTR.findAll(html)
            .map { it.groupValues[1] }
            // rel="canonical"/alternate and anchor navigation to http pages are not
            // subresource loads; but distinguishing reliably needs a real parser, so
            // we keep href matches too and simply de-duplicate and cap the list.
            .filterNot { it.startsWith("http://www.w3.org") } // XML namespaces, not loads
            .distinct()
            .take(limit)
            .toList()
    }
}
