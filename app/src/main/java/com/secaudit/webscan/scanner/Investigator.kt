package com.secaudit.webscan.scanner

import com.secaudit.webscan.i18n.EnStrings
import com.secaudit.webscan.i18n.Strings
import com.secaudit.webscan.model.Confidence
import com.secaudit.webscan.model.Lead
import com.secaudit.webscan.model.LeadId
import com.secaudit.webscan.model.SecurityTxt
import com.secaudit.webscan.model.Severity
import com.secaudit.webscan.model.TechProfile
import com.secaudit.webscan.model.TechSignal
import com.secaudit.webscan.model.TlsInfo

/** Everything the passive collectors observed about one target. */
data class Evidence(
    val finalUrl: String,
    val host: String,
    val isHttps: Boolean,
    val status: Int,
    val headers: Map<String, String>,
    val setCookies: List<String>,
    val tls: TlsInfo?,
    val securityTxt: SecurityTxt?
)

data class Investigation(
    val leads: List<Lead>,
    val techProfile: TechProfile,
    val summary: String
)

/**
 * The correlation layer.
 *
 * Individual checks answer "is header X present?". This class does the other
 * half of an assessment: it reads all of the observations together and asks what
 * they jointly imply. A missing `Secure` flag is a note on its own; a missing
 * `Secure` flag next to a missing HSTS policy on an HTTPS site is a concrete
 * chain worth writing up. Every conclusion carries the clues that produced it so
 * a reader can check the reasoning rather than trust the verdict.
 */
class Investigator(private val s: Strings = EnStrings) {

    private companion object {
        /** Oldest branch still receiving vendor fixes, for an age sanity check. */
        val SUPPORTED_FLOOR = mapOf(
            "nginx" to "1.24",
            "apache" to "2.4.58",
            "httpd" to "2.4.58",
            "php" to "8.2",
            "openssl" to "3.0",
            "tomcat" to "9.0",
            "jetty" to "10.0"
        )

        val CDN_HEADERS = mapOf(
            "cf-ray" to "Cloudflare",
            "x-amz-cf-id" to "Amazon CloudFront",
            "x-vercel-id" to "Vercel",
            "x-nf-request-id" to "Netlify",
            "x-github-request-id" to "GitHub Pages",
            "fastly-debug-digest" to "Fastly",
            "x-varnish" to "Varnish",
            "x-akamai-transformed" to "Akamai"
        )

        /** A leading "@" marks a translation key rather than a product name. */
        val HEADER_SIGNALS = mapOf(
            "x-aspnet-version" to "ASP.NET",
            "x-aspnetmvc-version" to "ASP.NET MVC",
            "x-drupal-cache" to "Drupal",
            "x-drupal-dynamic-cache" to "Drupal",
            "x-shopify-stage" to "Shopify",
            "x-litespeed-cache" to "LiteSpeed",
            "x-generator" to "@tech.cmsGenerator"
        )

        val COOKIE_SIGNALS = listOf(
            "phpsessid" to "PHP",
            "jsessionid" to "@tech.javaServlet",
            "asp.net_sessionid" to "ASP.NET",
            ".aspnetcore." to "ASP.NET Core",
            "laravel_session" to "Laravel",
            "wordpress_" to "WordPress",
            "wp-settings" to "WordPress",
            "csrftoken" to "Django",
            "_session_id" to "Ruby on Rails",
            "connect.sid" to "Express / Node.js",
            "_shopify" to "Shopify"
        )

        val WEAK_CIPHER_MARKERS = listOf("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "_CBC_")
        val LEGACY_TLS = setOf("TLSv1", "TLSv1.1")
    }

    fun investigate(evidence: Evidence): Investigation {
        val profile = fingerprint(evidence)
        val leads = buildList {
            addAll(legacyStackLead(evidence))
            addAll(cookieExposureChain(evidence))
            addAll(missingHardeningLayer(evidence))
            addAll(originLeakThroughEdge(evidence))
            addAll(fingerprintableWithoutChannel(evidence, profile))
            addAll(certificateAndContact(evidence))
            addAll(downgradeSurface(evidence))
            addAll(weakCipher(evidence))
        }.sortedWith(
            compareByDescending<Lead> { it.severity.weight }.thenByDescending { it.confidence.ordinal }
        )

        return Investigation(leads, profile, narrate(evidence, profile, leads))
    }

    /** Product names stay as they are; "@key" entries are translated. */
    private fun implies(raw: String): String =
        if (raw.startsWith("@")) s.t(raw.substring(1)) else raw

    // ---------------------------------------------------------------- profile

    /** Builds a stack picture out of many individually inconclusive hints. */
    private fun fingerprint(evidence: Evidence): TechProfile {
        val signals = mutableListOf<TechSignal>()

        evidence.headers["server"]?.takeIf { it.isNotBlank() }?.let { value ->
            signals += TechSignal(s.t("tech.src.server"), value, describeProducts(value))
        }
        evidence.headers["x-powered-by"]?.takeIf { it.isNotBlank() }?.let { value ->
            signals += TechSignal(s.t("tech.src.powered"), value, describeProducts(value))
        }
        HEADER_SIGNALS.forEach { (header, implied) ->
            evidence.headers[header]?.let { value ->
                signals += TechSignal(s.t("tech.src.header", header), value, implies(implied))
            }
        }
        CDN_HEADERS.forEach { (header, vendor) ->
            if (evidence.headers.containsKey(header)) {
                signals += TechSignal(
                    s.t("tech.src.header", header),
                    s.t("tech.present"),
                    s.t("tech.cdnInFront", vendor)
                )
            }
        }
        evidence.headers["link"]?.let { value ->
            if (value.contains("wp-json", ignoreCase = true)) {
                signals += TechSignal(s.t("tech.src.link"), s.t("tech.linkWpJson"), "WordPress")
            }
        }
        evidence.setCookies.forEach { cookie ->
            val name = cookie.substringBefore('=').trim()
            val lower = name.lowercase()
            COOKIE_SIGNALS.firstOrNull { lower.contains(it.first) }?.let { (_, implied) ->
                signals += TechSignal(s.t("tech.src.cookie"), name, implies(implied))
            }
        }

        val unrecognised = s.t("tech.unrecognised")
        val stack = signals
            .map { it.implies }
            .filter { it.isNotBlank() && it != unrecognised }
            .flatMap { it.split(", ") }
            .distinct()

        return TechProfile(stack, signals)
    }

    private fun describeProducts(raw: String): String {
        val products = parseProducts(raw)
        if (products.isEmpty()) return s.t("tech.unrecognised")
        return products.joinToString(", ") { (name, version) ->
            if (version == null) name else "$name $version"
        }
    }

    /** Extracts `product/version` pairs from a header such as `Apache/2.4.41 (Ubuntu)`. */
    private fun parseProducts(raw: String): List<Pair<String, String?>> =
        Regex("([A-Za-z][A-Za-z0-9._+-]*)(?:/(\\d[\\d.]*))?")
            .findAll(raw)
            .map { it.groupValues[1] to it.groupValues[2].takeIf(String::isNotEmpty) }
            .filter { it.first.length > 1 }
            .toList()

    /** Returns products whose advertised version predates the supported branch. */
    private fun outdatedProducts(evidence: Evidence): List<String> =
        listOfNotNull(evidence.headers["server"], evidence.headers["x-powered-by"])
            .flatMap(::parseProducts)
            .mapNotNull { (name, version) ->
                val floor = SUPPORTED_FLOOR[name.lowercase()] ?: return@mapNotNull null
                if (version != null && compareVersions(version, floor) < 0) {
                    s.t("tech.branchNote", name, version, floor)
                } else {
                    null
                }
            }

    private fun compareVersions(a: String, b: String): Int {
        val left = a.split('.').mapNotNull { it.toIntOrNull() }
        val right = b.split('.').mapNotNull { it.toIntOrNull() }
        for (i in 0 until maxOf(left.size, right.size)) {
            val l = left.getOrElse(i) { 0 }
            val r = right.getOrElse(i) { 0 }
            if (l != r) return l.compareTo(r)
        }
        return 0
    }

    // ------------------------------------------------------------------ leads

    private fun legacyStackLead(evidence: Evidence): List<Lead> {
        val clues = mutableListOf<String>()

        val legacy = evidence.tls?.accepted.orEmpty().filter { it in LEGACY_TLS }
        if (legacy.isNotEmpty()) clues += s.t("c.legacyHandshake", legacy.joinToString(" / "))

        outdatedProducts(evidence).forEach { clues += s.t("c.bannerOutdated", it) }

        val securityTxt = evidence.securityTxt
        if (securityTxt != null && securityTxt.expired == true) {
            clues += s.t("c.stxtExpired", securityTxt.expires)
        }
        if (evidence.isHttps && evidence.tls?.accepted?.contains("TLSv1.3") == false) {
            clues += s.t("c.noTls13")
        }

        if (clues.size < 2) return emptyList()

        return listOf(
            Lead(
                id = LeadId.UNMAINTAINED,
                hypothesis = s.t("l.unmaintained.h"),
                confidence = if (clues.size >= 3) Confidence.HIGH else Confidence.MEDIUM,
                severity = if (legacy.isNotEmpty()) Severity.HIGH else Severity.MEDIUM,
                evidence = clues,
                soWhat = s.t("l.unmaintained.s")
            )
        )
    }

    private fun cookieExposureChain(evidence: Evidence): List<Lead> {
        if (!evidence.isHttps) return emptyList()

        val insecure = evidence.setCookies
            .filter { !it.lowercase().contains("secure") }
            .map { it.substringBefore('=').trim() }
        if (insecure.isEmpty()) return emptyList()

        val hasHsts = evidence.headers.containsKey("strict-transport-security")
        val clues = mutableListOf(
            s.t("c.servedHttps"),
            s.t("c.cookiesNoSecure", insecure.joinToString(", "))
        )
        if (!hasHsts) clues += s.t("c.noHstsPolicy")
        evidence.tls?.accepted.orEmpty().filter { it in LEGACY_TLS }.takeIf { it.isNotEmpty() }
            ?.let { clues += s.t("c.legacyStillAccepted", it.joinToString(", ")) }

        return listOf(
            Lead(
                id = LeadId.COOKIE_PLAINTEXT_CHAIN,
                hypothesis = s.t("l.cookiechain.h"),
                confidence = if (hasHsts) Confidence.MEDIUM else Confidence.HIGH,
                severity = if (hasHsts) Severity.MEDIUM else Severity.HIGH,
                evidence = clues,
                soWhat = s.t(if (hasHsts) "l.cookiechain.s.hsts" else "l.cookiechain.s.nohsts")
            )
        )
    }

    private fun missingHardeningLayer(evidence: Evidence): List<Lead> {
        val csp = evidence.headers["content-security-policy"].orEmpty()
        val missing = buildList {
            if (csp.isBlank()) add(s.t("hdr.csp"))
            if (evidence.headers["x-frame-options"].isNullOrBlank() &&
                !csp.contains("frame-ancestors", true)
            ) add(s.t("hdr.frame"))
            if (!evidence.headers["x-content-type-options"].equals("nosniff", true)) {
                add(s.t("hdr.nosniff"))
            }
            if (evidence.headers["referrer-policy"].isNullOrBlank()) add(s.t("hdr.referrer"))
            if (evidence.headers["permissions-policy"].isNullOrBlank()) add(s.t("hdr.permissions"))
        }
        if (missing.size < 4) return emptyList()

        return listOf(
            Lead(
                id = LeadId.NO_HARDENING_LAYER,
                hypothesis = s.t("l.hardening.h"),
                confidence = Confidence.HIGH,
                severity = Severity.MEDIUM,
                evidence = missing.map { s.t("c.headerAbsent", it) },
                soWhat = s.t("l.hardening.s", missing.size)
            )
        )
    }

    private fun originLeakThroughEdge(evidence: Evidence): List<Lead> {
        val edge = CDN_HEADERS.entries.firstOrNull { evidence.headers.containsKey(it.key) }
            ?: return emptyList()

        val originClues = mutableListOf<String>()
        evidence.headers["x-powered-by"]?.let { originClues += s.t("c.poweredByReports", it) }
        evidence.headers["x-aspnet-version"]?.let { originClues += s.t("c.aspnetVersion", it) }
        evidence.setCookies
            .map { it.substringBefore('=').trim() }
            .filter { name -> COOKIE_SIGNALS.any { name.lowercase().contains(it.first) } }
            .forEach { originClues += s.t("c.originCookie", it) }

        if (originClues.isEmpty()) return emptyList()

        return listOf(
            Lead(
                id = LeadId.EDGE_ORIGIN_LEAK,
                hypothesis = s.t("l.edgeleak.h"),
                confidence = Confidence.MEDIUM,
                severity = Severity.LOW,
                evidence = listOf(s.t("c.edgeServing", edge.value)) + originClues,
                soWhat = s.t("l.edgeleak.s")
            )
        )
    }

    private fun fingerprintableWithoutChannel(
        evidence: Evidence,
        profile: TechProfile
    ): List<Lead> {
        val securityTxt = evidence.securityTxt
        val hasChannel = securityTxt?.found == true && securityTxt.contacts.isNotEmpty()
        if (hasChannel || profile.stack.size < 2) return emptyList()

        return listOf(
            Lead(
                id = LeadId.FINGERPRINTABLE_NO_CONTACT,
                hypothesis = s.t("l.fingerprint.h"),
                confidence = Confidence.MEDIUM,
                severity = Severity.LOW,
                evidence = listOf(
                    s.t("c.identifiedStack", profile.stack.joinToString(", ")),
                    if (securityTxt?.found == true) {
                        s.t("c.stxtNoContactField")
                    } else {
                        s.t("c.noStxtFile")
                    }
                ),
                soWhat = s.t("l.fingerprint.s")
            )
        )
    }

    private fun certificateAndContact(evidence: Evidence): List<Lead> {
        val tls = evidence.tls ?: return emptyList()
        val days = tls.certDaysRemaining ?: return emptyList()
        if (days > 30) return emptyList()

        val contacts = evidence.securityTxt?.contacts.orEmpty()
        val clues = mutableListOf(
            if (days < 0) s.t("c.certExpiredAgo", -days) else s.t("c.certExpiresIn", days)
        )
        tls.certIssuer?.let { clues += s.t("c.issuedBy", it) }
        if (contacts.isEmpty()) clues += s.t("c.noSecurityContact")

        return listOf(
            Lead(
                id = LeadId.CERTIFICATE_EXPIRY,
                hypothesis = s.t(if (days < 0) "l.cert.h.expired" else "l.cert.h.expiring"),
                confidence = Confidence.HIGH,
                severity = if (days < 7) Severity.HIGH else Severity.MEDIUM,
                evidence = clues,
                soWhat = s.t("l.cert.s")
            )
        )
    }

    private fun downgradeSurface(evidence: Evidence): List<Lead> {
        val accepted = evidence.tls?.accepted.orEmpty()
        val legacy = accepted.filter { it in LEGACY_TLS }
        if (legacy.isEmpty() || !accepted.contains("TLSv1.2")) return emptyList()

        return listOf(
            Lead(
                id = LeadId.TLS_DOWNGRADE_SURFACE,
                hypothesis = s.t("l.downgrade.h"),
                confidence = Confidence.HIGH,
                severity = Severity.HIGH,
                evidence = listOf(
                    s.t("c.acceptedVersions", accepted.joinToString(", ")),
                    s.t("c.deprecatedNegotiated", legacy.joinToString(", ")),
                    s.t("c.modernClientUses", accepted.last())
                ),
                soWhat = s.t("l.downgrade.s")
            )
        )
    }

    private fun weakCipher(evidence: Evidence): List<Lead> {
        val suite = evidence.tls?.cipherSuite ?: return emptyList()
        val markers = WEAK_CIPHER_MARKERS.filter { suite.contains(it, ignoreCase = true) }
        if (markers.isEmpty()) return emptyList()

        return listOf(
            Lead(
                id = LeadId.WEAK_CIPHER,
                hypothesis = s.t("l.weakcipher.h"),
                confidence = Confidence.MEDIUM,
                severity = Severity.MEDIUM,
                evidence = listOf(
                    s.t("c.negotiatedSuite", suite),
                    s.t("c.datedElements", markers.joinToString(", "))
                ),
                soWhat = s.t("l.weakcipher.s")
            )
        )
    }

    // -------------------------------------------------------------- narration

    private fun narrate(
        evidence: Evidence,
        profile: TechProfile,
        leads: List<Lead>
    ): String {
        if (leads.isEmpty()) return s.t("narr.nothing")

        val builder = StringBuilder()
        builder.append(
            s.t("narr.opening", evidence.host, evidence.tls?.bestVersion ?: s.t("narr.protoHttp"))
        )
        if (profile.stack.isNotEmpty()) {
            builder.append(s.t("narr.stack", profile.stack.take(3).joinToString(", ")))
        }
        builder.append(". ")

        val top = leads.first()
        builder.append(
            s.t(
                "narr.top",
                top.hypothesis.replaceFirstChar { it.lowercase() },
                s.t(top.confidence.key).lowercase(),
                top.evidence.size
            )
        )

        val high = leads.count { it.severity == Severity.HIGH }
        if (high > 1) builder.append(s.t("narr.multiHigh", high))

        builder.append(s.t("narr.closing"))
        return builder.toString()
    }
}
