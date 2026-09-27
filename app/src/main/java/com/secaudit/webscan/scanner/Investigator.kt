package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.Confidence
import com.secaudit.webscan.model.Lead
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
class Investigator {

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

        val HEADER_SIGNALS = mapOf(
            "x-aspnet-version" to "ASP.NET",
            "x-aspnetmvc-version" to "ASP.NET MVC",
            "x-drupal-cache" to "Drupal",
            "x-drupal-dynamic-cache" to "Drupal",
            "x-shopify-stage" to "Shopify",
            "x-litespeed-cache" to "LiteSpeed",
            "x-generator" to "CMS generator"
        )

        val COOKIE_SIGNALS = listOf(
            "phpsessid" to "PHP",
            "jsessionid" to "Java servlet container",
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
            addAll(legacyStackLead(evidence, profile))
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

    // ---------------------------------------------------------------- profile

    /** Builds a stack picture out of many individually inconclusive hints. */
    private fun fingerprint(evidence: Evidence): TechProfile {
        val signals = mutableListOf<TechSignal>()

        evidence.headers["server"]?.takeIf { it.isNotBlank() }?.let { value ->
            signals += TechSignal("Server header", value, describeProducts(value))
        }
        evidence.headers["x-powered-by"]?.takeIf { it.isNotBlank() }?.let { value ->
            signals += TechSignal("X-Powered-By header", value, describeProducts(value))
        }
        HEADER_SIGNALS.forEach { (header, implies) ->
            evidence.headers[header]?.let { value ->
                signals += TechSignal("$header header", value, implies)
            }
        }
        CDN_HEADERS.forEach { (header, vendor) ->
            if (evidence.headers.containsKey(header)) {
                signals += TechSignal("$header header", "present", "$vendor in front of the origin")
            }
        }
        evidence.headers["link"]?.let { value ->
            if (value.contains("wp-json", ignoreCase = true)) {
                signals += TechSignal("Link header", "wp-json REST route", "WordPress")
            }
        }
        evidence.setCookies.forEach { cookie ->
            val name = cookie.substringBefore('=').trim()
            val lower = name.lowercase()
            COOKIE_SIGNALS.firstOrNull { lower.contains(it.first) }?.let { (_, implies) ->
                signals += TechSignal("Cookie name", name, implies)
            }
        }

        val stack = signals
            .map { it.implies }
            .filter { it.isNotBlank() && it != "unrecognised product string" }
            .flatMap { it.split(", ") }
            .distinct()

        return TechProfile(stack, signals)
    }

    private fun describeProducts(raw: String): String {
        val products = parseProducts(raw)
        if (products.isEmpty()) return "unrecognised product string"
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
                    "$name $version (supported branch starts at $floor)"
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

    private fun legacyStackLead(evidence: Evidence, profile: TechProfile): List<Lead> {
        val clues = mutableListOf<String>()

        val legacy = evidence.tls?.accepted.orEmpty().filter { it in LEGACY_TLS }
        if (legacy.isNotEmpty()) clues += "Server completes a handshake on ${legacy.joinToString(" and ")}"

        outdatedProducts(evidence).forEach { clues += "Banner advertises $it" }

        val securityTxt = evidence.securityTxt
        if (securityTxt != null && securityTxt.expired == true) {
            clues += "Published security.txt expired on ${securityTxt.expires}"
        }
        if (evidence.tls?.accepted?.contains("TLSv1.3") == false && evidence.isHttps) {
            clues += "TLS 1.3 is not offered"
        }

        if (clues.size < 2) return emptyList()

        return listOf(
            Lead(
                hypothesis = "This deployment looks like it has not been maintained for some time",
                confidence = if (clues.size >= 3) Confidence.HIGH else Confidence.MEDIUM,
                severity = if (legacy.isNotEmpty()) Severity.HIGH else Severity.MEDIUM,
                evidence = clues,
                soWhat = "Independent signals all point at an ageing configuration. The " +
                    "specific items matter less than the pattern: whoever owns this host is " +
                    "probably not applying the vendor's current guidance, so assume other " +
                    "patches are outstanding too. Confirm the platform's patch level directly."
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
            "Site is served over HTTPS",
            "Cookie(s) set without the Secure attribute: ${insecure.joinToString(", ")}"
        )
        if (!hasHsts) clues += "No Strict-Transport-Security policy is published"
        evidence.tls?.accepted.orEmpty().filter { it in LEGACY_TLS }.takeIf { it.isNotEmpty() }
            ?.let { clues += "Legacy TLS (${it.joinToString(", ")}) still accepted" }

        return listOf(
            Lead(
                hypothesis = "These cookies can end up on the wire in plaintext",
                confidence = if (hasHsts) Confidence.MEDIUM else Confidence.HIGH,
                severity = if (hasHsts) Severity.MEDIUM else Severity.HIGH,
                evidence = clues,
                soWhat = if (hasHsts) {
                    "HSTS keeps browsers on HTTPS after the first visit, which narrows this a " +
                        "lot, but the cookies themselves are still not marked Secure. Anything " +
                        "that reaches the site over HTTP before the policy is cached, or from a " +
                        "client that ignores it, will send them unprotected. Set Secure anyway."
                } else {
                    "Two gaps line up here. Without Secure the browser is willing to send these " +
                        "cookies over plain HTTP, and without HSTS nothing stops it from making " +
                        "that plain-HTTP request in the first place. Together they mean session " +
                        "values can be observed by anyone on the network path. Fixing either one " +
                        "breaks the chain; fix both."
                }
            )
        )
    }

    private fun missingHardeningLayer(evidence: Evidence): List<Lead> {
        val csp = evidence.headers["content-security-policy"].orEmpty()
        val missing = buildList {
            if (csp.isBlank()) add("Content-Security-Policy")
            if (evidence.headers["x-frame-options"].isNullOrBlank() &&
                !csp.contains("frame-ancestors", true)
            ) add("frame protection")
            if (!evidence.headers["x-content-type-options"].equals("nosniff", true)) {
                add("X-Content-Type-Options")
            }
            if (evidence.headers["referrer-policy"].isNullOrBlank()) add("Referrer-Policy")
            if (evidence.headers["permissions-policy"].isNullOrBlank()) add("Permissions-Policy")
        }
        if (missing.size < 4) return emptyList()

        return listOf(
            Lead(
                hypothesis = "No browser-hardening layer was ever configured here",
                confidence = Confidence.HIGH,
                severity = Severity.MEDIUM,
                evidence = missing.map { "$it is absent" },
                soWhat = "When one or two of these are missing it usually means a specific " +
                    "trade-off. When ${missing.size} are missing at once it almost always means " +
                    "nobody configured response headers at all, and the server is answering with " +
                    "stock defaults. That is worth checking as a process gap, not just a config " +
                    "gap: the same omission probably applies to other hosts in the estate."
            )
        )
    }

    private fun originLeakThroughEdge(evidence: Evidence): List<Lead> {
        val edge = CDN_HEADERS.entries.firstOrNull { evidence.headers.containsKey(it.key) }
            ?: return emptyList()

        val originClues = mutableListOf<String>()
        evidence.headers["x-powered-by"]?.let { originClues += "X-Powered-By still reports \"$it\"" }
        evidence.headers["x-aspnet-version"]?.let { originClues += "X-AspNet-Version reports \"$it\"" }
        evidence.setCookies
            .map { it.substringBefore('=').trim() }
            .filter { name -> COOKIE_SIGNALS.any { name.lowercase().contains(it.first) } }
            .forEach { originClues += "Origin framework cookie \"$it\" passes through the edge" }

        if (originClues.isEmpty()) return emptyList()

        return listOf(
            Lead(
                hypothesis = "The CDN fronts the site, but the origin's fingerprint passes straight through",
                confidence = Confidence.MEDIUM,
                severity = Severity.LOW,
                evidence = listOf("${edge.value} is serving the response") + originClues,
                soWhat = "Part of the point of an edge layer is that the origin's software is " +
                    "not the internet's business. These headers and cookie names are generated " +
                    "behind the CDN and forwarded unchanged, so the abstraction is leaking. " +
                    "Strip origin-identifying headers at the edge, or at the origin itself."
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
                hypothesis = "The stack is easy to identify, and there is no published way to report a problem",
                confidence = Confidence.MEDIUM,
                severity = Severity.LOW,
                evidence = listOf(
                    "Identified from response metadata: ${profile.stack.joinToString(", ")}",
                    if (securityTxt?.found == true) {
                        "security.txt exists but declares no Contact field"
                    } else {
                        "No security.txt at /.well-known/security.txt or /security.txt"
                    }
                ),
                soWhat = "These two facts are only interesting together. The stack being " +
                    "identifiable is normal and mostly harmless. The problem is the asymmetry: " +
                    "a researcher who notices something wrong has nowhere to send it, so the " +
                    "report either goes nowhere or goes public. Publishing an RFC 9116 " +
                    "security.txt with a monitored Contact costs very little."
            )
        )
    }

    private fun certificateAndContact(evidence: Evidence): List<Lead> {
        val tls = evidence.tls ?: return emptyList()
        val days = tls.certDaysRemaining ?: return emptyList()
        if (days > 30) return emptyList()

        val contacts = evidence.securityTxt?.contacts.orEmpty()
        val clues = mutableListOf(
            if (days < 0) {
                "Certificate expired ${-days} day(s) ago"
            } else {
                "Certificate expires in $days day(s)"
            }
        )
        tls.certIssuer?.let { clues += "Issued by $it" }
        if (contacts.isEmpty()) clues += "No published security contact to notify"

        return listOf(
            Lead(
                hypothesis = if (days < 0) {
                    "The certificate has already lapsed"
                } else {
                    "The certificate is close to expiry"
                },
                confidence = Confidence.HIGH,
                severity = if (days < 7) Severity.HIGH else Severity.MEDIUM,
                evidence = clues,
                soWhat = "Renewal is routine, so a short remaining life is mainly a signal about " +
                    "automation: either renewal is automated and this is fine, or it is manual " +
                    "and will eventually be missed. Check whether ACME renewal is actually " +
                    "running rather than just renewing it by hand this once."
            )
        )
    }

    private fun downgradeSurface(evidence: Evidence): List<Lead> {
        val accepted = evidence.tls?.accepted.orEmpty()
        val legacy = accepted.filter { it in LEGACY_TLS }
        if (legacy.isEmpty() || !accepted.contains("TLSv1.2")) return emptyList()

        return listOf(
            Lead(
                hypothesis = "Modern TLS is available, but the deprecated versions were never switched off",
                confidence = Confidence.HIGH,
                severity = Severity.HIGH,
                evidence = listOf(
                    "Accepted: ${accepted.joinToString(", ")}",
                    "Deprecated versions still negotiated: ${legacy.joinToString(", ")}",
                    "A modern client would use ${accepted.last()}"
                ),
                soWhat = "Because current clients already negotiate the strong version, leaving " +
                    "TLS 1.0/1.1 enabled buys almost no real compatibility, while keeping the " +
                    "older protocols' weaknesses reachable. This pattern usually means the " +
                    "config was upgraded by adding new versions rather than by replacing the " +
                    "list. Set a minimum version of TLS 1.2."
            )
        )
    }

    private fun weakCipher(evidence: Evidence): List<Lead> {
        val suite = evidence.tls?.cipherSuite ?: return emptyList()
        val markers = WEAK_CIPHER_MARKERS.filter { suite.contains(it, ignoreCase = true) }
        if (markers.isEmpty()) return emptyList()

        return listOf(
            Lead(
                hypothesis = "The negotiated cipher suite uses dated primitives",
                confidence = Confidence.MEDIUM,
                severity = Severity.MEDIUM,
                evidence = listOf(
                    "Negotiated suite: $suite",
                    "Dated elements: ${markers.joinToString(", ")}"
                ),
                soWhat = "This is what the server chose when talking to this device, so it is " +
                    "the preference order that matters, not just the supported list. Prefer " +
                    "AEAD suites (GCM or ChaCha20-Poly1305) and put them first."
            )
        )
    }

    // -------------------------------------------------------------- narration

    private fun narrate(
        evidence: Evidence,
        profile: TechProfile,
        leads: List<Lead>
    ): String {
        if (leads.isEmpty()) {
            return "Nothing in the collected metadata contradicted anything else, and no " +
                "combination of observations formed a chain worth reporting. That is a " +
                "statement about these passive signals only — it is not a clean bill of health " +
                "for the application behind them."
        }

        val builder = StringBuilder()
        builder.append("Examined ${evidence.host} over ${evidence.tls?.bestVersion ?: "HTTP"}")
        if (profile.stack.isNotEmpty()) {
            builder.append(", which presents as ${profile.stack.take(3).joinToString(", ")}")
        }
        builder.append(". ")

        val top = leads.first()
        builder.append("The thread most worth pulling: ${top.hypothesis.lowercase()} ")
        builder.append("(${top.confidence.label.lowercase()}, drawn from ${top.evidence.size} observations). ")

        val high = leads.count { it.severity == Severity.HIGH }
        if (high > 1) {
            builder.append("$high separate chains reached a high-severity conclusion, ")
            builder.append("which usually points at one underlying cause rather than several. ")
        }
        builder.append(
            "Each conclusion below lists the clues behind it — check the reasoning before acting on it."
        )
        return builder.toString()
    }
}
