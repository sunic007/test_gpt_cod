package com.secaudit.webscan.i18n

object EnStrings : Strings() {

    override val lang = Lang.EN

    override val map = mapOf(
        // ---------------------------------------------------------------- chrome
        "ui.app.title" to "WEB SECURITY AUDIT",
        "ui.target.label" to "TARGET",
        "ui.target.hint" to "example.com",
        "ui.action.scan" to "RUN AUDIT",
        "ui.action.reset" to "CLEAR",
        "ui.action.export" to "SHARE",
        "ui.sec.history" to "HISTORY",
        "ui.history.clear" to "CLEAR ALL",

        // ------------------------------------------------------------ lab screen
        "ui.tab.audit" to "AUDIT",
        "ui.tab.lab" to "LAB",
        "lab.copy" to "COPY",
        "lab.title" to "TRAINING LAB",
        "lab.intro" to "A local, intentionally-vulnerable playground for practising security " +
            "tooling legally — it runs on your own machine, against targets you own.",
        "lab.warn.title" to "YOUR MACHINE ONLY",
        "lab.warn.body" to "The lab removes the legality problem: you may run any tool, even the " +
            "aggressive ones, against these containers because they are yours. Never point the " +
            "same tools at systems you do not own or are not authorised to test.",
        "lab.public.title" to "BEYOND LOCALHOST (AUTHORISED TARGETS)",
        "lab.public.body" to "The Audit tab already scans any site you enter. For active practice " +
            "off your own device, use targets whose owners publicly permit testing — listed below. " +
            "Do not point active tools at any other external site.",
        "lab.phone.title" to "PHONE ONLY (TERMUX)",
        "lab.phone.body" to "No PC needed. Install Termux (from F-Droid), then run this to fetch " +
            "and start DSVW (Damn Small Vulnerable Web, a ready-made project by stamparm) on the " +
            "phone itself. It serves at localhost:65412 — scan it in the Audit tab. Full steps: " +
            "lab/termux/README.md.",
        "lab.docker.title" to "FULL LAB (NEEDS A PC)",
        "lab.docker.body" to "On a machine with Docker you can run the full Juice Shop and DVWA " +
            "and point real Kali tools at them.",
        "lab.step1.title" to "1 · START THE LAB",
        "lab.step1.body" to "Requires Docker. This starts OWASP Juice Shop and DVWA, bound to " +
            "localhost only.",
        "lab.targets.title" to "2 · LOCAL TARGETS",
        "lab.targets.body" to "Open these in a browser, or point the Audit tab at localhost:3000.",
        "lab.step2.title" to "3 · RUN TOOLS AT LOCALHOST",
        "lab.step2.body" to "On your Kali box, aim the offensive tooling at your own containers.",
        "lab.step3.title" to "4 · LEARN THE BUGS",
        "lab.step3.body" to "The tools are the easy part; these walk through the vulnerabilities " +
            "themselves.",
        "ui.lang.label" to "LANGUAGE",
        "ui.footer" to "The app reads only what the target publishes about itself: one page " +
            "request, handshake-only TLS probes, and the disclosure policy. Use it solely on " +
            "systems you own or are explicitly authorised to assess.",
        "ui.error.title" to "REQUEST FAILED",
        "ui.err.noTarget" to "Enter a target address first.",
        "ui.err.generic" to "The request failed.",

        // ---------------------------------------------------------------- report
        "ui.case.title" to "CASE SUMMARY",
        "ui.evidence" to "EVIDENCE",
        "ui.fix" to "Fix: %s",
        "ui.meta" to "HTTP %d · %d ms · observations: %d",
        "ui.score" to "Header hygiene: %d/100",
        "ui.sec.investigation" to "INVESTIGATION",
        "ui.sec.tech" to "TECHNOLOGY PROFILE",
        "ui.sec.tls" to "TLS",
        "ui.sec.disclosure" to "DISCLOSURE POLICY",
        "ui.sec.observations" to "OBSERVATIONS",
        "ui.tech.stack" to "INFERRED STACK",
        "ui.tech.signals" to "SIGNALS BEHIND IT",

        "ui.tls.accepted" to "ACCEPTED",
        "ui.tls.refused" to "REFUSED",
        "ui.tls.untestable" to "NOT TESTABLE HERE",
        "ui.tls.suite" to "CIPHER SUITE",
        "ui.tls.cert" to "CERTIFICATE",
        "ui.tls.issuer" to "ISSUER",
        "ui.tls.expiresIn" to "VALID FOR",
        "ui.tls.sans" to "SAN ENTRIES",
        "ui.tls.unavailable" to "COULD NOT PROFILE TLS",
        "ui.tls.nohandshake" to "No handshake completed.",
        "ui.tls.expiredAgo" to "expired %d d ago",
        "ui.tls.daysLeft" to "%d d",

        "ui.stxt.missing.title" to "NOT PUBLISHED",
        "ui.stxt.missing.body" to "No policy at /.well-known/security.txt or /security.txt.",
        "ui.stxt.location" to "LOCATION",
        "ui.stxt.contact" to "CONTACT",
        "ui.stxt.expires" to "EXPIRES",
        "ui.stxt.expiredSuffix" to "%s (expired)",
        "ui.stxt.policy" to "POLICY",
        "ui.stxt.encryption" to "ENCRYPTION",
        "ui.stxt.languages" to "LANGUAGES",
        "ui.stxt.canonical" to "CANONICAL",

        // ------------------------------------------------------------- vocabulary
        "sev.high" to "HIGH",
        "sev.medium" to "MEDIUM",
        "sev.low" to "LOW",
        "sev.info" to "INFO",
        "conf.high" to "STRONG",
        "conf.medium" to "PROBABLE",
        "conf.low" to "TENTATIVE",
        "cat.transport" to "TRANSPORT",
        "cat.headers" to "HEADERS",
        "cat.cookies" to "COOKIES",
        "cat.tls" to "TLS",
        "cat.dns" to "DNS",
        "cat.content" to "CONTENT",
        "cat.disclosure" to "DISCLOSURE",
        "cat.general" to "GENERAL",

        // -------------------------------------------------------- grade & words
        "ui.grade" to "GRADE",
        "word.yes" to "yes",
        "word.no" to "no",

        // ----------------------------------------------------- new UI sections
        "prog.dns" to "Resolving DNS records for %s …",
        "ui.sec.dns" to "DNS",
        "ui.dns.unavailable" to "DNS COULD NOT BE RESOLVED",
        "ui.dns.caa" to "CAA",
        "ui.dns.dnssec" to "DNSSEC",
        "ui.dns.spf" to "SPF",
        "ui.dns.dmarc" to "DMARC",
        "ui.tls.key" to "PUBLIC KEY",
        "ui.tls.sig" to "SIGNATURE",
        "ui.tls.chain" to "CHAIN LENGTH",
        "ui.tls.covers" to "COVERS HOST",

        // -------------------------------------------------- certificate findings
        "f.certweaksig.title" to "Weak certificate signature",
        "f.certweaksig.detail" to "The certificate is signed with %s, which relies on a " +
            "collision-broken hash.",
        "f.certweaksig.fix" to "Reissue the certificate with an SHA-256 (or stronger) signature.",

        "f.certweakkey.title" to "Under-strength certificate key",
        "f.certweakkey.detail" to "The certificate uses a %s key of only %d bits.",
        "f.certweakkey.fix" to "Use at least RSA 2048 or an EC P-256 key.",

        "f.certnohost.title" to "Host not listed in the certificate",
        "f.certnohost.detail" to "The presented certificate's SAN entries do not cover the " +
            "requested host. A browser would reject it.",
        "f.certnohost.fix" to "Issue a certificate whose SAN includes this host.",

        "f.tlsprofile.key" to "Key: %s %d-bit. ",
        "f.tlsprofile.sig" to "Signature: %s. ",
        "f.tlsprofile.chain" to "Chain length: %d. ",

        // ------------------------------------------------------- mixed content
        "f.mixed.title" to "Mixed content: %d plain-HTTP resource(s)",
        "f.mixed.detail" to "This HTTPS page references resources over http://:\n%s",
        "f.mixed.fix" to "Load all subresources over https:// (or protocol-relative URLs).",

        // ----------------------------------------------------------- DNS findings
        "f.nocaa.title" to "No CAA record",
        "f.nocaa.detail" to "No Certification Authority Authorization record. Any CA may issue " +
            "certificates for this domain.",
        "f.nocaa.fix" to "Publish a CAA record naming your permitted issuer(s).",

        "f.nodnssec.title" to "DNSSEC not enabled",
        "f.nodnssec.detail" to "Responses are not DNSSEC-authenticated, so DNS answers can be " +
            "spoofed.",
        "f.nodnssec.fix" to "Enable DNSSEC signing at your DNS provider.",

        "f.nodmarc.title" to "No DMARC policy",
        "f.nodmarc.detail" to "No _dmarc record. Attackers can spoof mail from this domain.",
        "f.nodmarc.fix" to "Publish a DMARC record, building up to p=reject.",

        "f.dmarcnone.title" to "DMARC policy is p=none",
        "f.dmarcnone.detail" to "DMARC is published but only monitors; it does not block spoofed " +
            "mail.",
        "f.dmarcnone.fix" to "Move the policy to quarantine, then reject.",

        "f.nospf.title" to "No SPF record",
        "f.nospf.detail" to "No v=spf1 TXT record. Receivers cannot check which hosts may send " +
            "mail for this domain.",
        "f.nospf.fix" to "Publish an SPF record listing your legitimate senders.",

        "f.dnsprofile.title" to "DNS profile",
        "f.dnsprofile.caa" to "CAA records: %d. ",
        "f.dnsprofile.dnssec" to "DNSSEC: %s. ",
        "f.dnsprofile.spf" to "SPF: %s. ",
        "f.dnsprofile.dmarc" to "DMARC: %s.",

        // ------------------------------------------------- deep header hardening
        "f.cspinline.title" to "CSP allows 'unsafe-inline'",
        "f.cspinline.detail" to "The Content-Security-Policy permits inline scripts/styles, which " +
            "largely defeats CSP's XSS protection.",
        "f.cspinline.fix" to "Remove 'unsafe-inline'; use nonces or hashes instead.",

        "f.cspeval.title" to "CSP allows 'unsafe-eval'",
        "f.cspeval.detail" to "'unsafe-eval' lets strings be executed as code (eval, new Function).",
        "f.cspeval.fix" to "Remove 'unsafe-eval' and refactor code that needs it.",

        "f.cspwildcard.title" to "CSP uses a wildcard source",
        "f.cspwildcard.detail" to "default-src or script-src contains '*', allowing scripts from " +
            "any origin.",
        "f.cspwildcard.fix" to "Replace '*' with an explicit allow-list of origins.",

        "f.cspbaseuri.title" to "CSP has no base-uri",
        "f.cspbaseuri.detail" to "Without base-uri, an injected <base> tag can hijack relative URLs.",
        "f.cspbaseuri.fix" to "Add base-uri 'self' (or 'none') to the policy.",

        "f.hstsshort.title" to "HSTS max-age is short",
        "f.hstsshort.detail" to "max-age is %d seconds; under ~6 months weakens the guarantee and " +
            "blocks preload eligibility.",
        "f.hstsshort.fix" to "Use max-age=31536000 (1 year).",

        "f.hstsnosub.title" to "HSTS without includeSubDomains",
        "f.hstsnosub.detail" to "Subdomains are not covered by the HSTS policy.",
        "f.hstsnosub.fix" to "Add includeSubDomains (and preload once ready).",

        "f.corscred.title" to "CORS exposes credentials to a specific origin",
        "f.corscred.detail" to "Access-Control-Allow-Origin is \"%s\" with Allow-Credentials: " +
            "true. If that origin is reflected from the request, any site can read authenticated " +
            "responses.",
        "f.corscred.fix" to "Never combine credentials with a reflected/loose origin; pin an exact, trusted origin.",

        "f.corswildcard.title" to "CORS allows any origin (*)",
        "f.corswildcard.detail" to "Access-Control-Allow-Origin: * lets any site read the response.",
        "f.corswildcard.fix" to "Restrict to specific trusted origins if the data is not public.",

        "f.cookiehost.title" to "Cookie \"%s\" breaks __Host- rules",
        "f.cookiehost.detail" to "A __Host- cookie must be Secure, Path=/ and have no Domain.",
        "f.cookiehost.fix" to "Set Secure; Path=/ and drop the Domain attribute.",

        "f.cookiesecpfx.title" to "Cookie \"%s\" ignores its __Secure- prefix",
        "f.cookiesecpfx.detail" to "A __Secure- cookie must carry the Secure attribute.",
        "f.cookiesecpfx.fix" to "Add the Secure attribute.",

        "f.cookiesamenone.title" to "Cookie \"%s\" is SameSite=None without Secure",
        "f.cookiesamenone.detail" to "SameSite=None requires Secure; browsers reject it otherwise.",
        "f.cookiesamenone.fix" to "Add Secure, or use SameSite=Lax/Strict.",

        "f.hpkp.title" to "Deprecated Public-Key-Pins header",
        "f.hpkp.detail" to "HPKP is deprecated and removed from browsers; a bad pin can lock out " +
            "your own users.",
        "f.hpkp.fix" to "Remove the Public-Key-Pins header.",

        "f.xxss.title" to "X-XSS-Protection is enabled",
        "f.xxss.detail" to "The legacy XSS auditor is removed from modern browsers and can " +
            "introduce bugs; it should be 0 or absent.",
        "f.xxss.fix" to "Set X-XSS-Protection: 0 (rely on CSP instead).",

        // --------------------------------------------------------------- progress
        "prog.start" to "Starting …",
        "prog.request" to "Requesting %s …",
        "prog.tls" to "Probing TLS versions on %s …",
        "prog.stxt" to "Looking for a disclosure policy …",
        "prog.correlate" to "Correlating observations …",

        // --------------------------------------------------------------- findings
        "f.info.fix" to "Informational.",

        "f.nohttps.title" to "Site not served over HTTPS",
        "f.nohttps.detail" to "The final response was delivered over plain HTTP (%s). " +
            "Traffic can be read or modified in transit.",
        "f.nohttps.fix" to "Serve all content over HTTPS and redirect HTTP to HTTPS.",

        "f.hsts.title" to "Missing Strict-Transport-Security (HSTS)",
        "f.hsts.detail" to "No HSTS header. Browsers may fall back to HTTP on the first visit.",
        "f.hsts.fix" to "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",

        "f.csp.title" to "Missing Content-Security-Policy",
        "f.csp.detail" to "No CSP header. CSP is a key defence against XSS and data injection.",
        "f.csp.fix" to "Define a Content-Security-Policy tailored to your resources.",

        "f.frame.title" to "Clickjacking protection not set",
        "f.frame.detail" to "Neither X-Frame-Options nor CSP frame-ancestors is present.",
        "f.frame.fix" to "Add X-Frame-Options: DENY or a CSP frame-ancestors directive.",

        "f.nosniff.title" to "MIME sniffing not disabled",
        "f.nosniff.detail" to "X-Content-Type-Options: nosniff is missing.",
        "f.nosniff.fix" to "Add: X-Content-Type-Options: nosniff",

        "f.referrer.title" to "No Referrer-Policy",
        "f.referrer.detail" to "Without a Referrer-Policy, full URLs may leak to third parties.",
        "f.referrer.fix" to "Add: Referrer-Policy: strict-origin-when-cross-origin",

        "f.permissions.title" to "No Permissions-Policy",
        "f.permissions.detail" to "Permissions-Policy lets you disable powerful browser features.",
        "f.permissions.fix" to "Consider restricting features, e.g. geolocation=(), camera=().",

        "f.server.title" to "Server version disclosed",
        "f.server.detail" to "The Server header reveals software and version: \"%s\".",
        "f.server.fix" to "Suppress version details in the Server header.",

        "f.powered.title" to "X-Powered-By disclosed",
        "f.powered.detail" to "X-Powered-By reveals backend technology: \"%s\".",
        "f.powered.fix" to "Remove the X-Powered-By header.",

        "f.cookie.title" to "Cookie \"%s\" has weak attributes",
        "f.cookie.detail" to "Cookie set with: %s.",
        "f.cookie.fix" to "Set Secure; HttpOnly; SameSite on session cookies.",
        "f.cookie.issue.secure" to "missing Secure",
        "f.cookie.issue.httponly" to "missing HttpOnly",
        "f.cookie.issue.samesite" to "missing SameSite",

        "f.tlsfail.title" to "TLS versions could not be profiled",
        "f.tlsfail.fix" to "Check the host from a network that permits direct TLS connections.",

        "f.tlsdeprecated.title" to "Deprecated TLS accepted: %s",
        "f.tlsdeprecated.detail" to "The server completed a handshake using %s. Both were " +
            "deprecated by RFC 8996 and are rejected by current browsers.",
        "f.tlsdeprecated.fix" to "Set the minimum protocol version to TLS 1.2.",

        "f.notls13.title" to "TLS 1.3 not offered",
        "f.notls13.detail" to "Accepted versions: %s. TLS 1.3 removes legacy primitives and " +
            "shortens the handshake.",
        "f.notls13.fix" to "Enable TLS 1.3 on the listener.",

        "f.certexpired.title" to "Certificate expired",
        "f.certexpired.detail" to "The presented certificate expired %d d ago.",
        "f.certexpired.fix" to "Renew the certificate and verify automated renewal.",

        "f.certexpiring.title" to "Certificate expires in %d d",
        "f.certexpiring.detail" to "Issuer: %s.",
        "f.certexpiring.fix" to "Confirm that automated renewal is running.",

        "f.tlsprofile.title" to "TLS profile",
        "f.tlsprofile.accepted" to "Accepted: %s. ",
        "f.tlsprofile.refused" to "Refused: %s. ",
        "f.tlsprofile.untestable" to "Not testable on this device: %s. ",
        "f.tlsprofile.suite" to "Negotiated suite: %s. ",
        "f.tlsprofile.subject" to "Subject: %s. ",
        "f.tlsprofile.sans" to "SAN entries: %d.",

        "f.nostxt.title" to "No security.txt published",
        "f.nostxt.detail" to "Neither /.well-known/security.txt nor /security.txt returned a " +
            "policy. RFC 9116 defines this file so researchers know where to send reports.",
        "f.nostxt.fix" to "Publish /.well-known/security.txt with Contact and Expires fields.",

        "f.stxtnocontact.title" to "security.txt has no Contact field",
        "f.stxtnocontact.detail" to "RFC 9116 requires at least one Contact field; the " +
            "published file has none.",
        "f.stxtnocontact.fix" to "Add a Contact field (mailto:, https: or tel: URI).",

        "f.stxtexpired.title" to "security.txt has expired",
        "f.stxtexpired.detail" to "The Expires field is %s, which is in the past. Clients are " +
            "expected to disregard an expired policy.",
        "f.stxtexpired.fix" to "Refresh Expires (RFC 9116 suggests under a year out).",

        "f.stxtnoexpires.title" to "security.txt has no Expires field",
        "f.stxtnoexpires.detail" to "Expires is a required field under RFC 9116.",
        "f.stxtnoexpires.fix" to "Add an ISO-8601 Expires timestamp.",

        "f.stxtbadexpires.title" to "security.txt Expires value is unparseable",
        "f.stxtbadexpires.detail" to "Could not read \"%s\" as an ISO-8601 timestamp.",
        "f.stxtbadexpires.fix" to "Use a format such as 2027-01-01T00:00:00.000Z.",

        "f.stxtok.title" to "security.txt published",
        "f.stxtok.detail" to "Found at %s. Contact: %s. Valid until %s.",
        "f.stxtok.policy" to " Policy: %s.",

        // ------------------------------------------------------------------ leads
        "l.unmaintained.h" to "This deployment looks like it has not been maintained for some time",
        "l.unmaintained.s" to "Independent signals all point at an ageing configuration. The " +
            "specific items matter less than the pattern: whoever owns this host is probably " +
            "not applying the vendor's current guidance, so assume other patches are " +
            "outstanding too. Confirm the platform's patch level directly.",

        "l.cookiechain.h" to "These cookies can end up on the wire in plaintext",
        "l.cookiechain.s.hsts" to "HSTS keeps browsers on HTTPS after the first visit, which " +
            "narrows this a lot, but the cookies themselves are still not marked Secure. " +
            "Anything that reaches the site over HTTP before the policy is cached, or from a " +
            "client that ignores it, will send them unprotected. Set Secure anyway.",
        "l.cookiechain.s.nohsts" to "Two gaps line up here. Without Secure the browser is " +
            "willing to send these cookies over plain HTTP, and without HSTS nothing stops it " +
            "from making that plain-HTTP request in the first place. Together they mean session " +
            "values can be observed by anyone on the network path. Fixing either one breaks the " +
            "chain; fix both.",

        "l.hardening.h" to "No browser-hardening layer was ever configured here",
        "l.hardening.s" to "When one or two of these are missing it usually reflects a specific " +
            "trade-off. When %d are missing at once it almost always means nobody configured " +
            "response headers at all and the server is answering with stock defaults. That is " +
            "worth checking as a process gap, not just a config gap: the same omission probably " +
            "applies to other hosts in the estate.",

        "l.edgeleak.h" to "The CDN fronts the site, but the origin's fingerprint passes straight through",
        "l.edgeleak.s" to "Part of the point of an edge layer is that the origin's software is " +
            "not the internet's business. These headers and cookie names are generated behind " +
            "the CDN and forwarded unchanged, so the abstraction is leaking. Strip " +
            "origin-identifying headers at the edge, or at the origin itself.",

        "l.fingerprint.h" to "The stack is easy to identify, and there is no published way to report a problem",
        "l.fingerprint.s" to "These two facts are only interesting together. The stack being " +
            "identifiable is normal and mostly harmless. The problem is the asymmetry: a " +
            "researcher who notices something wrong has nowhere to send it, so the report " +
            "either goes nowhere or goes public. Publishing an RFC 9116 security.txt with a " +
            "monitored Contact costs very little.",

        "l.cert.h.expired" to "The certificate has already lapsed",
        "l.cert.h.expiring" to "The certificate is close to expiry",
        "l.cert.s" to "Renewal is routine, so a short remaining life is mainly a signal about " +
            "automation: either renewal is automated and this is fine, or it is manual and will " +
            "eventually be missed. Check whether ACME renewal is actually running rather than " +
            "just renewing it by hand this once.",

        "l.downgrade.h" to "Modern TLS is available, but the deprecated versions were never switched off",
        "l.downgrade.s" to "Because current clients already negotiate the strong version, " +
            "leaving TLS 1.0/1.1 enabled buys almost no real compatibility, while keeping the " +
            "older protocols' weaknesses reachable. This pattern usually means the config was " +
            "upgraded by adding new versions rather than by replacing the list. Set a minimum " +
            "version of TLS 1.2.",

        "l.weakcipher.h" to "The negotiated cipher suite uses dated primitives",
        "l.weakcipher.s" to "This is what the server chose when talking to this device, so it " +
            "is the preference order that matters, not just the supported list. Prefer AEAD " +
            "suites (GCM or ChaCha20-Poly1305) and put them first.",

        // ------------------------------------------------------------------ clues
        "c.legacyHandshake" to "Server completes a handshake on %s",
        "c.bannerOutdated" to "Banner advertises %s",
        "c.stxtExpired" to "Published security.txt expired on %s",
        "c.noTls13" to "TLS 1.3 is not offered",
        "c.servedHttps" to "Site is served over HTTPS",
        "c.cookiesNoSecure" to "Cookie(s) set without the Secure attribute: %s",
        "c.noHstsPolicy" to "No Strict-Transport-Security policy is published",
        "c.legacyStillAccepted" to "Legacy TLS (%s) still accepted",
        "c.headerAbsent" to "%s is absent",
        "c.edgeServing" to "%s is serving the response",
        "c.poweredByReports" to "X-Powered-By still reports \"%s\"",
        "c.aspnetVersion" to "X-AspNet-Version reports \"%s\"",
        "c.originCookie" to "Origin framework cookie \"%s\" passes through the edge",
        "c.identifiedStack" to "Identified from response metadata: %s",
        "c.noStxtFile" to "No security.txt at /.well-known/security.txt or /security.txt",
        "c.stxtNoContactField" to "security.txt exists but declares no Contact field",
        "c.certExpiredAgo" to "Certificate expired %d d ago",
        "c.certExpiresIn" to "Certificate expires in %d d",
        "c.issuedBy" to "Issued by %s",
        "c.noSecurityContact" to "No published security contact to notify",
        "c.acceptedVersions" to "Accepted: %s",
        "c.deprecatedNegotiated" to "Deprecated versions still negotiated: %s",
        "c.modernClientUses" to "A modern client would use %s",
        "c.negotiatedSuite" to "Negotiated suite: %s",
        "c.datedElements" to "Dated elements: %s",

        "hdr.csp" to "Content-Security-Policy",
        "hdr.frame" to "frame protection",
        "hdr.nosniff" to "X-Content-Type-Options",
        "hdr.referrer" to "Referrer-Policy",
        "hdr.permissions" to "Permissions-Policy",

        // ------------------------------------------------------------------- tech
        "tech.branchNote" to "%s %s (supported branch starts at %s)",
        "tech.src.server" to "Server header",
        "tech.src.powered" to "X-Powered-By header",
        "tech.src.cookie" to "Cookie name",
        "tech.src.link" to "Link header",
        "tech.src.header" to "%s header",
        "tech.linkWpJson" to "wp-json REST route",
        "tech.unrecognised" to "unrecognised product string",
        "tech.cdnInFront" to "%s in front of the origin",
        "tech.cmsGenerator" to "CMS generator",
        "tech.javaServlet" to "Java servlet container",
        "tech.present" to "present",

        // -------------------------------------------------------------- narration
        "narr.nothing" to "Nothing in the collected metadata contradicted anything else, and no " +
            "combination of observations formed a chain worth reporting. That is a statement " +
            "about these passive signals only — it is not a clean bill of health for the " +
            "application behind them.",
        "narr.opening" to "Examined %s over %s",
        "narr.stack" to ", which presents as %s",
        "narr.top" to "The thread most worth pulling: %s (%s, drawn from %d observations). ",
        "narr.multiHigh" to "%d separate chains reached a high-severity conclusion, which " +
            "usually points at one underlying cause rather than several. ",
        "narr.closing" to "Each conclusion below lists the clues behind it — check the " +
            "reasoning before acting on it.",
        "narr.protoHttp" to "HTTP",

        // ---------------------------------------------------------------- AI (Gemini)
        "ai.lang" to "English",
        "ai.prompt" to "You are a web-security assistant. In %s, explain this audit finding in " +
            "simple terms for a site owner: what it means, why it matters, and how to fix it. Be " +
            "concise (3–5 sentences), no markdown. Finding: \"%s\". Details: %s. Suggested fix: %s.",
        "ai.title" to "AI EXPLANATIONS (GEMINI)",
        "ai.key.hint" to "Paste your Gemini API key",
        "ai.model.hint" to "Model (auto = pick one automatically)",
        "ai.save" to "SAVE",
        "ai.saved" to "Key saved — an AI button now appears on each finding.",
        "ai.get" to "Get a free key at aistudio.google.com",
        "ai.explain" to "EXPLAIN (AI)",
        "ai.explainAll" to "EXPLAIN EVERYTHING (AI)",
        "ai.prompt.all" to "You are a web-security assistant. In %s, explain this whole audit of " +
            "%s (grade %s, score %d/100) to the site owner: summarise the main problems, why they " +
            "matter, and the top priorities to fix first. Plain language, no markdown, group " +
            "related issues. Findings:\n%s",
        "ai.explaining" to "Asking Gemini …",
        "ai.needkey" to "Add a Gemini key on the Audit tab to enable AI explanations."
    )
}
