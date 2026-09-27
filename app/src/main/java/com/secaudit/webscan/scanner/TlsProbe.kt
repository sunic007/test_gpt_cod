package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.TlsInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Determines which TLS protocol versions the target's listener will agree to.
 *
 * For each candidate version the probe opens a TCP connection, completes a TLS
 * handshake with exactly that version enabled, reads the negotiated parameters,
 * and closes the socket. No HTTP request is sent and no application data is
 * transmitted, so this observes the server's own advertised configuration only.
 * At most four short-lived connections are made.
 */
class TlsProbe {

    companion object {
        /** Ascending, so the last success is the strongest version on offer. */
        private val CANDIDATES = listOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        private val TIMEOUT_MS = TimeUnit.SECONDS.toMillis(8).toInt()

        private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        private val HOSTNAME = Regex(
            "^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"
        )

        /**
         * SNI carries a DNS name only. `SNIHostName` throws for an IP literal, a
         * trailing dot, or a label with an underscore, which would otherwise make
         * every handshake fail and mislabel a reachable host as refusing all TLS.
         * When this returns false the probe simply omits SNI and still connects.
         */
        internal fun isValidSniHost(host: String): Boolean {
            if (host.isBlank() || host.length > 253) return false
            if (host.contains(':')) return false          // IPv6 literal
            if (host.endsWith(".")) return false          // FQDN root, rejected by SNIHostName
            if (IPV4.matches(host)) return false          // IPv4 literal
            return HOSTNAME.matches(host)
        }

        /**
         * Whether [host] is covered by the certificate's SAN dNSName entries,
         * with single-label wildcard matching (`*.example.com` covers `a.example.com`
         * but not `example.com` or `a.b.example.com`).
         */
        internal fun hostMatchesSan(host: String, sans: List<String>): Boolean {
            val h = host.lowercase().trimEnd('.')
            return sans.any { raw ->
                val s = raw.lowercase().trimEnd('.')
                if (s.startsWith("*.")) {
                    val suffix = s.substring(1)             // ".example.com"
                    val dot = h.indexOf('.')
                    dot > 0 && h.substring(dot) == suffix
                } else {
                    s == h
                }
            }
        }
    }

    suspend fun probe(host: String, port: Int): TlsInfo = withContext(Dispatchers.IO) {
        val accepted = mutableListOf<String>()
        val rejected = mutableListOf<String>()
        val untestable = mutableListOf<String>()

        var bestVersion: String? = null
        var cipherSuite: String? = null
        var certificate: X509Certificate? = null
        var chainLength = 0
        var firstError: String? = null

        for (version in CANDIDATES) {
            try {
                val result = handshake(host, port, version)
                accepted += version
                bestVersion = version
                cipherSuite = result.cipherSuite
                result.certificate?.let { certificate = it }
                if (result.chainLength > 0) chainLength = result.chainLength
            } catch (e: UnsupportedVersionException) {
                untestable += version
            } catch (t: Throwable) {
                rejected += version
                if (firstError == null) firstError = t.message
            }
        }

        val cert = certificate
        val expiresAt = cert?.notAfter?.time
        val sanNames = cert?.let(::dnsAltNames).orEmpty()

        TlsInfo(
            accepted = accepted,
            rejected = rejected,
            untestable = untestable,
            bestVersion = bestVersion,
            cipherSuite = cipherSuite,
            certSubject = cert?.subjectX500Principal?.name?.let(::shortenDn),
            certIssuer = cert?.issuerX500Principal?.name?.let(::shortenDn),
            certExpiresEpochMs = expiresAt,
            certDaysRemaining = expiresAt?.let {
                TimeUnit.MILLISECONDS.toDays(it - System.currentTimeMillis())
            },
            certAltNames = sanNames.size,
            certSigAlg = cert?.sigAlgName,
            certKeyType = cert?.publicKey?.algorithm,
            certKeyBits = cert?.let(::keyBits) ?: 0,
            certChainLength = chainLength,
            certCoversHost = if (sanNames.isEmpty()) null else hostMatchesSan(host, sanNames),
            error = if (accepted.isEmpty()) firstError ?: "No TLS handshake succeeded." else null
        )
    }

    private fun dnsAltNames(cert: X509Certificate): List<String> = try {
        cert.subjectAlternativeNames.orEmpty()
            .filter { (it.getOrNull(0) as? Int) == 2 }          // 2 = dNSName
            .mapNotNull { it.getOrNull(1) as? String }
    } catch (t: Throwable) {
        emptyList()
    }

    private fun keyBits(cert: X509Certificate): Int = when (val key = cert.publicKey) {
        is RSAPublicKey -> key.modulus.bitLength()
        is ECPublicKey -> key.params.curve.field.fieldSize
        else -> 0
    }

    /** Raised when the device itself cannot speak a version, which is not a server verdict. */
    private class UnsupportedVersionException(version: String) :
        Exception("$version is unavailable on this device")

    private class HandshakeResult(
        val cipherSuite: String?,
        val certificate: X509Certificate?,
        val chainLength: Int
    )

    private fun handshake(host: String, port: Int, version: String): HandshakeResult {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        (factory.createSocket() as SSLSocket).use { socket ->
            if (version !in socket.supportedProtocols) throw UnsupportedVersionException(version)

            socket.soTimeout = TIMEOUT_MS
            socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
            socket.enabledProtocols = arrayOf(version)
            if (isValidSniHost(host)) {
                socket.sslParameters = socket.sslParameters.apply {
                    serverNames = listOf<SNIServerName>(SNIHostName(host))
                }
            }
            socket.startHandshake()

            val session = socket.session
            val chain = session.peerCertificates
            return HandshakeResult(
                cipherSuite = session.cipherSuite,
                certificate = chain.firstOrNull() as? X509Certificate,
                chainLength = chain.size
            )
        }
    }

    /** Distinguished names are long; keep the CN for display. */
    private fun shortenDn(dn: String): String =
        Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1)?.trim() ?: dn.take(80)
}
