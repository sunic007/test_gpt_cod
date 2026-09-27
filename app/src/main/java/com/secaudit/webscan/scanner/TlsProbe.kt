package com.secaudit.webscan.scanner

import com.secaudit.webscan.model.TlsInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.security.cert.X509Certificate
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

    private companion object {
        /** Ascending, so the last success is the strongest version on offer. */
        val CANDIDATES = listOf("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        val TIMEOUT_MS = TimeUnit.SECONDS.toMillis(8).toInt()
    }

    suspend fun probe(host: String, port: Int): TlsInfo = withContext(Dispatchers.IO) {
        val accepted = mutableListOf<String>()
        val rejected = mutableListOf<String>()
        val untestable = mutableListOf<String>()

        var bestVersion: String? = null
        var cipherSuite: String? = null
        var certificate: X509Certificate? = null
        var firstError: String? = null

        for (version in CANDIDATES) {
            try {
                val result = handshake(host, port, version)
                accepted += version
                bestVersion = version
                cipherSuite = result.cipherSuite
                result.certificate?.let { certificate = it }
            } catch (e: UnsupportedVersionException) {
                untestable += version
            } catch (t: Throwable) {
                rejected += version
                if (firstError == null) firstError = t.message
            }
        }

        val cert = certificate
        val expiresAt = cert?.notAfter?.time

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
            certAltNames = cert?.subjectAlternativeNames?.size ?: 0,
            error = if (accepted.isEmpty()) firstError ?: "No TLS handshake succeeded." else null
        )
    }

    /** Raised when the device itself cannot speak a version, which is not a server verdict. */
    private class UnsupportedVersionException(version: String) :
        Exception("$version is unavailable on this device")

    private class HandshakeResult(
        val cipherSuite: String?,
        val certificate: X509Certificate?
    )

    private fun handshake(host: String, port: Int, version: String): HandshakeResult {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        (factory.createSocket() as SSLSocket).use { socket ->
            if (version !in socket.supportedProtocols) throw UnsupportedVersionException(version)

            socket.soTimeout = TIMEOUT_MS
            socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
            socket.enabledProtocols = arrayOf(version)
            socket.sslParameters = socket.sslParameters.apply {
                serverNames = listOf<SNIServerName>(SNIHostName(host))
            }
            socket.startHandshake()

            val session = socket.session
            return HandshakeResult(
                cipherSuite = session.cipherSuite,
                certificate = session.peerCertificates.firstOrNull() as? X509Certificate
            )
        }
    }

    /** Distinguished names are long; keep the CN for display. */
    private fun shortenDn(dn: String): String =
        Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1)?.trim() ?: dn.take(80)
}
