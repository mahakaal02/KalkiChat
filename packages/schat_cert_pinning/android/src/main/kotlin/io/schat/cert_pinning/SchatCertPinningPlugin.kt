package io.schat.cert_pinning

import android.os.Handler
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import android.util.Base64

/**
 * Walks the TLS chain on connection and checks every cert's
 * SubjectPublicKeyInfo SHA-256 against the supplied pin list. Pass on
 * any-match. Unlike http_certificate_pinning (which only checks
 * serverCertificates[0] / the leaf), this lets the app pin to a
 * long-lived intermediate (e.g. Let's Encrypt R13) so leaf rotations
 * don't break the APK every 90 days.
 *
 * Threading: the synchronous network call runs on a background executor
 * and the Flutter result is posted back on the main looper, same
 * pattern http_certificate_pinning uses.
 */
class SchatCertPinningPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "io.schat/cert_pinning")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        if (call.method != "check") {
            result.notImplemented(); return
        }
        @Suppress("UNCHECKED_CAST")
        val url = call.argument<String>("url") ?: ""
        @Suppress("UNCHECKED_CAST")
        val pins = call.argument<List<String>>("pins") ?: emptyList()
        val timeoutSeconds = call.argument<Int>("timeoutSeconds") ?: 10

        executor.execute {
            try {
                val chainPins = chainSpkiSha256Base64(url, timeoutSeconds * 1000)
                val ok = chainPins.any { it in pins.toSet() }
                if (ok) {
                    mainHandler.post { result.success(null) }
                } else {
                    mainHandler.post {
                        result.error(
                            "PIN_MISMATCH",
                            "No cert in the TLS chain matched an allowed pin.",
                            "chainSpkiPins=${chainPins.joinToString(",")}; allowed=${pins.joinToString(",")}",
                        )
                    }
                }
            } catch (e: UnknownHostException) {
                mainHandler.post {
                    result.error("NO_INTERNET", "DNS lookup failed", e.localizedMessage)
                }
            } catch (e: SocketTimeoutException) {
                mainHandler.post {
                    result.error("NO_INTERNET", "Handshake timeout", e.localizedMessage)
                }
            } catch (e: SecurityException) {
                // App is missing android.permission.INTERNET. Distinct from a
                // real cert / chain failure — surface it cleanly so the Dart
                // side can give the user something actionable instead of the
                // misleading "bad certificate" wrapping.
                mainHandler.post {
                    result.error(
                        "NO_INTERNET_PERMISSION",
                        "App lacks android.permission.INTERNET",
                        e.localizedMessage,
                    )
                }
            } catch (e: SocketException) {
                // EACCES from a missing INTERNET permission can also surface as
                // a SocketException("Permission denied") depending on Android
                // version; classify it by message rather than miscategorising
                // as a handshake failure.
                if (e.localizedMessage?.contains("Permission denied", ignoreCase = true) == true) {
                    mainHandler.post {
                        result.error(
                            "NO_INTERNET_PERMISSION",
                            "App lacks android.permission.INTERNET",
                            e.localizedMessage,
                        )
                    }
                } else {
                    mainHandler.post {
                        result.error("HANDSHAKE_FAILED", e.javaClass.simpleName, e.localizedMessage)
                    }
                }
            } catch (e: SSLException) {
                // Genuine TLS / chain problem — separate bucket so the message
                // points at TLS rather than "the socket couldn't open".
                mainHandler.post {
                    result.error("TLS_ERROR", e.javaClass.simpleName, e.localizedMessage)
                }
            } catch (e: Throwable) {
                mainHandler.post {
                    result.error("HANDSHAKE_FAILED", e.javaClass.simpleName, e.localizedMessage)
                }
            }
        }
    }

    /**
     * Opens an HTTPS connection to [httpsURL], lets the JDK perform the
     * full handshake + chain validation against the system trust store,
     * then returns the SHA-256(SubjectPublicKeyInfo) of every cert in
     * the resulting chain — base64-encoded.
     *
     * SubjectPublicKeyInfo is exactly what X509Certificate.getPublicKey
     * ().getEncoded() returns (DER-encoded SPKI per RFC 5280).
     */
    private fun chainSpkiSha256Base64(httpsURL: String, connectTimeoutMs: Int): List<String> {
        val url = URL(httpsURL)
        val conn = url.openConnection() as HttpsURLConnection
        conn.connectTimeout = connectTimeoutMs
        conn.readTimeout = connectTimeoutMs
        // HEAD instead of GET — we don't care about the body, just the
        // TLS handshake. Cuts both bandwidth and latency.
        conn.requestMethod = "HEAD"
        try {
            conn.connect()
            val chain: Array<Certificate> = conn.serverCertificates
            val md = MessageDigest.getInstance("SHA-256")
            return chain.map { cert ->
                val spkiDer = (cert as X509Certificate).publicKey.encoded
                val digest = md.digest(spkiDer)
                md.reset()
                Base64.encodeToString(digest, Base64.NO_WRAP)
            }
        } finally {
            try { conn.disconnect() } catch (_: Throwable) {}
        }
    }
}
