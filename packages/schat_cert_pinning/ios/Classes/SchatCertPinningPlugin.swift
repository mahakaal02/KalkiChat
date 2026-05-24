import Flutter
import Foundation
import CommonCrypto

// MARK: - Plugin entry-point
//
// Walks the TLS chain on connection and checks every cert's
// SubjectPublicKeyInfo SHA-256 against the supplied pin list. Pass on
// any-match. Counterpart to the Android plugin in
// android/src/main/kotlin/io/schat/cert_pinning/SchatCertPinningPlugin.kt
// — same MethodChannel, same error codes, same threading model.
public class SchatCertPinningPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "io.schat/cert_pinning",
            binaryMessenger: registrar.messenger())
        let instance = SchatCertPinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard call.method == "check" else { result(FlutterMethodNotImplemented); return }
        guard let args = call.arguments as? [String: Any],
              let urlStr = args["url"] as? String,
              let pins = args["pins"] as? [String] else {
            result(FlutterError(code: "ARGS", message: "Bad arguments", details: nil))
            return
        }
        let timeoutSeconds = (args["timeoutSeconds"] as? Int) ?? 10

        guard let url = URL(string: urlStr) else {
            result(FlutterError(code: "ARGS", message: "Bad URL", details: nil))
            return
        }

        // Spin a transient URLSession with our delegate so we get the
        // SecTrust chain at challenge time.
        let delegate = ChainCaptureDelegate(allowedPins: Set(pins))
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = TimeInterval(timeoutSeconds)
        cfg.timeoutIntervalForResource = TimeInterval(timeoutSeconds)
        let session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)

        var req = URLRequest(url: url)
        // HEAD — we only care about the handshake, not the body.
        req.httpMethod = "HEAD"

        let task = session.dataTask(with: req) { _, _, err in
            DispatchQueue.main.async {
                if delegate.pinPassed {
                    result(nil)
                    return
                }
                // Pin failure overrides any other error so the caller
                // gets a deterministic message.
                if !delegate.chainSpkiPins.isEmpty {
                    result(FlutterError(
                        code: "PIN_MISMATCH",
                        message: "No cert in the TLS chain matched an allowed pin.",
                        details: "chainSpkiPins=\(delegate.chainSpkiPins.joined(separator: ",")); allowed=\(pins.joined(separator: ","))"))
                    return
                }
                if let nserr = err as NSError? {
                    if nserr.domain == NSURLErrorDomain {
                        switch nserr.code {
                        case NSURLErrorTimedOut, NSURLErrorCannotConnectToHost,
                             NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed,
                             NSURLErrorNotConnectedToInternet:
                            result(FlutterError(code: "NO_INTERNET",
                                                message: nserr.localizedDescription,
                                                details: "\(nserr.code)"))
                            return
                        default: break
                        }
                    }
                    result(FlutterError(code: "HANDSHAKE_FAILED",
                                        message: nserr.localizedDescription,
                                        details: "\(nserr.code)"))
                } else {
                    result(FlutterError(code: "HANDSHAKE_FAILED",
                                        message: "Unknown error",
                                        details: nil))
                }
            }
        }
        task.resume()
    }
}

// MARK: - Delegate

/// Captures the SecTrust chain at challenge time, hashes each cert's
/// SubjectPublicKeyInfo SHA-256, accepts the handshake iff any matches
/// an allowed pin.
private final class ChainCaptureDelegate: NSObject, URLSessionDelegate {
    let allowedPins: Set<String>
    var chainSpkiPins: [String] = []
    var pinPassed = false

    init(allowedPins: Set<String>) { self.allowedPins = allowedPins }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                  URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }

        // Let the system validate the chain against trust anchors first
        // — we don't want to second-guess root CAs.
        var trustErr: CFError?
        let systemValid = SecTrustEvaluateWithError(trust, &trustErr)
        if !systemValid {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }

        // Walk the chain. SecTrustGetCertificateAtIndex returns the leaf
        // at 0 and works up; SecTrustCopyCertificateChain (iOS 15+) is
        // preferred but we support 12+ so fall back.
        let count = SecTrustGetCertificateCount(trust)
        for i in 0..<count {
            guard let cert = SecTrustGetCertificateAtIndex(trust, i) else { continue }
            guard let pin = spkiSha256Base64(cert: cert) else { continue }
            chainSpkiPins.append(pin)
            if allowedPins.contains(pin) { pinPassed = true }
        }

        if pinPassed {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// SHA-256 of the cert's DER-encoded SubjectPublicKeyInfo, base64.
    /// Uses SecCertificateCopyKey + SecKeyCopyExternalRepresentation
    /// then wraps the raw key into a proper SPKI structure via
    /// SecKeyCopyAttributes — but for SPKI-fingerprint compatibility
    /// we need the FULL ASN.1 SubjectPublicKeyInfo, not just the raw key
    /// bytes. The reliable way: extract from the cert via
    /// SecCertificateCopyData and parse out the SPKI substring.
    ///
    /// Simpler alternative used here: compute via SecTrust's copy-data
    /// + a minimal ASN.1 walk to locate the SPKI bytes. The format
    /// matches what `openssl x509 -pubkey -noout | openssl pkey -pubin
    /// -outform DER | openssl dgst -sha256 -binary | base64` produces.
    private func spkiSha256Base64(cert: SecCertificate) -> String? {
        let certData = SecCertificateCopyData(cert) as Data
        guard let spki = extractSubjectPublicKeyInfo(fromCertDer: certData) else {
            return nil
        }
        return sha256(spki).base64EncodedString()
    }

    /// Parse a DER-encoded X.509 Certificate and return the bytes of
    /// the SubjectPublicKeyInfo sub-structure. This is the canonical
    /// SPKI representation per RFC 5280 §4.1.2.7.
    ///
    /// X.509 cert is `SEQUENCE { tbsCertificate, signatureAlgorithm,
    /// signatureValue }`. tbsCertificate is `SEQUENCE { version, serial,
    /// signature, issuer, validity, subject, subjectPublicKeyInfo, ... }`.
    /// We walk into tbs and pick out the 7th element (or 6th if the
    /// optional version is absent — but it's effectively always present
    /// in modern certs).
    private func extractSubjectPublicKeyInfo(fromCertDer data: Data) -> Data? {
        var p = 0
        // Outer SEQUENCE (Certificate)
        guard data.count > 4, data[p] == 0x30 else { return nil }
        let (outerLen, outerLenSize) = readDerLength(data, at: p + 1) ?? (0, 0)
        if outerLen == 0 { return nil }
        p += 1 + outerLenSize
        // Inner SEQUENCE (tbsCertificate)
        guard p < data.count, data[p] == 0x30 else { return nil }
        let (_, tbsLenSize) = readDerLength(data, at: p + 1) ?? (0, 0)
        p += 1 + tbsLenSize
        // Now positioned at the first element of tbsCertificate.
        // version is `[0] EXPLICIT INTEGER` — tag 0xA0. If present, skip.
        if p < data.count && data[p] == 0xA0 {
            let (vl, vls) = readDerLength(data, at: p + 1) ?? (0, 0)
            p += 1 + vls + vl
        }
        // Skip serial (INTEGER 0x02), signature alg (SEQUENCE), issuer
        // (SEQUENCE), validity (SEQUENCE), subject (SEQUENCE). Five
        // elements. Then we're at SubjectPublicKeyInfo.
        for _ in 0..<5 {
            guard p < data.count else { return nil }
            let (l, ls) = readDerLength(data, at: p + 1) ?? (0, 0)
            p += 1 + ls + l
        }
        // SPKI is a SEQUENCE here. Capture from `p` to `p + 1 + ls + l`.
        guard p < data.count, data[p] == 0x30 else { return nil }
        let (spkiLen, spkiLenSize) = readDerLength(data, at: p + 1) ?? (0, 0)
        let totalLen = 1 + spkiLenSize + spkiLen
        guard p + totalLen <= data.count else { return nil }
        return data.subdata(in: p..<(p + totalLen))
    }

    /// Read a DER length octet at `offset`. Returns (value, lengthOf-
    /// LengthEncoding) — i.e. how many bytes the length field itself
    /// consumed (1 for short-form, 2-5 for long-form).
    private func readDerLength(_ data: Data, at offset: Int) -> (Int, Int)? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        if first < 0x80 { return (Int(first), 1) }
        let count = Int(first & 0x7F)
        guard count > 0 && count <= 4, offset + 1 + count <= data.count else { return nil }
        var v = 0
        for i in 0..<count { v = (v << 8) | Int(data[offset + 1 + i]) }
        return (v, 1 + count)
    }

    private func sha256(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buf in
            _ = CC_SHA256(buf.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }
}
