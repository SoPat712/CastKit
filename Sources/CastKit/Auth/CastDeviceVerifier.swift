import Foundation
import Security

/// Authenticates Cast devices against the Cast device roots and a separately rooted, mandatory CRL.
public struct CastDeviceVerifier: CastDeviceAuthenticating {
    private let trustedRoots: [Data]
    private let crlRoot: Data
    private let crlCache: any CastCRLCache

    /// Creates a verifier. Injected anchors are useful for isolated tests; production uses the built-in roots.
    public init(
        trustedRoots: [Data] = CastTrustRoots.device,
        crlRoot: Data = CastTrustRoots.crl,
        crlCache: any CastCRLCache = InMemoryCastCRLCache()
    ) {
        self.trustedRoots = trustedRoots
        self.crlRoot = crlRoot
        self.crlCache = crlCache
    }

    /// Verifies a decoded response, in protocol order. Call on a connection worker, away from the main thread.
    /// The connection owns namespace, binary-payload and remote-error checks before calling this method.
    public func verify(_ response: CastAuthResponse, context: CastAuthContext) throws -> CastDeviceIdentity {
        guard !Thread.isMainThread else { throw CastAuthError.requiresBackgroundVerification }
        guard context.now.timeIntervalSince1970.isFinite else { throw CastAuthError.invalidVerificationTime }
        guard response.intermediateCertificates.count <= 16, trustedRoots.count <= 16,
              response.signature.count <= 16_384 else { throw CastAuthError.inputTooLarge }

        // The TLS certificate is only a signed binding: its issuer, key usage and name are irrelevant.
        let tlsDates: (Date, Date)
        do { tlsDates = try Self.tlsValidity(context.tlsCertificate) }
        catch { throw CastAuthError.malformedTLSCertificate }
        guard tlsDates.0 <= context.now else { throw CastAuthError.tlsCertificateNotYetValid }
        guard context.now <= tlsDates.1 else { throw CastAuthError.tlsCertificateExpired }
        guard tlsDates.1 <= context.now.addingTimeInterval(4 * 86_400) else {
            throw CastAuthError.tlsCertificateLifetimeTooLong
        }
        guard let nonce = response.senderNonce else { throw CastAuthError.missingNonce }
        guard nonce == context.sentNonce else { throw CastAuthError.nonceMismatch }
        guard nonce.count == 16 else { throw CastAuthError.invalidNonceLength }

        let leaf = try Self.parse(response.deviceCertificate, failure: .malformedDeviceCertificate)
        let intermediates = try response.intermediateCertificates.map {
            try Self.parse($0, failure: .malformedIntermediateCertificate)
        }
        let anchors = try trustedRoots.map { try Self.parse($0, failure: .malformedTrustedRoot) }
        let date = Self.validationDate(leaf: leaf, intermediates: intermediates, anchors: anchors, now: context.now)
        let path: [CastCertificate]
        do {
            path = try CastPathValidator(roots: anchors).build(leaf: leaf, intermediates: intermediates, date: date, device: true)
        } catch is CastDERError { throw CastAuthError.malformedCertificateExtension }

        let revocationRoot = try Self.parse(crlRoot, failure: .malformedTrustedRoot)
        let cachedBytes = crlCache.load()
        let deviceCRL = Self.crlResult(response.crl, root: revocationRoot, now: context.now)
        let cachedCRL = Self.crlResult(cachedBytes, root: revocationRoot, now: context.now)
        var usable: [CastCRL] = []
        if case .success(let crl) = deviceCRL { usable.append(crl) }
        if case .success(let crl) = cachedCRL { usable.append(crl) }
        if usable.isEmpty {
            if response.crl != nil, case .failure(let error) = deviceCRL { throw error }
            if cachedBytes != nil, case .failure(let error) = cachedCRL { throw error }
            throw CastAuthError.missingCRL
        }
        // Always check both usable sources before replacing the cache with a newer issuance.
        for crl in usable { try crl.check(path, now: context.now) }

        guard !response.signature.isEmpty else { throw CastAuthError.emptySignature }
        let algorithm: SecKeyAlgorithm = switch response.hashAlgorithm {
        case .sha1: .rsaSignatureMessagePKCS1v15SHA1
        case .sha256: .rsaSignatureMessagePKCS1v15SHA256
        }
        // Like Chromium, the wire signature_algorithm does not select a different signature scheme.
        guard SecKeyVerifySignature(
            leaf.publicKey, algorithm, (nonce + context.tlsCertificate) as CFData, response.signature as CFData, nil
        ) else { throw CastAuthError.invalidSignature }

        let isAudioOnly = try path.contains { try $0.policies()?.contains("1.3.6.1.4.1.11129.2.5.2") == true }
        guard !isAudioOnly || !context.advertisesVideoOutput else { throw CastAuthError.audioOnlyDeviceAdvertisesVideo }
        if let freshest = usable.max(by: { $0.notBefore < $1.notBefore }) {
            crlCache.store(freshest.bundle, issuedAt: freshest.notBefore)
        }
        guard let commonName = leaf.commonName else { throw CastAuthError.missingCommonName }
        return CastDeviceIdentity(commonName: commonName, isAudioOnly: isAudioOnly)
    }

    private static func parse(_ der: Data, failure: CastAuthError) throws -> CastCertificate {
        do { return try CastCertificate(der) }
        catch let error as CastAuthError { throw error }
        catch { throw failure }
    }

    private static func crlResult(_ bytes: Data?, root: CastCertificate, now: Date) -> Result<CastCRL, CastAuthError> {
        guard let bytes else { return .failure(.missingCRL) }
        do { return .success(try CastCRL.verify(bytes, root: root, now: now)) }
        catch let error as CastAuthError { return .failure(error) }
        catch { return .failure(.malformedCRL) }
    }

    private static func validationDate(
        leaf: CastCertificate, intermediates: [CastCertificate], anchors: [CastCertificate], now: Date
    ) -> Date {
        let sent = ([leaf] + intermediates).filter { certificate in !anchors.contains { $0.der == certificate.der } }
        guard let earliest = sent.map(\.notAfter).min(),
              let shortest = sent.map({ $0.notAfter.timeIntervalSince($0.notBefore) }).min(),
              earliest <= now, now <= leaf.notAfter.addingTimeInterval(15 * 365 * 86_400),
              shortest > 5 * 365 * 86_400 else { return now }
        return earliest.addingTimeInterval(-7 * 86_400)
    }

    private static func tlsValidity(_ der: Data) throws -> (Date, Date) {
        let certificate = try CastDER.parse(der)
        try certificate.require(0x30, count: 3)
        let body = certificate.children[0]
        try body.require(0x30)
        let index = body.children.first?.tag == 0xa0 ? 4 : 3
        guard body.children.count > index else { throw CastDERError.malformed }
        let validity = body.children[index]
        try validity.require(0x30, count: 2)
        let before = try validity.children[0].date, after = try validity.children[1].date
        guard before <= after else { throw CastDERError.malformed }
        return (before, after)
    }
}
