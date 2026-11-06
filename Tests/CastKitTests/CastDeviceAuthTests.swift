import CastKit
import CryptoKit
import Foundation
import Security
import Testing

private struct CastDeviceAuthTests {
    @Test func verifiesNonceThenExactTLSCertificateDER() throws {
        let fixture = try CastAuthFixture()
        let identity = try fixture.verifier().verify(fixture.response(), context: fixture.context())
        #expect(identity == CastDeviceIdentity(commonName: "Cast test device", isAudioOnly: false))
    }

    @Test func rejectsWrongEchoedNonceEvenWhenItsSignatureIsValid() throws {
        let fixture = try CastAuthFixture()
        let response = try fixture.response(nonce: Data(repeating: 0xff, count: 16))
        expectAuthFailure(.nonceMismatch) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func rejectsMissingNonceEvenWhenTLSOnlySignatureIsValid() throws {
        let fixture = try CastAuthFixture()
        let response = try fixture.response(nonce: nil)
        expectAuthFailure(.missingNonce) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func rejectsTLSCertificateThenNonceSignatureOrder() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.signature = try fixture.sign(fixture.tls.der + fixture.nonce)
        expectAuthFailure(.invalidSignature) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func rejectsTamperedAuthenticationSignature() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.signature[0] ^= 1
        expectAuthFailure(.invalidSignature) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func authenticationSignatureBindsExactTLSBytes() throws {
        let fixture = try CastAuthFixture()
        let response = try fixture.response()
        let replacement = try fixture.tlsCertificate(serial: 999)
        var context = fixture.context()
        context.tlsCertificate = replacement.der
        expectAuthFailure(.invalidSignature) { try fixture.verifier().verify(response, context: context) }
    }

    @Test func rejectsDeviceChainWithoutConfiguredAnchor() throws {
        let fixture = try CastAuthFixture()
        let verifier = CastDeviceVerifier(trustedRoots: [], crlRoot: fixture.crlRoot.der)
        expectAuthFailure(.untrustedDeviceChain) { try verifier.verify(fixture.response(), context: fixture.context()) }
    }

    @Test func keepsDeviceAndCRLTrustStoresSeparate() throws {
        let fixture = try CastAuthFixture()
        let verifier = CastDeviceVerifier(trustedRoots: [fixture.crlRoot.der], crlRoot: fixture.root.der)
        expectAuthFailure(.untrustedDeviceChain) { try verifier.verify(fixture.response(), context: fixture.context()) }
        let wrongCRLRoot = CastDeviceVerifier(trustedRoots: [fixture.root.der], crlRoot: fixture.root.der)
        expectAuthFailure(.untrustedCRLSigner) { try wrongCRLRoot.verify(fixture.response(), context: fixture.context()) }
    }

    @Test(arguments: CastTLSWindowFailure.allCases)
    func rejectsTLSCertificateOutsideItsRequiredWindow(_ failure: CastTLSWindowFailure) throws {
        let fixture = try CastAuthFixture()
        let bounds: (TimeInterval, TimeInterval)
        let expected: CastAuthError
        switch failure {
        case .notYetValid:
            bounds = (60, CastAuthFixture.day)
            expected = .tlsCertificateNotYetValid
        case .expired:
            bounds = (-CastAuthFixture.day, -60)
            expected = .tlsCertificateExpired
        case .moreThanFourDaysRemaining:
            bounds = (-60, 4 * CastAuthFixture.day + 1)
            expected = .tlsCertificateLifetimeTooLong
        }
        let tls = try fixture.tlsCertificate(notBefore: bounds.0, notAfter: bounds.1)
        let response = try fixture.response(tls: tls.der)
        var context = fixture.context()
        context.tlsCertificate = tls.der
        expectAuthFailure(expected) { try fixture.verifier().verify(response, context: context) }
    }

    @Test func rejectsExpiredShortLifetimeDeviceCertificate() throws {
        let fixture = try CastAuthFixture(deviceNotBefore: -365 * CastAuthFixture.day, deviceNotAfter: -1)
        expectAuthFailure(.certificateExpired) { try fixture.verifier().verify(fixture.response(), context: fixture.context()) }
    }

    @Test func longLivedChainExpiredMoreThanSevenDaysAgoUsesGraceTime() throws {
        let fixture = try CastAuthFixture(
            deviceNotBefore: -10 * CastAuthFixture.year, deviceNotAfter: -30 * CastAuthFixture.day
        )
        let identity = try fixture.verifier().verify(fixture.response(), context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func rejectsExpiredLongLivedChainBeyondFifteenYearGraceLimit() throws {
        let fixture = try CastAuthFixture(
            deviceNotBefore: -25 * CastAuthFixture.year, deviceNotAfter: -16 * CastAuthFixture.year
        )
        expectAuthFailure(.certificateExpired) { try fixture.verifier().verify(fixture.response(), context: fixture.context()) }
    }

    @Test func unusedShortLivedIntermediateDisablesExpiryGrace() throws {
        let fixture = try CastAuthFixture(
            deviceNotBefore: -10 * CastAuthFixture.year, deviceNotAfter: -30 * CastAuthFixture.day
        )
        var response = try fixture.response()
        response.intermediateCertificates.append(try fixture.expiredAlternativeIssuer().der)
        expectAuthFailure(.certificateExpired) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func acceptsLegacySHA1AuthenticationSignature() throws {
        let fixture = try CastAuthFixture()
        let identity = try fixture.verifier().verify(fixture.response(hash: .sha1), context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func wireSignatureAlgorithmDoesNotSelectPSS() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.signatureAlgorithm = .rsassaPSS
        let identity = try fixture.verifier().verify(response, context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test(arguments: [TimeInterval(-60), 60])
    func anchorValidityDoesNotLimitDevicePath(_ boundary: TimeInterval) throws {
        let fixture = try CastAuthFixture(
            rootNotBefore: boundary > 0 ? boundary : -CastAuthFixture.year,
            rootNotAfter: boundary < 0 ? boundary : CastAuthFixture.year
        )
        let identity = try fixture.verifier().verify(fixture.response(), context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test(arguments: CastLeafConstraintFailure.allCases)
    func enforcesDeviceCertificateConstraints(_ failure: CastLeafConstraintFailure) throws {
        let fixture = try CastAuthFixture(leafConstraintFailure: failure)
        expectAuthFailure(failure.expected) { try fixture.verifier().verify(fixture.response(), context: fixture.context()) }
    }

    @Test func enforcesAnchorPathLengthConstraint() throws {
        let fixture = try CastAuthFixture(rootPathLength: 0)
        expectAuthFailure(.pathLengthExceeded) { try fixture.verifier().verify(fixture.response(), context: fixture.context()) }
    }

    @Test func acceptsIntermediateWithoutKeyUsage() throws {
        let fixture = try CastAuthFixture(omitIssuerKeyUsage: true)
        let identity = try fixture.verifier().verify(fixture.response(), context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func productionRootFingerprintsMatchReference() {
        let fingerprints = (CastTrustRoots.device + [CastTrustRoots.crl]).map {
            SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined()
        }
        #expect(fingerprints == [
            "809af14700b3fe2611ad597eb1584d6354313b64ccdb3390f097fa3e5826d6ca",
            "caf6d1e37b532203e01a76bf07187bb731ccd38801565ab2211a2c0ab7f3bc46",
            "8b77c60291f9d62764613083f49750b1c5caac2d9efbe5a28edf301f9d84831d",
        ])
    }

    @Test func buildsPathFromUnorderedIntermediates() throws {
        let fixture = try CastAuthFixture(twoIntermediates: true)
        let response = try fixture.response()
        #expect(response.intermediateCertificates.count == 2)
        let identity = try fixture.verifier().verify(response, context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func triesValidAlternativeAfterSameKeyIntermediateFailsValidity() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.intermediateCertificates.insert(try fixture.expiredAlternativeIssuer().der, at: 0)
        let identity = try fixture.verifier().verify(response, context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test(arguments: CastAuthFixture.LeafKeyKind.rejectedKinds)
    func rejectsUnsupportedAuthenticationPublicKeys(_ keyKind: CastAuthFixture.LeafKeyKind) throws {
        let fixture = try CastAuthFixture(leafKeyKind: keyKind)
        let expected: CastAuthError = keyKind == .ec256 ? .nonRSADeviceKey : .insufficientRSAKeySize
        expectAuthFailure(expected) { try fixture.verifier().verify(fixture.response(), context: fixture.context()) }
    }

    @Test func rejectsMissingCRLWithoutCachedFallback() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.crl = nil
        expectAuthFailure(.missingCRL) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func rejectsExpiredCRLEvenWhenDeviceChainUsesExpiryGrace() throws {
        let fixture = try CastAuthFixture(
            deviceNotBefore: -10 * CastAuthFixture.year, deviceNotAfter: -30 * CastAuthFixture.day
        )
        var response = try fixture.response()
        response.crl = try fixture.crl(notBefore: -8 * CastAuthFixture.day, notAfter: -1)
        expectAuthFailure(.crlExpired) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func rejectsRevokedDeviceSerialAtInclusiveRangeBoundary() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.crl = try fixture.crl(revokedSerial: fixture.leaf.serial)
        expectAuthFailure(.revokedSerialNumber) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test(arguments: CastRevokedPathCertificate.allCases)
    func rejectsRevokedSPKIAnywhereInValidatedPath(_ certificate: CastRevokedPathCertificate) throws {
        let fixture = try CastAuthFixture()
        let spki: Data
        switch certificate {
        case .leaf: spki = fixture.leaf.spki
        case .intermediate: spki = fixture.issuer.spki
        case .anchor: spki = fixture.root.spki
        }
        var response = try fixture.response()
        response.crl = try fixture.crl(revokedSPKI: spki)
        expectAuthFailure(.revokedPublicKey) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test(arguments: CastAudioPolicyLocation.allCases)
    func audioOnlyPolicyIsReturnedAndCannotAdvertiseVideoOutput(_ location: CastAudioPolicyLocation) throws {
        let fixture = try CastAuthFixture(audioOnlyLocation: location)
        let response = try fixture.response()
        let identity = try fixture.verifier().verify(response, context: fixture.context())
        #expect(identity.isAudioOnly)
        expectAuthFailure(.audioOnlyDeviceAdvertisesVideo) {
            try fixture.verifier().verify(response, context: fixture.context(video: true))
        }
    }

    @Test(arguments: CastMissingDeviceCRL.allCases)
    func validCachedCRLFillsInForUnusableDeviceCRL(_ condition: CastMissingDeviceCRL) throws {
        let fixture = try CastAuthFixture()
        let cache = InMemoryCastCRLCache()
        let fallback = try fixture.crl()
        cache.store(fallback, issuedAt: fixture.now.addingTimeInterval(-60))
        var response = try fixture.response()
        switch condition {
        case .missing: response.crl = nil
        case .malformed: response.crl = Data([0xff])
        case .expired: response.crl = try fixture.crl(notBefore: -100, notAfter: -1)
        }
        let identity = try fixture.verifier(cache: cache).verify(response, context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func validatesDeviceAndCachedCRLsBeforeReplacingCache() throws {
        let fixture = try CastAuthFixture()
        let cache = InMemoryCastCRLCache()
        let revokedFallback = try fixture.crl(revokedSerial: fixture.leaf.serial)
        cache.store(revokedFallback, issuedAt: fixture.now.addingTimeInterval(-120))
        let response = try fixture.response()
        expectAuthFailure(.revokedSerialNumber) { try fixture.verifier(cache: cache).verify(response, context: fixture.context()) }
    }

    @Test func cachedCleanCRLDoesNotOverrideDeviceRevocation() throws {
        let fixture = try CastAuthFixture()
        let cache = InMemoryCastCRLCache()
        cache.store(try fixture.crl(), issuedAt: fixture.now.addingTimeInterval(-60))
        var response = try fixture.response()
        response.crl = try fixture.crl(revokedSerial: fixture.leaf.serial)
        expectAuthFailure(.revokedSerialNumber) { try fixture.verifier(cache: cache).verify(response, context: fixture.context()) }
    }

    @Test func expiredCachedCRLCannotReplaceMissingDeviceCRL() throws {
        let fixture = try CastAuthFixture()
        let cache = InMemoryCastCRLCache()
        cache.store(try fixture.crl(notBefore: -100, notAfter: -1), issuedAt: fixture.now.addingTimeInterval(-100))
        var response = try fixture.response()
        response.crl = nil
        expectAuthFailure(.crlExpired) { try fixture.verifier(cache: cache).verify(response, context: fixture.context()) }
    }

    @Test(arguments: CastSkippedCRLEntry.allCases)
    func skipsUnparseableAndUnsupportedCRLEntriesBeforeFirstVersionZero(_ skipped: CastSkippedCRLEntry) throws {
        let fixture = try CastAuthFixture()
        let skippedBundle = try fixture.crl(version: skipped == .unsupportedVersion ? 1 : 0, malformedTBS: skipped == .malformed)
        var response = try fixture.response()
        response.crl = skippedBundle + (try fixture.crl())
        let identity = try fixture.verifier().verify(response, context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func firstVersionZeroCRLFailureCannotBeHiddenByLaterValidEntry() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.crl = try fixture.crl(tamperSignature: true) + fixture.crl()
        expectAuthFailure(.invalidCRLSignature) { try fixture.verifier().verify(response, context: fixture.context()) }
    }

    @Test func usesOnlyFirstVersionZeroEntryWithinOneCRLBundle() throws {
        let fixture = try CastAuthFixture()
        var response = try fixture.response()
        response.crl = try fixture.crl() + fixture.crl(revokedSerial: fixture.leaf.serial)
        let identity = try fixture.verifier().verify(response, context: fixture.context())
        #expect(identity.commonName == "Cast test device")
    }

    @Test func cacheKeepsTheNewestSignedBundle() {
        let cache = InMemoryCastCRLCache()
        let old = Data([1])
        let fresh = Data([2])
        cache.store(fresh, issuedAt: Date(timeIntervalSince1970: 200))
        cache.store(old, issuedAt: Date(timeIntervalSince1970: 100))
        #expect(cache.load() == fresh)
    }

    private func expectAuthFailure(_ expected: CastAuthError, _ operation: () throws -> CastDeviceIdentity) {
        do {
            _ = try operation()
            Issue.record("Device authentication unexpectedly succeeded")
        } catch {
            #expect((error as? CastAuthError) == expected)
        }
    }
}

private enum CastTLSWindowFailure: CaseIterable, Sendable {
    case notYetValid, expired, moreThanFourDaysRemaining
}

private enum CastRevokedPathCertificate: CaseIterable, Sendable { case leaf, intermediate, anchor }
private enum CastMissingDeviceCRL: CaseIterable, Sendable { case missing, malformed, expired }
private enum CastSkippedCRLEntry: CaseIterable, Sendable, Equatable { case malformed, unsupportedVersion }
private enum CastAudioPolicyLocation: CaseIterable, Sendable, Equatable { case leaf, intermediate, anchor }

private enum CastLeafConstraintFailure: CaseIterable, Sendable, Equatable {
    case missingKeyUsage, wrongKeyUsage, missingCommonName, wrongEKU, unknownCriticalExtension

    var expected: CastAuthError {
        switch self {
        case .missingKeyUsage, .wrongKeyUsage: .missingDigitalSignatureKeyUsage
        case .missingCommonName: .missingCommonName
        case .wrongEKU: .invalidExtendedKeyUsage
        case .unknownCriticalExtension: .unsupportedCriticalExtension
        }
    }
}

/// Builds independent device and CRL hierarchies in memory. The DER and protobuf writers below are
/// deliberately local to these fixtures, so the verifier never supplies its own expected input.
private final class CastAuthFixture {
    static let day: TimeInterval = 86_400
    static let year = 365 * day

    enum LeafKeyKind: Sendable, Equatable {
        case rsa2048, rsa1024, ec256
        static let rejectedKinds: [Self] = [.rsa1024, .ec256]
    }

    struct Certificate {
        let der: Data
        let spki: Data
        let serial: UInt64
        let name: String
        let key: SecKey
    }

    let now = Date(timeIntervalSince1970: 1_793_923_200)
    let nonce = Data(0..<16)
    let root: Certificate
    let issuer: Certificate
    let leaf: Certificate
    let crlRoot: Certificate
    let crlSigner: Certificate
    let tls: Certificate
    private let upperIssuer: Certificate?
    private let leafKeyKind: LeafKeyKind

    init(
        leafKeyKind: LeafKeyKind = .rsa2048,
        deviceNotBefore: TimeInterval = -CastAuthFixture.year,
        deviceNotAfter: TimeInterval = CastAuthFixture.year,
        audioOnly: Bool = false,
        twoIntermediates: Bool = false,
        rootNotBefore: TimeInterval = -30 * CastAuthFixture.year,
        rootNotAfter: TimeInterval = 30 * CastAuthFixture.year,
        rootPathLength: UInt64 = 2,
        omitIssuerKeyUsage: Bool = false,
        leafConstraintFailure: CastLeafConstraintFailure? = nil,
        audioOnlyLocation: CastAudioPolicyLocation? = nil
    ) throws {
        self.leafKeyKind = leafKeyKind
        let now = Date(timeIntervalSince1970: 1_793_923_200)
        let rootKey = try Self.key(role: "root")
        root = try Self.certificate(
            name: "Device test root", key: rootKey, issuerName: "Device test root", issuerKey: rootKey,
            serial: 1, before: now.addingTimeInterval(rootNotBefore), after: now.addingTimeInterval(rootNotAfter),
            caPathLength: rootPathLength, audioOnly: audioOnlyLocation == .anchor
        )
        let parent: Certificate
        if twoIntermediates {
            let upper = try Self.certificate(
                name: "Upper device issuer", key: Self.key(role: "upper"), issuerName: root.name, issuerKey: root.key,
                serial: 2, before: now.addingTimeInterval(deviceNotBefore), after: now.addingTimeInterval(deviceNotAfter),
                caPathLength: 1
            )
            upperIssuer = upper
            parent = upper
        } else {
            upperIssuer = nil
            parent = root
        }
        issuer = try Self.certificate(
            name: "Device test issuer", key: Self.key(role: "issuer"), issuerName: parent.name, issuerKey: parent.key,
            serial: 3, before: now.addingTimeInterval(deviceNotBefore), after: now.addingTimeInterval(deviceNotAfter),
            caPathLength: 0, audioOnly: audioOnlyLocation == .intermediate, omitKeyUsage: omitIssuerKeyUsage
        )
        leaf = try Self.certificate(
            name: "Cast test device", key: Self.key(leafKeyKind, role: "leaf"), issuerName: issuer.name, issuerKey: issuer.key,
            serial: 42, before: now.addingTimeInterval(deviceNotBefore), after: now.addingTimeInterval(deviceNotAfter),
            caPathLength: nil, audioOnly: audioOnly || audioOnlyLocation == .leaf, keyKind: leafKeyKind,
            omitKeyUsage: leafConstraintFailure == .missingKeyUsage,
            leafConstraintFailure: leafConstraintFailure
        )
        let crlRootKey = try Self.key(role: "crlRoot")
        crlRoot = try Self.certificate(
            name: "CRL test root", key: crlRootKey, issuerName: "CRL test root", issuerKey: crlRootKey,
            serial: 50, before: now.addingTimeInterval(-Self.year), after: now.addingTimeInterval(Self.year),
            caPathLength: 1
        )
        crlSigner = try Self.certificate(
            name: "CRL test signer", key: Self.key(role: "crlSigner"), issuerName: crlRoot.name, issuerKey: crlRoot.key,
            serial: 51, before: now.addingTimeInterval(-Self.day), after: now.addingTimeInterval(30 * Self.day),
            caPathLength: nil
        )
        tls = try Self.certificate(
            name: "TLS test device", key: root.key, issuerName: "TLS test device", issuerKey: root.key,
            serial: 100, before: now.addingTimeInterval(-Self.day), after: now.addingTimeInterval(Self.day),
            caPathLength: nil
        )
    }

    func verifier(cache: any CastCRLCache = InMemoryCastCRLCache()) -> CastDeviceVerifier {
        CastDeviceVerifier(trustedRoots: [root.der], crlRoot: crlRoot.der, crlCache: cache)
    }

    func context(video: Bool = false) -> CastAuthContext {
        CastAuthContext(sentNonce: nonce, tlsCertificate: tls.der, advertisesVideoOutput: video, now: now)
    }

    func response(
        nonce: Data? = Data(0..<16), tls: Data? = nil, hash: CastHashAlgorithm = .sha256
    ) throws -> CastAuthResponse {
        let signed = (nonce ?? Data()) + (tls ?? self.tls.der)
        // The two-level fixture intentionally sends the root-nearest intermediate first.
        let intermediates = upperIssuer.map { [$0.der, issuer.der] } ?? [issuer.der]
        return try CastAuthResponse(
            signature: sign(signed, hash: hash), deviceCertificate: leaf.der,
            intermediateCertificates: intermediates, hashAlgorithm: hash, senderNonce: nonce, crl: crl()
        )
    }

    func sign(_ bytes: Data, hash: CastHashAlgorithm = .sha256) throws -> Data {
        let algorithm: SecKeyAlgorithm
        if leafKeyKind == .ec256 {
            algorithm = .ecdsaSignatureMessageX962SHA256
        } else {
            algorithm = hash == .sha1 ? .rsaSignatureMessagePKCS1v15SHA1 : .rsaSignatureMessagePKCS1v15SHA256
        }
        return try Self.signature(bytes, key: leaf.key, algorithm: algorithm)
    }

    func tlsCertificate(
        notBefore: TimeInterval = -CastAuthFixture.day, notAfter: TimeInterval = CastAuthFixture.day, serial: UInt64 = 101
    ) throws -> Certificate {
        try Self.certificate(
            name: "TLS test device", key: root.key, issuerName: "TLS test device", issuerKey: root.key,
            serial: serial, before: now.addingTimeInterval(notBefore), after: now.addingTimeInterval(notAfter),
            caPathLength: nil
        )
    }

    func expiredAlternativeIssuer() throws -> Certificate {
        try Self.certificate(
            name: issuer.name, key: issuer.key, issuerName: root.name, issuerKey: root.key,
            serial: 4, before: now.addingTimeInterval(-Self.year), after: now.addingTimeInterval(-Self.day),
            caPathLength: 0
        )
    }

    func crl(
        notBefore: TimeInterval = -60, notAfter: TimeInterval = 7 * CastAuthFixture.day,
        revokedSerial: UInt64? = nil, revokedSPKI: Data? = nil,
        version: UInt64 = 0, malformedTBS: Bool = false, tamperSignature: Bool = false
    ) throws -> Data {
        var tbs = Self.protoInteger(1, version)
        tbs += Self.protoInteger(2, UInt64(now.addingTimeInterval(notBefore).timeIntervalSince1970))
        tbs += Self.protoInteger(3, UInt64(now.addingTimeInterval(notAfter).timeIntervalSince1970))
        if let revokedSPKI {
            tbs += Self.protoBytes(4, Data(SHA256.hash(data: revokedSPKI)))
        }
        if let revokedSerial {
            let range = Self.protoBytes(1, Data(SHA256.hash(data: issuer.spki)))
                + Self.protoInteger(2, revokedSerial) + Self.protoInteger(3, revokedSerial)
            tbs += Self.protoBytes(5, range)
        }
        if malformedTBS { tbs = Data([0xff]) }
        var signature = try Self.signature(tbs, key: crlSigner.key)
        if tamperSignature { signature[0] ^= 1 }
        let entry = Self.protoBytes(1, tbs) + Self.protoBytes(2, crlSigner.der) + Self.protoBytes(3, signature)
        return Self.protoBytes(1, entry)
    }

    /// Each fixture role reuses one key per process; certificates are still rebuilt for every test.
    /// Generating six RSA keys per fixture made this suite the slowest and most CPU-heavy one.
    private static func key(_ kind: LeafKeyKind = .rsa2048, role: String) throws -> SecKey {
        try keyCache.key(for: "\(role)-\(kind)") { try generateKey(kind) }
    }

    private static let keyCache = FixtureKeyCache()

    private static func generateKey(_ kind: LeafKeyKind) throws -> SecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kind == .ec256 ? kSecAttrKeyTypeECSECPrimeRandom : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: kind == .ec256 ? 256 : kind == .rsa1024 ? 1024 : 2048,
            kSecAttrIsPermanent: false,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error { throw error.takeRetainedValue() as Error }
            throw FixtureError.keyGeneration
        }
        return key
    }

    private static func signature(
        _ bytes: Data, key: SecKey, algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
    ) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let value = SecKeyCreateSignature(key, algorithm, bytes as CFData, &error) else {
            if let error { throw error.takeRetainedValue() as Error }
            throw FixtureError.signature
        }
        return value as Data
    }

    private static func certificate(
        name: String, key: SecKey, issuerName: String, issuerKey: SecKey, serial: UInt64,
        before: Date, after: Date, caPathLength: UInt64?, audioOnly: Bool = false,
        keyKind: LeafKeyKind = .rsa2048, omitKeyUsage: Bool = false,
        leafConstraintFailure: CastLeafConstraintFailure? = nil
    ) throws -> Certificate {
        guard let publicKey = SecKeyCopyPublicKey(key) else { throw FixtureError.publicKey }
        var error: Unmanaged<CFError>?
        guard let rawKey = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            if let error { throw error.takeRetainedValue() as Error }
            throw FixtureError.publicKey
        }
        let publicKeyAlgorithm = keyKind == .ec256
            ? DER.sequence(DER.oid("1.2.840.10045.2.1") + DER.oid("1.2.840.10045.3.1.7"))
            : DER.sequence(DER.oid("1.2.840.113549.1.1.1") + DER.value(0x05, Data()))
        let spki = DER.sequence(publicKeyAlgorithm + DER.bitString(rawKey as Data))
        let algorithm = DER.sequence(DER.oid("1.2.840.113549.1.1.11") + DER.value(0x05, Data()))
        var extensions = Data()
        if let caPathLength {
            extensions += DER.extensionValue(
                "2.5.29.19", critical: true,
                bytes: DER.sequence(DER.value(0x01, Data([0xff])) + DER.integer(caPathLength))
            )
            if !omitKeyUsage {
                extensions += DER.extensionValue("2.5.29.15", critical: true, bytes: DER.bitString(Data([0x06]), unused: 1))
            }
        } else {
            extensions += DER.extensionValue("2.5.29.19", critical: true, bytes: DER.sequence(Data()))
            if !omitKeyUsage {
                let wrongUsage = leafConstraintFailure == .wrongKeyUsage
                extensions += DER.extensionValue(
                    "2.5.29.15", critical: true,
                    bytes: DER.bitString(Data([wrongUsage ? 0x20 : 0x80]), unused: wrongUsage ? 5 : 7)
                )
            }
            let eku = leafConstraintFailure == .wrongEKU ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"
            extensions += DER.extensionValue("2.5.29.37", bytes: DER.sequence(DER.oid(eku)))
        }
        if leafConstraintFailure == .unknownCriticalExtension {
            extensions += DER.extensionValue("1.2.3.4", critical: true, bytes: DER.value(0x05, Data()))
        }
        if audioOnly {
            extensions += DER.extensionValue(
                "2.5.29.32", bytes: DER.sequence(DER.sequence(DER.oid("1.3.6.1.4.1.11129.2.5.2")))
            )
        }
        let tbs = DER.sequence(
            DER.value(0xa0, DER.integer(2)) + DER.integer(serial) + algorithm
                + DER.name(issuerName) + DER.sequence(DER.time(before) + DER.time(after))
                + (leafConstraintFailure == .missingCommonName ? DER.sequence(Data()) : DER.name(name))
                + spki + DER.value(0xa3, DER.sequence(extensions))
        )
        let signed = try signature(tbs, key: issuerKey)
        return Certificate(
            der: DER.sequence(tbs + algorithm + DER.bitString(signed)), spki: spki,
            serial: serial, name: name, key: key
        )
    }

    private static func protoInteger(_ field: UInt64, _ value: UInt64) -> Data {
        varint(field << 3) + varint(value)
    }

    private static func protoBytes(_ field: UInt64, _ value: Data) -> Data {
        varint((field << 3) | 2) + varint(UInt64(value.count)) + value
    }

    private static func varint(_ value: UInt64) -> Data {
        var remainder = value
        var bytes = Data()
        repeat {
            var byte = UInt8(remainder & 0x7f)
            remainder >>= 7
            if remainder != 0 { byte |= 0x80 }
            bytes.append(byte)
        } while remainder != 0
        return bytes
    }

    private enum FixtureError: Error { case keyGeneration, publicKey, signature }

    private enum DER {
        static func value(_ tag: UInt8, _ bytes: Data) -> Data {
            var length = bytes.count
            var encodedLength = Data()
            if length < 128 {
                encodedLength.append(UInt8(length))
            } else {
                while length > 0 {
                    encodedLength.insert(UInt8(length & 0xff), at: 0)
                    length >>= 8
                }
                encodedLength.insert(0x80 | UInt8(encodedLength.count), at: 0)
            }
            return Data([tag]) + encodedLength + bytes
        }

        static func sequence(_ bytes: Data) -> Data { value(0x30, bytes) }
        static func bitString(_ bytes: Data, unused: UInt8 = 0) -> Data { value(0x03, Data([unused]) + bytes) }

        static func integer(_ number: UInt64) -> Data {
            var number = number
            var bytes = Data()
            repeat {
                bytes.insert(UInt8(number & 0xff), at: 0)
                number >>= 8
            } while number > 0
            if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
            return value(0x02, bytes)
        }

        static func oid(_ dotted: String) -> Data {
            let components = dotted.split(separator: ".").map { UInt64($0)! }
            var bytes = Data([UInt8(components[0] * 40 + components[1])])
            for component in components.dropFirst(2) {
                var component = component
                var encoded = [UInt8(component & 0x7f)]
                component >>= 7
                while component > 0 {
                    encoded.insert(UInt8(component & 0x7f) | 0x80, at: 0)
                    component >>= 7
                }
                bytes.append(contentsOf: encoded)
            }
            return value(0x06, bytes)
        }

        static func name(_ commonName: String) -> Data {
            sequence(value(0x31, sequence(oid("2.5.4.3") + value(0x0c, Data(commonName.utf8)))))
        }

        static func time(_ date: Date) -> Data {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            let year = Calendar(identifier: .gregorian).component(.year, from: date)
            let useUTC = (1950..<2050).contains(year)
            formatter.dateFormat = useUTC ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
            return value(useUTC ? 0x17 : 0x18, Data(formatter.string(from: date).utf8))
        }

        static func extensionValue(_ oidString: String, critical: Bool = false, bytes: Data) -> Data {
            sequence(oid(oidString) + (critical ? value(0x01, Data([0xff])) : Data()) + value(0x04, bytes))
        }
    }
}

// NSLock guards the dictionary; SecKey objects are immutable and safe to share between test threads.
private final class FixtureKeyCache: @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: SecKey] = [:]

    func key(for name: String, make: () throws -> SecKey) throws -> SecKey {
        try lock.withLock {
            if let key = keys[name] { return key }
            let key = try make()
            keys[name] = key
            return key
        }
    }
}
