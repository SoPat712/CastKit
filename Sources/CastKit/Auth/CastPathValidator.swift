import Foundation
import Security

struct CastPathValidator {
    let roots: [CastCertificate]

    func build(
        leaf: CastCertificate, intermediates: [CastCertificate], date: Date, device: Bool
    ) throws -> [CastCertificate] {
        var attempts = 0
        var failure: (any Error)?
        func visit(_ path: [CastCertificate]) -> [CastCertificate]? {
            guard let child = path.last, attempts < 128 else { return nil }
            if roots.contains(where: { $0.der == child.der }) {
                attempts += 1
                do {
                    try validate(path, date: date, device: device)
                    return path
                } catch { failure = error; return nil }
            }
            guard path.count <= 16 else { return nil }
            for issuer in intermediates + roots where child.issuer == issuer.normalizedSubject {
                guard !path.contains(where: { $0.der == issuer.der }) else { continue }
                // Reject bad edges early so unrelated cross-signatures cannot exhaust path exploration.
                attempts += 1
                guard attempts < 128 else { return nil }
                do { try child.verifySignature(issuer: issuer) }
                catch { failure = error; continue }
                if let result = visit(path + [issuer]) { return result }
            }
            return nil
        }
        if let path = visit([leaf]) { return path }
        if attempts >= 128 { throw CastAuthError.inputTooLarge }
        if let failure { throw failure }
        throw device ? CastAuthError.untrustedDeviceChain : CastAuthError.untrustedCRLSigner
    }

    private func validate(_ path: [CastCertificate], date: Date, device: Bool) throws {
        let handled: Set<String> = [
            "2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.32", "2.5.29.33",
            "2.5.29.36", "2.5.29.54", "2.5.29.30", "2.5.29.17",
        ]
        for (index, certificate) in path.enumerated() {
            try certificate.validateKey(requiresRSA: index == 0)
            for (oid, value) in certificate.extensions where value.critical && !handled.contains(oid) {
                throw CastAuthError.unsupportedCriticalExtension
            }
            if index < path.count - 1 {
                guard certificate.notBefore <= date else { throw CastAuthError.certificateNotYetValid }
                guard date <= certificate.notAfter else { throw CastAuthError.certificateExpired }
            }
            if device, let eku = try certificate.extendedKeyUsage(),
               !eku.contains("1.3.6.1.5.5.7.3.2"), !eku.contains("2.5.29.37.0") {
                throw CastAuthError.invalidExtendedKeyUsage
            }
            // Parse even noncritical extensions, including those not needed for the final identity.
            _ = try certificate.extendedKeyUsage()
            _ = try certificate.policies()
            _ = try certificate.basicConstraints()
            let usage = try certificate.keyUsage()
            if index > 0 || path.count == 1 {
                guard let constraints = try certificate.basicConstraints(), constraints.isCA,
                      usage == nil || usage! & 0x04 != 0 else { throw CastAuthError.invalidIssuerConstraints }
                if let length = constraints.pathLength {
                    let below = index > 1 ? path[1..<index].filter { $0.issuer != $0.normalizedSubject }.count : 0
                    guard UInt64(below) <= length else { throw CastAuthError.pathLengthExceeded }
                }
            }
            if index < path.count - 1 { try certificate.verifySignature(issuer: path[index + 1]) }
        }
        if device {
            guard let usage = try path[0].keyUsage(), usage & 0x80 != 0 else {
                throw CastAuthError.missingDigitalSignatureKeyUsage
            }
            guard path[0].commonName != nil else { throw CastAuthError.missingCommonName }
        }
        try CastPathConstraints.validateNames(path)
        try CastPathConstraints.validatePolicies(path)
        try evaluateTrust(path, date: date, device: device)
    }

    private func evaluateTrust(_ path: [CastCertificate], date: Date, device: Bool) throws {
        guard let anchor = path.last else { throw CastAuthError.malformedTrustedRoot }
        let trustAnchor = try anchor.trustAnchor(at: date)
        let certificates = path.dropLast().map(\.certificate) + [trustAnchor]
        let expected = certificates.map { SecCertificateCopyData($0) as Data }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, [trustAnchor] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, date as CFDate) == errSecSuccess else {
            throw device ? CastAuthError.untrustedDeviceChain : CastAuthError.untrustedCRLSigner
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error),
              let evaluated = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              evaluated.map({ SecCertificateCopyData($0) as Data }) == expected else {
            throw device ? CastAuthError.untrustedDeviceChain : CastAuthError.untrustedCRLSigner
        }
    }
}
