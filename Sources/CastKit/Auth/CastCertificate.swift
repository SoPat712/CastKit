import Foundation
import Security

struct CastCertificate {
    struct Extension {
        let critical: Bool
        let value: Data
    }

    let der: Data
    let certificate: SecCertificate
    let tbs: Data
    let signatureAlgorithm: CastDERNode
    let signature: Data
    let serial: UInt64?
    let subject: CastDERNode
    let issuer: Data
    let normalizedSubject: Data
    let spki: Data
    let publicKey: SecKey
    let notBefore: Date
    let notAfter: Date
    let commonName: String?
    let extensions: [String: Extension]

    init(_ der: Data) throws {
        let outer = try CastDER.parse(der)
        try outer.require(0x30, count: 3)
        let body = outer.children[0]
        try body.require(0x30)
        var index = 0
        var version: UInt64 = 0
        if body.children.first?.tag == 0xa0 {
            let explicit = body.children[0]
            guard explicit.children.count == 1, let value = explicit.children[0].unsignedInteger,
                  value == 1 || value == 2 else { throw CastDERError.malformed }
            version = value
            index += 1
        }
        guard body.children.count >= index + 6 else { throw CastDERError.malformed }
        let serialNode = body.children[index]
        try serialNode.require(0x02)
        let innerAlgorithm = body.children[index + 1]
        try innerAlgorithm.require(0x30)
        try outer.children[1].require(0x30)
        guard innerAlgorithm.encoded == outer.children[1].encoded else {
            throw CastAuthError.invalidCertificateSignatureAlgorithm
        }
        try body.children[index + 2].require(0x30)
        let validity = body.children[index + 3]
        try validity.require(0x30, count: 2)
        let before = try validity.children[0].date
        let after = try validity.children[1].date
        guard before <= after else { throw CastDERError.malformed }
        let subject = body.children[index + 4]
        try subject.require(0x30)
        let spki = body.children[index + 5]
        try spki.require(0x30, count: 2)
        try spki.children[0].require(0x30)
        try spki.children[1].require(0x03)
        guard spki.children[1].value.first == 0 else { throw CastDERError.malformed }
        try outer.children[2].require(0x03)
        guard outer.children[2].value.first == 0, outer.children[2].value.count > 1 else {
            throw CastDERError.malformed
        }
        var commonName: String?
        for rdn in subject.children {
            try rdn.require(0x31)
            guard !rdn.children.isEmpty else { throw CastDERError.malformed }
            for attribute in rdn.children {
                try attribute.require(0x30, count: 2)
                let oid = try attribute.children[0].oid
                if oid == "2.5.4.3" {
                    guard let name = attribute.children[1].string, !name.isEmpty else { throw CastDERError.malformed }
                    if commonName == nil { commonName = name }
                }
            }
        }
        var extensions: [String: Extension] = [:]
        var lastTag: UInt8 = 0x80
        for optional in body.children.dropFirst(index + 6) {
            guard optional.tag > lastTag else { throw CastDERError.malformed }
            lastTag = optional.tag
            switch optional.tag {
            case 0x81, 0x82:
                guard version >= 1, let unused = optional.value.first, unused <= 7,
                      optional.value.count > 1 else { throw CastDERError.malformed }
                if unused > 0 {
                    guard optional.value.last! & UInt8((1 << unused) - 1) == 0 else { throw CastDERError.malformed }
                }
            case 0xa3:
                guard version == 2, optional.children.count == 1 else { throw CastDERError.malformed }
                let sequence = optional.children[0]
                try sequence.require(0x30)
                guard !sequence.children.isEmpty else { throw CastDERError.malformed }
                for item in sequence.children {
                    try item.require(0x30)
                    guard item.children.count == 2 || item.children.count == 3 else { throw CastDERError.malformed }
                    let oid = try item.children[0].oid
                    var critical = false
                    if item.children.count == 3 {
                        try item.children[1].require(0x01)
                        guard item.children[1].value == Data([0xff]) else { throw CastDERError.malformed }
                        critical = true
                    }
                    let octets = item.children.last!
                    try octets.require(0x04)
                    guard extensions[oid] == nil else { throw CastDERError.malformed }
                    extensions[oid] = Extension(critical: critical, value: octets.value)
                }
            default: throw CastDERError.malformed
            }
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData),
              let key = SecCertificateCopyKey(certificate),
              let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate),
              let normalizedSubject = SecCertificateCopyNormalizedSubjectSequence(certificate) else {
            throw CastAuthError.invalidPublicKey
        }
        self.der = der
        self.certificate = certificate
        tbs = body.encoded
        signatureAlgorithm = outer.children[1]
        signature = Data(outer.children[2].value.dropFirst())
        serial = serialNode.unsignedInteger
        self.subject = subject
        self.issuer = issuer as Data
        self.normalizedSubject = normalizedSubject as Data
        self.spki = spki.encoded
        publicKey = key
        notBefore = before
        notAfter = after
        self.commonName = commonName
        self.extensions = extensions
    }

    func extensionNode(_ oid: String) throws -> CastDERNode? {
        try extensions[oid].map { try CastDER.parse($0.value) }
    }

    func basicConstraints() throws -> (isCA: Bool, pathLength: UInt64?)? {
        guard let node = try extensionNode("2.5.29.19") else { return nil }
        try node.require(0x30)
        var fields = node.children[...]
        var isCA = false
        if fields.first?.tag == 0x01 {
            guard fields.removeFirst().value == Data([0xff]) else { throw CastDERError.malformed }
            isCA = true
        }
        var pathLength: UInt64?
        if let field = fields.first {
            guard isCA, let value = field.unsignedInteger else { throw CastDERError.malformed }
            pathLength = value
            fields = fields.dropFirst()
        }
        guard fields.isEmpty else { throw CastDERError.malformed }
        return (isCA, pathLength)
    }

    func keyUsage() throws -> UInt8? {
        guard let node = try extensionNode("2.5.29.15") else { return nil }
        try node.require(0x03)
        guard node.value.count == 2 || node.value.count == 3 else { throw CastDERError.malformed }
        let bytes = [UInt8](node.value)
        guard bytes.last != 0, bytes.count != 3 || (bytes[0] == 7 && bytes[2] == 0x80) else {
            throw CastDERError.malformed
        }
        guard Int(bytes[0]) == bytes.last!.trailingZeroBitCount else { throw CastDERError.malformed }
        return bytes[1]
    }

    func extendedKeyUsage() throws -> Set<String>? {
        guard let node = try extensionNode("2.5.29.37") else { return nil }
        try node.require(0x30)
        guard !node.children.isEmpty else { throw CastDERError.malformed }
        return Set(try node.children.map { try $0.oid })
    }

    func policies() throws -> Set<String>? {
        guard let node = try extensionNode("2.5.29.32") else { return nil }
        try node.require(0x30)
        guard !node.children.isEmpty else { throw CastDERError.malformed }
        var policies: Set<String> = []
        for information in node.children {
            try information.require(0x30)
            guard information.children.count == 1 || information.children.count == 2 else { throw CastDERError.malformed }
            let oid = try information.children[0].oid
            guard policies.insert(oid).inserted else { throw CastDERError.malformed }
            if information.children.count == 2 { try information.children[1].require(0x30) }
        }
        return policies
    }

    func validateKey(requiresRSA: Bool) throws {
        do { try validateKeyEncoding(requiresRSA: requiresRSA) }
        catch is CastDERError { throw CastAuthError.invalidPublicKey }
    }

    private func validateKeyEncoding(requiresRSA: Bool) throws {
        guard let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let type = attributes[kSecAttrKeyType as String] as? String,
              let size = attributes[kSecAttrKeySizeInBits as String] as? Int else { throw CastAuthError.invalidPublicKey }
        if type == kSecAttrKeyTypeRSA as String {
            guard size >= 2_048 else { throw CastAuthError.insufficientRSAKeySize }
            let info = try CastDER.parse(spki)
            let algorithm = info.children[0]
            guard algorithm.children.count == 1 || (algorithm.children.count == 2 && algorithm.children[1].tag == 0x05),
                  try algorithm.children[0].oid == "1.2.840.113549.1.1.1" else {
                throw CastAuthError.invalidPublicKey
            }
            let key = try CastDER.parse(Data(info.children[1].value.dropFirst()))
            try key.require(0x30, count: 2)
            for integer in key.children {
                try integer.require(0x02)
                guard let first = integer.value.first, first & 0x80 == 0,
                      integer.value.contains(where: { $0 != 0 }) else { throw CastAuthError.invalidPublicKey }
            }
        } else {
            guard !requiresRSA else { throw CastAuthError.nonRSADeviceKey }
            guard type == kSecAttrKeyTypeECSECPrimeRandom as String, [256, 384, 521].contains(size) else {
                throw CastAuthError.unsupportedEllipticCurve
            }
            let algorithm = try CastDER.parse(spki).children[0]
            guard algorithm.children.count == 2,
                  try algorithm.children[0].oid == "1.2.840.10045.2.1",
                  ["1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"].contains(try algorithm.children[1].oid) else {
                throw CastAuthError.unsupportedEllipticCurve
            }
        }
    }

    func verifySignature(issuer: CastCertificate) throws {
        let algorithm: SecKeyAlgorithm
        do { algorithm = try Self.algorithm(signatureAlgorithm) }
        catch is CastDERError { throw CastAuthError.invalidCertificateSignatureAlgorithm }
        guard SecKeyIsAlgorithmSupported(issuer.publicKey, .verify, algorithm),
              SecKeyVerifySignature(issuer.publicKey, algorithm, tbs as CFData, signature as CFData, nil) else {
            throw CastAuthError.invalidCertificateSignature
        }
    }

    func trustAnchor(at date: Date) throws -> SecCertificate {
        if notBefore <= date, date <= notAfter { return certificate }
        // SecTrust checks anchor dates, unlike Cast. Only the anchor's unsigned trust representation
        // gets an unrestricted window; all constraints, names and keys remain the original ones.
        let outer = try CastDER.parse(der)
        let body = outer.children[0]
        let index = body.children.first?.tag == 0xa0 ? 4 : 3
        var fields = body.children.map(\.encoded)
        let before = CastDER.encode(0x18, Data("00010101000000Z".utf8))
        let after = CastDER.encode(0x18, Data("99991231235959Z".utf8))
        fields[index] = CastDER.encode(0x30, before + after)
        let replacement = CastDER.encode(0x30, fields.reduce(Data(), +))
        let anchorDER = CastDER.encode(0x30, replacement + outer.children[1].encoded + outer.children[2].encoded)
        guard let anchor = SecCertificateCreateWithData(nil, anchorDER as CFData) else {
            throw CastAuthError.malformedTrustedRoot
        }
        return anchor
    }

    private static func algorithm(_ node: CastDERNode) throws -> SecKeyAlgorithm {
        guard let oidNode = node.children.first else { throw CastDERError.malformed }
        let oid = try oidNode.oid
        if oid == "1.2.840.113549.1.1.10" { return try pssAlgorithm(node) }
        let rsa: [String: SecKeyAlgorithm] = [
            "1.2.840.113549.1.1.5": .rsaSignatureMessagePKCS1v15SHA1,
            "1.2.840.113549.1.1.11": .rsaSignatureMessagePKCS1v15SHA256,
            "1.2.840.113549.1.1.12": .rsaSignatureMessagePKCS1v15SHA384,
            "1.2.840.113549.1.1.13": .rsaSignatureMessagePKCS1v15SHA512,
        ]
        if let algorithm = rsa[oid] {
            guard node.children.count == 1 || (node.children.count == 2 && node.children[1].tag == 0x05) else {
                throw CastAuthError.unsupportedCertificateSignatureAlgorithm
            }
            return algorithm
        }
        let ec: [String: SecKeyAlgorithm] = [
            "1.2.840.10045.4.1": .ecdsaSignatureMessageX962SHA1,
            "1.2.840.10045.4.3.2": .ecdsaSignatureMessageX962SHA256,
            "1.2.840.10045.4.3.3": .ecdsaSignatureMessageX962SHA384,
            "1.2.840.10045.4.3.4": .ecdsaSignatureMessageX962SHA512,
        ]
        guard node.children.count == 1, let algorithm = ec[oid] else {
            throw CastAuthError.unsupportedCertificateSignatureAlgorithm
        }
        return algorithm
    }

    private static func pssAlgorithm(_ node: CastDERNode) throws -> SecKeyAlgorithm {
        guard node.children.count == 2 else { throw CastAuthError.unsupportedCertificateSignatureAlgorithm }
        let parameters = node.children[1]
        try parameters.require(0x30)
        var hash: String?
        var maskHash: String?
        var salt: UInt64 = 20
        var last: UInt8 = 0x9f
        for field in parameters.children {
            guard field.tag > last, field.children.count == 1 else { throw CastDERError.malformed }
            last = field.tag
            let value = field.children[0]
            switch field.tag {
            case 0xa0: hash = try digestOID(value)
            case 0xa1:
                try value.require(0x30, count: 2)
                guard try value.children[0].oid == "1.2.840.113549.1.1.8" else {
                    throw CastAuthError.unsupportedCertificateSignatureAlgorithm
                }
                maskHash = try digestOID(value.children[1])
            case 0xa2:
                guard let length = value.unsignedInteger else { throw CastDERError.malformed }
                salt = length
            case 0xa3:
                guard value.unsignedInteger == 1 else { throw CastAuthError.unsupportedCertificateSignatureAlgorithm }
            default: throw CastDERError.malformed
            }
        }
        guard let hash, hash == maskHash else { throw CastAuthError.unsupportedCertificateSignatureAlgorithm }
        switch (hash, salt) {
        case ("2.16.840.1.101.3.4.2.1", 32): return .rsaSignatureMessagePSSSHA256
        case ("2.16.840.1.101.3.4.2.2", 48): return .rsaSignatureMessagePSSSHA384
        case ("2.16.840.1.101.3.4.2.3", 64): return .rsaSignatureMessagePSSSHA512
        default: throw CastAuthError.unsupportedCertificateSignatureAlgorithm
        }
    }

    private static func digestOID(_ node: CastDERNode) throws -> String {
        try node.require(0x30)
        guard node.children.count == 1 || (node.children.count == 2 && node.children[1].tag == 0x05) else {
            throw CastDERError.malformed
        }
        return try node.children[0].oid
    }
}
