import CryptoKit
import Foundation
import Security

struct CastCRL {
    struct SerialRange {
        var issuerHash: Data
        var first: UInt64
        var last: UInt64
    }

    let bundle: Data
    let notBefore: Date
    let notAfter: Date
    let publicKeyHashes: Set<Data>
    let serialRanges: [SerialRange]

    static func verify(_ bundle: Data, root: CastCertificate, now: Date) throws -> CastCRL {
        let entries = try CastProto.decode(bundle).filter { $0.number == 1 }
        guard entries.count <= 16 else { throw CastAuthError.inputTooLarge }
        var sawUnsupportedVersion = false
        for entry in entries {
            guard let bytes = entry.bytes else { throw CastAuthError.malformedCRL }
            let fields = try CastProto.decode(bytes)
            guard let tbsBytes = try CastProto.bytes(1, in: fields),
                  let tbs = try? CastProto.decode(tbsBytes) else { continue }
            guard let version = try? CastProto.integer(1, in: tbs) else { continue }
            guard version == 0 else { sawUnsupportedVersion = true; continue }
            // The first parseable version-0 entry is decisive, even if its signature is bad.
            guard let signature = try CastProto.bytes(3, in: fields), !signature.isEmpty else {
                throw CastAuthError.missingCRLSignature
            }
            guard let signerBytes = try CastProto.bytes(2, in: fields) else {
                throw CastAuthError.missingCRLSignerCertificate
            }
            let signer: CastCertificate
            do { signer = try CastCertificate(signerBytes) }
            catch { throw CastAuthError.malformedCRLSigner }
            do { try signer.validateKey(requiresRSA: true) }
            catch CastAuthError.nonRSADeviceKey { throw CastAuthError.nonRSACRLSignerKey }
            guard SecKeyVerifySignature(
                signer.publicKey, .rsaSignatureMessagePKCS1v15SHA256,
                tbsBytes as CFData, signature as CFData, nil
            ) else { throw CastAuthError.invalidCRLSignature }
            let path = try CastPathValidator(roots: [root]).build(leaf: signer, intermediates: [], date: now, device: false)
            guard let beforeSeconds = try CastProto.optionalInteger(2, in: tbs),
                  let afterSeconds = try CastProto.optionalInteger(3, in: tbs) else { throw CastAuthError.malformedCRL }
            let before = Date(timeIntervalSince1970: TimeInterval(beforeSeconds))
            let after = min(Date(timeIntervalSince1970: TimeInterval(afterSeconds)), path.map(\.notAfter).min()!)
            guard before <= now else { throw CastAuthError.crlNotYetValid }
            guard now <= after, before <= after else { throw CastAuthError.crlExpired }
            var hashes: Set<Data> = []
            for field in tbs where field.number == 4 {
                guard let hash = field.bytes, hash.count == 32 else { throw CastAuthError.invalidCRLHash }
                hashes.insert(hash)
            }
            var ranges: [SerialRange] = []
            for field in tbs where field.number == 5 {
                guard let bytes = field.bytes else { throw CastAuthError.malformedCRL }
                let range = try CastProto.decode(bytes)
                guard let hash = try CastProto.bytes(1, in: range), hash.count == 32 else {
                    throw CastAuthError.invalidCRLHash
                }
                let first = try CastProto.integer(2, in: range), last = try CastProto.integer(3, in: range)
                guard last >= first else { throw CastAuthError.invalidCRLSerialRange }
                ranges.append(SerialRange(issuerHash: hash, first: first, last: last))
            }
            return CastCRL(bundle: bundle, notBefore: before, notAfter: after, publicKeyHashes: hashes, serialRanges: ranges)
        }
        throw sawUnsupportedVersion ? CastAuthError.unsupportedCRLVersion : CastAuthError.malformedCRL
    }

    func check(_ path: [CastCertificate], now: Date) throws {
        guard notBefore <= now else { throw CastAuthError.crlNotYetValid }
        guard now <= notAfter else { throw CastAuthError.crlExpired }
        for (index, certificate) in path.enumerated() {
            let hash = Data(SHA256.hash(data: certificate.spki))
            guard !publicKeyHashes.contains(hash) else { throw CastAuthError.revokedPublicKey }
            if index > 0, let serial = path[index - 1].serial,
               serialRanges.contains(where: { $0.issuerHash == hash && $0.first <= serial && serial <= $0.last }) {
                throw CastAuthError.revokedSerialNumber
            }
        }
    }
}

// Only the CRL protobuf is decoded here; deviceauth framing belongs to the connection.
enum CastProto {
    struct Field {
        var number: UInt64
        var bytes: Data?
        var integer: UInt64?
    }

    static func decode(_ data: Data) throws -> [Field] {
        guard data.count <= 1_048_576 else { throw CastAuthError.inputTooLarge }
        let bytes = [UInt8](data)
        var index = 0
        var fields: [Field] = []
        func varint() throws -> UInt64 {
            var value: UInt64 = 0
            for shift in stride(from: 0, through: 63, by: 7) {
                guard index < bytes.count else { throw CastAuthError.malformedCRL }
                let byte = bytes[index]
                index += 1
                guard shift < 63 || byte <= 1 else { throw CastAuthError.malformedCRL }
                value |= UInt64(byte & 0x7f) << shift
                if byte & 0x80 == 0 { return value }
            }
            throw CastAuthError.malformedCRL
        }
        while index < bytes.count {
            guard fields.count < 8_192 else { throw CastAuthError.inputTooLarge }
            let key = try varint(), number = key >> 3
            guard number > 0, number <= 0x1fff_ffff else { throw CastAuthError.malformedCRL }
            switch key & 7 {
            case 0: fields.append(Field(number: number, integer: try varint()))
            case 1, 5:
                let count = key & 7 == 1 ? 8 : 4
                guard count <= bytes.count - index else { throw CastAuthError.malformedCRL }
                index += count
                fields.append(Field(number: number))
            case 2:
                let length = try varint()
                guard length <= UInt64(bytes.count - index) else { throw CastAuthError.malformedCRL }
                let end = index + Int(length)
                fields.append(Field(number: number, bytes: Data(bytes[index..<end])))
                index = end
            default: throw CastAuthError.malformedCRL
            }
        }
        return fields
    }

    static func bytes(_ number: UInt64, in fields: [Field]) throws -> Data? {
        let matches = fields.filter { $0.number == number }
        guard matches.allSatisfy({ $0.bytes != nil }) else { throw CastAuthError.malformedCRL }
        return matches.last?.bytes
    }

    static func optionalInteger(_ number: UInt64, in fields: [Field]) throws -> UInt64? {
        let matches = fields.filter { $0.number == number }
        guard matches.allSatisfy({ $0.integer != nil }) else { throw CastAuthError.malformedCRL }
        return matches.last?.integer
    }

    static func integer(_ number: UInt64, in fields: [Field]) throws -> UInt64 {
        try optionalInteger(number, in: fields) ?? 0
    }
}
