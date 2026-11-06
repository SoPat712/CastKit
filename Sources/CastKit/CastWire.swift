import Foundation

enum CastWireLimits {
    static let maximumFrameLength = 65_536
}

/// Buffers at most one bounded frame, even when a read contains many messages.
struct CastFramer {
    private var pending = Data()
    private var expectedLength: Int?

    init() {}

    mutating func append(_ data: Data) throws -> [CastMessage] {
        var messages: [CastMessage] = []
        var index = data.startIndex
        do {
            while index < data.endIndex {
                let target = expectedLength ?? 4
                let count = min(target - pending.count, data.distance(from: index, to: data.endIndex))
                let end = data.index(index, offsetBy: count)
                pending.append(contentsOf: data[index..<end])
                index = end
                guard pending.count == target else { break }

                if expectedLength == nil {
                    let length = pending.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                    pending.removeAll(keepingCapacity: true)
                    guard length > 0 else { throw CastError.invalidMessage }
                    guard length <= CastWireLimits.maximumFrameLength else { throw CastError.frameTooLarge }
                    expectedLength = Int(length)
                } else {
                    let message = try CastMessage(data: pending)
                    pending.removeAll(keepingCapacity: true)
                    expectedLength = nil
                    messages.append(message)
                }
            }
        } catch {
            pending.removeAll(keepingCapacity: true)
            expectedLength = nil
            throw error
        }
        return messages
    }

    static func frame(_ message: CastMessage) throws -> Data {
        let encoded = try message.encoded()
        guard !encoded.isEmpty else { throw CastError.invalidMessage }
        guard encoded.count <= CastWireLimits.maximumFrameLength else { throw CastError.frameTooLarge }
        let length = UInt32(encoded.count)
        var result = Data([
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length),
        ])
        result.append(encoded)
        return result
    }
}

enum CastDeviceAuthWire {
    static func challenge(nonce: Data) throws -> Data {
        guard nonce.count == 16 else { throw CastError.authenticationFailed }
        var challenge = CastProtoWriter()
        try challenge.appendBytes(field: 2, value: nonce)
        try challenge.appendVarint(field: 3, value: UInt64(CastHashAlgorithm.sha256.rawValue))
        var message = CastProtoWriter()
        try message.appendBytes(field: 1, value: challenge.data)
        return message.data
    }

    static func response(from data: Data) throws -> CastAuthResponse {
        do {
            guard data.count <= CastWireLimits.maximumFrameLength else { throw CastError.invalidMessage }
            var reader = CastProtoReader(data: data)
            var response: CastAuthResponse?
            while let field = try reader.nextField() {
                switch field.number {
                case 1:
                    _ = try reader.bytes(wire: field.wire)
                case 2:
                    response = try decodeResponse(reader.bytes(wire: field.wire))
                case 3:
                    throw CastError.authenticationFailed
                default:
                    try reader.skip(wire: field.wire)
                }
            }
            guard let response else { throw CastError.authenticationFailed }
            return response
        } catch {
            throw CastError.authenticationFailed
        }
    }

    private static func decodeResponse(_ data: Data) throws -> CastAuthResponse {
        var reader = CastProtoReader(data: data)
        var signature: Data?
        var certificate: Data?
        var intermediates: [Data] = []
        var signatureAlgorithm = CastSignatureAlgorithm.rsassaPKCS1v15
        var hashAlgorithm = CastHashAlgorithm.sha1
        var nonce: Data?
        var crl: Data?
        while let field = try reader.nextField() {
            switch field.number {
            case 1:
                signature = try reader.bytes(wire: field.wire)
            case 2:
                certificate = try reader.bytes(wire: field.wire)
            case 3:
                intermediates.append(try reader.bytes(wire: field.wire))
            case 4:
                let value = try reader.varint(wire: field.wire)
                guard let rawValue = Int(exactly: value),
                      let algorithm = CastSignatureAlgorithm(rawValue: rawValue) else {
                    throw CastError.invalidMessage
                }
                signatureAlgorithm = algorithm
            case 5:
                nonce = try reader.bytes(wire: field.wire)
            case 6:
                let value = try reader.varint(wire: field.wire)
                guard let rawValue = Int(exactly: value),
                      let algorithm = CastHashAlgorithm(rawValue: rawValue) else {
                    throw CastError.invalidMessage
                }
                hashAlgorithm = algorithm
            case 7:
                crl = try reader.bytes(wire: field.wire)
            default:
                try reader.skip(wire: field.wire)
            }
        }
        guard let signature, let certificate else { throw CastError.invalidMessage }
        return CastAuthResponse(
            signature: signature,
            deviceCertificate: certificate,
            intermediateCertificates: intermediates,
            signatureAlgorithm: signatureAlgorithm,
            hashAlgorithm: hashAlgorithm,
            senderNonce: nonce,
            crl: crl
        )
    }
}

/// The reader checks lengths before converting them to native indices or copying bytes.
struct CastProtoReader {
    struct Field {
        let number: UInt64
        let wire: UInt8
    }

    private let data: Data
    private var index: Data.Index

    init(data: Data) {
        self.data = data
        index = data.startIndex
    }

    mutating func nextField() throws -> Field? {
        guard index != data.endIndex else { return nil }
        let key = try readVarint()
        let number = key >> 3
        let wire = UInt8(key & 7)
        guard number > 0, number <= 0x1fff_ffff, [0, 1, 2, 5].contains(wire) else {
            throw CastError.invalidMessage
        }
        return Field(number: number, wire: wire)
    }

    mutating func varint(wire: UInt8) throws -> UInt64 {
        guard wire == 0 else { throw CastError.invalidMessage }
        return try readVarint()
    }

    mutating func bytes(wire: UInt8) throws -> Data {
        guard wire == 2 else { throw CastError.invalidMessage }
        let length = try readVarint()
        guard length <= UInt64(data.distance(from: index, to: data.endIndex)) else {
            throw CastError.invalidMessage
        }
        let end = data.index(index, offsetBy: Int(length))
        let value = Data(data[index..<end])
        index = end
        return value
    }

    mutating func string(wire: UInt8) throws -> String {
        guard let value = String(data: try bytes(wire: wire), encoding: .utf8) else {
            throw CastError.invalidMessage
        }
        return value
    }

    mutating func skip(wire: UInt8) throws {
        switch wire {
        case 0:
            _ = try readVarint()
        case 1:
            try advance(by: 8)
        case 2:
            let length = try readVarint()
            guard length <= UInt64(data.distance(from: index, to: data.endIndex)) else {
                throw CastError.invalidMessage
            }
            try advance(by: Int(length))
        case 5:
            try advance(by: 4)
        default:
            throw CastError.invalidMessage
        }
    }

    private mutating func advance(by count: Int) throws {
        guard count <= data.distance(from: index, to: data.endIndex) else { throw CastError.invalidMessage }
        index = data.index(index, offsetBy: count)
    }

    private mutating func readVarint() throws -> UInt64 {
        var value: UInt64 = 0
        for byteNumber in 0..<10 {
            guard index != data.endIndex else { throw CastError.invalidMessage }
            let byte = data[index]
            index = data.index(after: index)
            if byteNumber == 9, byte > 1 { throw CastError.invalidMessage }
            value |= UInt64(byte & 0x7f) << (byteNumber * 7)
            if byte & 0x80 == 0 { return value }
        }
        throw CastError.invalidMessage
    }
}

struct CastProtoWriter {
    private(set) var data = Data()

    mutating func appendVarint(field: UInt64, value: UInt64) throws {
        let key = varintBytes(field << 3)
        let bytes = varintBytes(value)
        try reserve(count: key.count + bytes.count)
        data.append(contentsOf: key)
        data.append(contentsOf: bytes)
    }

    mutating func appendBytes(field: UInt64, value: Data) throws {
        let key = varintBytes((field << 3) | 2)
        let length = varintBytes(UInt64(value.count))
        try reserve(count: key.count + length.count, payloadCount: value.count)
        data.append(contentsOf: key)
        data.append(contentsOf: length)
        data.append(value)
    }

    private func reserve(count: Int, payloadCount: Int = 0) throws {
        let available = CastWireLimits.maximumFrameLength - data.count
        guard count <= available, payloadCount <= available - count else { throw CastError.frameTooLarge }
    }

    private func varintBytes(_ value: UInt64) -> [UInt8] {
        var value = value
        var result: [UInt8] = []
        repeat {
            let byte = UInt8(value & 0x7f)
            value >>= 7
            result.append(value == 0 ? byte : byte | 0x80)
        } while value != 0
        return result
    }
}
