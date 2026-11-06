import Foundation

/// One message carried by a Cast v2 channel.
public struct CastMessage: Sendable, Equatable {
    /// The protobuf payload discriminator; device authentication uses binary.
    public enum PayloadType: UInt64, Sendable, Equatable {
        case string = 0
        case binary = 1
    }

    /// Zero for outbound CASTV2_1_0 messages.
    public var protocolVersion: UInt64
    /// The source virtual endpoint.
    public var sourceID: String
    /// The destination virtual endpoint, or an asterisk for broadcast.
    public var destinationID: String
    /// The Cast namespace routing this payload.
    public var namespace: String
    /// The protobuf payload discriminator.
    public var payloadType: PayloadType
    /// Field six, normally JSON for STRING messages.
    public var payloadUTF8: String?
    /// Field seven, used for device auth and some receivers' STRING JSON.
    public var payloadBinary: Data?
    /// Preserved chunking flag; this sender does not negotiate chunk assembly.
    public var continued: Bool?
    /// Preserved chunking length; this sender does not negotiate chunk assembly.
    public var remainingLength: UInt32?

    /// Creates a message, preserving the presence of optional proto2 fields.
    public init(
        protocolVersion: UInt64 = 0,
        sourceID: String,
        destinationID: String,
        namespace: String,
        payloadType: PayloadType = .string,
        payloadUTF8: String? = nil,
        payloadBinary: Data? = nil,
        continued: Bool? = nil,
        remainingLength: UInt32? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.sourceID = sourceID
        self.destinationID = destinationID
        self.namespace = namespace
        self.payloadType = payloadType
        self.payloadUTF8 = payloadUTF8
        self.payloadBinary = payloadBinary
        self.continued = continued
        self.remainingLength = remainingLength
    }

    /// The JSON bytes for STRING messages, including the version 1.3 binary-field representation.
    public var jsonData: Data? {
        guard payloadType == .string else { return nil }
        if let payloadUTF8 { return Data(payloadUTF8.utf8) }
        guard let payloadBinary, String(data: payloadBinary, encoding: .utf8) != nil else { return nil }
        return payloadBinary
    }

    /// Encodes a validated protobuf without the four-byte frame header.
    public func encoded() throws -> Data {
        try validate()
        var writer = CastProtoWriter()
        try writer.appendVarint(field: 1, value: protocolVersion)
        try writer.appendBytes(field: 2, value: Data(sourceID.utf8))
        try writer.appendBytes(field: 3, value: Data(destinationID.utf8))
        try writer.appendBytes(field: 4, value: Data(namespace.utf8))
        try writer.appendVarint(field: 5, value: payloadType.rawValue)
        if let payloadUTF8 { try writer.appendBytes(field: 6, value: Data(payloadUTF8.utf8)) }
        if let payloadBinary { try writer.appendBytes(field: 7, value: payloadBinary) }
        if let continued { try writer.appendVarint(field: 8, value: continued ? 1 : 0) }
        if let remainingLength { try writer.appendVarint(field: 9, value: UInt64(remainingLength)) }
        return writer.data
    }

    /// Decodes a bounded protobuf, rejecting malformed or incomplete messages.
    public init(data: Data) throws {
        guard data.count <= CastWireLimits.maximumFrameLength else { throw CastError.frameTooLarge }
        var reader = CastProtoReader(data: data)
        var protocolVersion: UInt64?
        var sourceID: String?
        var destinationID: String?
        var namespace: String?
        var payloadType: PayloadType?
        var payloadUTF8: String?
        var payloadBinary: Data?
        var continued: Bool?
        var remainingLength: UInt32?

        while let field = try reader.nextField() {
            switch field.number {
            case 1:
                protocolVersion = try reader.varint(wire: field.wire)
            case 2:
                sourceID = try reader.string(wire: field.wire)
            case 3:
                destinationID = try reader.string(wire: field.wire)
            case 4:
                namespace = try reader.string(wire: field.wire)
            case 5:
                let value = try reader.varint(wire: field.wire)
                guard let type = PayloadType(rawValue: value) else { throw CastError.invalidMessage }
                payloadType = type
            case 6:
                payloadUTF8 = try reader.string(wire: field.wire)
            case 7:
                payloadBinary = try reader.bytes(wire: field.wire)
            case 8:
                continued = try reader.varint(wire: field.wire) != 0
            case 9:
                let value = try reader.varint(wire: field.wire)
                guard let length = UInt32(exactly: value) else { throw CastError.invalidMessage }
                remainingLength = length
            default:
                try reader.skip(wire: field.wire)
            }
        }

        guard let protocolVersion, let sourceID, let destinationID, let namespace, let payloadType else {
            throw CastError.invalidMessage
        }
        self.init(
            protocolVersion: protocolVersion,
            sourceID: sourceID,
            destinationID: destinationID,
            namespace: namespace,
            payloadType: payloadType,
            payloadUTF8: payloadUTF8,
            payloadBinary: payloadBinary,
            continued: continued,
            remainingLength: remainingLength
        )
        try validate()
    }

    private func validate() throws {
        guard !sourceID.isEmpty, !destinationID.isEmpty, !namespace.isEmpty else {
            throw CastError.invalidMessage
        }
        switch payloadType {
        case .string:
            if payloadUTF8 == nil {
                guard let payloadBinary, String(data: payloadBinary, encoding: .utf8) != nil else {
                    throw CastError.invalidMessage
                }
            }
        case .binary:
            guard payloadBinary != nil else { throw CastError.invalidMessage }
        }
    }
}
