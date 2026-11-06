import Foundation
import Testing
@testable import CastKit

struct CastKitWireTests {
    @Test func mediaCustomDataAndQueueItemMatchExactJSON() throws {
        let media = CastMedia(
            contentID: "https://example.test/track.mp3", contentType: "audio/mpeg", duration: 120,
            customData: ["occurrence": "first"]
        )
        let expected = #"{"contentId":"https://example.test/track.mp3","contentType":"audio/mpeg","customData":{"occurrence":"first"},"duration":120,"metadata":{"images":[],"metadataType":3},"streamType":"BUFFERED"}"#
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        #expect(String(decoding: try encoder.encode(media.json), as: UTF8.self) == expected)
        #expect(CastMedia(try JSONDecoder().decode(CastJSON.self, from: Data(expected.utf8))) == media)

        let item = CastQueueItem(media: media, autoplay: false, preloadTime: 12, customData: ["entry": "second"])
        let expectedItem = #"{"autoplay":false,"customData":{"entry":"second"},"media":\#(expected),"preloadTime":12}"#
        #expect(String(decoding: try encoder.encode(item.json), as: UTF8.self) == expectedItem)
        #expect(item.json["itemId"] == .null)
        #expect(CastQueueItem(media: media).json["customData"] == .null)
        #expect(CastMedia(contentID: "x", contentType: "audio/mpeg").json["customData"] == .null)
    }

    @Test func streamVolumeCapabilityUsesCommandBitFour() {
        let cases: [(Int?, Bool)] = [(nil, false), (0, false), (1, false), (4, true), (12, true), (64, false)]
        for (commands, expected) in cases {
            let status = CastMediaStatus(mediaSessionID: 1, playerState: .playing, supportedMediaCommands: commands)
            #expect(status.supportsStreamVolume == expected)
        }
    }

    private let ping = CastMessage(
        sourceID: "sender-0",
        destinationID: "receiver-0",
        namespace: "urn:x-cast:com.google.cast.tp.heartbeat",
        payloadUTF8: #"{"type":"PING"}"#
    )

    @Test func pingMatchesProtocolVector() throws {
        let vector = hex("""
            00000054 0800 1208 73656e6465722d30 1a0a 72656365697665722d30
            2227 75726e3a782d636173743a636f6d2e676f6f676c652e636173742e74702e686561727462656174
            2800 320f 7b2274797065223a2250494e47227d
            """)
        #expect(try CastFramer.frame(ping) == vector)
        var framer = CastFramer()
        let decoded = try framer.append(vector)
        #expect(decoded == [ping])
    }

    @Test func authChallengeMatchesProtocolVector() throws {
        let nonce = Data((0..<16).map(UInt8.init))
        let payload = try CastDeviceAuthWire.challenge(nonce: nonce)
        #expect(payload == hex("0a14 1210 000102030405060708090a0b0c0d0e0f 1801"))
        let message = CastMessage(
            sourceID: "sender-0",
            destinationID: "receiver-0",
            namespace: "urn:x-cast:com.google.cast.tp.deviceauth",
            payloadType: .binary,
            payloadBinary: payload
        )
        #expect(try CastFramer.frame(message) == hex("""
            0000005c 0800 1208 73656e6465722d30 1a0a 72656365697665722d30
            2228 75726e3a782d636173743a636f6d2e676f6f676c652e636173742e74702e64657669636561757468
            2801 3a16 0a141210000102030405060708090a0b0c0d0e0f1801
            """))
    }

    @Test func allCastFieldsRoundTrip() throws {
        let message = CastMessage(
            protocolVersion: .max,
            sourceID: "sender-音",
            destinationID: "*",
            namespace: "urn:x-cast:example",
            payloadType: .string,
            payloadUTF8: #"{"title":"音楽"}"#,
            payloadBinary: Data([0xff, 0x00]),
            continued: false,
            remainingLength: .max
        )
        #expect(try CastMessage(data: message.encoded()) == message)
        #expect(message.jsonData == Data(#"{"title":"音楽"}"#.utf8))
    }

    @Test func requiredZeroValuesAndPresentEmptyPayloadAreEncoded() throws {
        let message = CastMessage(sourceID: "s", destinationID: "d", namespace: "n", payloadUTF8: "")
        #expect(try message.encoded() == hex("0800 120173 1a0164 22016e 2800 3200"))
        let binary = CastMessage(
            sourceID: "s", destinationID: "d", namespace: "n", payloadType: .binary, payloadBinary: Data()
        )
        #expect(try binary.encoded() == hex("0800 120173 1a0164 22016e 2801 3a00"))
        #expect(try CastMessage(data: binary.encoded()) == binary)
        #expect(binary.jsonData == nil)
    }

    @Test func singularCastFieldsUseTheirLastValue() throws {
        let first = CastMessage(
            sourceID: "s", destinationID: "d", namespace: "n", payloadUTF8: "first",
            payloadBinary: Data([1]), continued: true, remainingLength: 12
        )
        let replacements = hex("0803 12027332 1a026432 22026e32 2801 32046c617374 3a020203 4000 4800")
        let decoded = try CastMessage(data: first.encoded() + replacements)
        #expect(decoded == CastMessage(
            protocolVersion: 3,
            sourceID: "s2", destinationID: "d2", namespace: "n2", payloadType: .binary,
            payloadUTF8: "last", payloadBinary: Data([2, 3]), continued: false, remainingLength: 0
        ))
    }

    @Test func unknownFieldsWithSupportedWireTypesAreSkipped() throws {
        let unknown = hex("50ac02 590102030405060708 6203616263 6d01020304")
        #expect(try CastMessage(data: unknown + ping.encoded() + unknown) == ping)
    }

    @Test func stringPayloadCanUseBinaryField() throws {
        let json = Data(#"{"type":"PONG"}"#.utf8)
        let message = CastMessage(
            protocolVersion: 3, sourceID: "s", destinationID: "d", namespace: "n", payloadBinary: json
        )
        let decoded = try CastMessage(data: message.encoded())
        #expect(decoded == message)
        #expect(decoded.payloadUTF8 == nil)
        #expect(decoded.jsonData == json)

        var invalid = message
        invalid.payloadBinary = Data([0xff])
        #expect(throws: CastError.invalidMessage) { try invalid.encoded() }
        #expect(throws: CastError.invalidMessage) {
            try CastMessage(data: hex("0803 120173 1a0164 22016e 2800 3a01ff"))
        }
    }

    @Test func castMessageRequiresEachRequiredFieldAndMatchingPayload() throws {
        let fields = ["0800", "120173", "1a0164", "22016e", "2800", "3200"].map(hex)
        for missing in fields.indices {
            let incomplete = fields.enumerated().reduce(into: Data()) { result, element in
                if element.offset != missing { result.append(element.element) }
            }
            #expect(throws: CastError.invalidMessage) { try CastMessage(data: incomplete) }
        }
        for emptyField in ["1200", "1a00", "2200"] {
            #expect(throws: CastError.invalidMessage) { try CastMessage(data: fields.reduce(Data(), +) + hex(emptyField)) }
        }
        #expect(throws: CastError.invalidMessage) {
            try CastMessage(data: hex("0800 120173 1a0164 22016e 2801 3200"))
        }
        #expect(throws: CastError.invalidMessage) {
            try CastMessage(sourceID: "", destinationID: "d", namespace: "n", payloadUTF8: "").encoded()
        }
        #expect(throws: CastError.invalidMessage) {
            try CastMessage(sourceID: "s", destinationID: "d", namespace: "n").encoded()
        }
        #expect(throws: CastError.invalidMessage) {
            try CastMessage(sourceID: "s", destinationID: "d", namespace: "n", payloadType: .binary).encoded()
        }
    }

    @Test(arguments: [
        "00", "0b", "0c", "0e", "0f", "80", "08", "0880",
        "0880808080808080808002", "088080808080808080808000",
        "12", "1280", "12ffffffffffffffffff01", "12036162", "1201ff",
        "110000000000000000", "2a00", "2802", "488080808010",
        "5080", "5100", "52036162", "550000", "ffffffffffffffffff01", "8080808010",
    ])
    func malformedProtobufIsRejected(suffix: String) throws {
        #expect(throws: CastError.invalidMessage) { try CastMessage(data: ping.encoded() + hex(suffix)) }
    }

    @Test func protobufBooleanUsesNonzeroSemantics() throws {
        let decoded = try CastMessage(data: ping.encoded() + hex("4002"))
        #expect(decoded.continued == true)
    }

    @Test func incrementalFramingAcceptsEverySplit() throws {
        let frame = try CastFramer.frame(ping)
        for split in 0...frame.count {
            var framer = CastFramer()
            let first = try framer.append(Data(frame.prefix(split)))
            let second = try framer.append(Data(frame.dropFirst(split)))
            #expect(first + second == [ping])
            let empty = try framer.append(Data())
            #expect(empty.isEmpty)
        }
    }

    @Test func incrementalFramingHandlesOneByteReadsAndCoalescedFrames() throws {
        let frame = try CastFramer.frame(ping)
        var byteFramer = CastFramer()
        var messages: [CastMessage] = []
        for byte in frame {
            let next = try byteFramer.append(Data([byte]))
            messages.append(contentsOf: next)
        }
        #expect(messages == [ping])

        var framer = CastFramer()
        let first = try framer.append(frame + frame + frame.prefix(7))
        #expect(first == [ping, ping])
        let second = try framer.append(Data(frame.dropFirst(7)))
        #expect(second == [ping])
    }

    @Test func framingRejectsZeroAndOversizeLengthsAtTheHeader() throws {
        for header in ["00000000", "00010001", "ffffffff"] {
            var framer = CastFramer()
            let error = capturedCastError { _ = try framer.append(hex(header)) }
            #expect(error == (header == "00000000" ? .invalidMessage : .frameTooLarge))
            let recovered = try framer.append(CastFramer.frame(ping))
            #expect(recovered == [ping])
        }
    }

    @Test func framingAcceptsExactlyMaximumAndRejectsLargerMessages() throws {
        var message = CastMessage(
            sourceID: "s", destinationID: "d", namespace: "n", payloadType: .binary,
            payloadBinary: Data(repeating: 0, count: 65_519)
        )
        let frame = try CastFramer.frame(message)
        #expect(frame.count == 65_540)
        #expect(Data(frame.prefix(4)) == hex("00010000"))
        var framer = CastFramer()
        let decoded = try framer.append(frame)
        #expect(decoded == [message])
        message.payloadBinary?.append(0)
        #expect(throws: CastError.frameTooLarge) { try CastFramer.frame(message) }
        #expect(throws: CastError.frameTooLarge) { try CastMessage(data: Data(repeating: 0, count: 65_537)) }
    }

    @Test func framingRejectsMalformedMessageBody() throws {
        var framer = CastFramer()
        let error = capturedCastError { _ = try framer.append(hex("00000001 00")) }
        #expect(error == .invalidMessage)
        let recovered = try framer.append(CastFramer.frame(ping))
        #expect(recovered == [ping])
    }

    @Test func authResponseDefaultsAndRequiredFields() throws {
        let response = try CastDeviceAuthWire.response(from: hex("1206 0a0101 120102"))
        #expect(response == CastAuthResponse(
            signature: Data([1]), deviceCertificate: Data([2]), intermediateCertificates: [],
            signatureAlgorithm: .rsassaPKCS1v15, hashAlgorithm: .sha1
        ))
        for missing in ["", "0a00", "1200", "12030a0101", "1203120102"] {
            #expect(throws: CastError.authenticationFailed) { try CastDeviceAuthWire.response(from: hex(missing)) }
        }
    }

    @Test func authResponseDecodesEveryField() throws {
        let response = try CastDeviceAuthWire.response(from: authEnvelope(hex("""
            0a020102 12020304 1a0105 1a020607 2002 2a020809 3001 3a020a0b
            """)))
        #expect(response == CastAuthResponse(
            signature: Data([1, 2]), deviceCertificate: Data([3, 4]),
            intermediateCertificates: [Data([5]), Data([6, 7])],
            signatureAlgorithm: .rsassaPSS, hashAlgorithm: .sha256,
            senderNonce: Data([8, 9]), crl: Data([10, 11])
        ))
    }

    @Test func authResponseSkipsUnknownFieldsAndUsesLastSingularValues() throws {
        let fields = hex("""
            0a0101 120102 0a0103 120104 1a0105 1a0106 2001 2000
            2a0107 2a0108 3001 3000 3a0109 3a010a
            5001 590102030405060708 6203616263 6d01020304
            """)
        let data = hex("0a00 5001") + hex("1206 0a010b 12010c") + authEnvelope(fields) + hex("5501020304")
        let response = try CastDeviceAuthWire.response(from: data)
        #expect(response == CastAuthResponse(
            signature: Data([3]), deviceCertificate: Data([4]),
            intermediateCertificates: [Data([5]), Data([6])],
            signatureAlgorithm: .unspecified, hashAlgorithm: .sha1,
            senderNonce: Data([8]), crl: Data([10])
        ))
    }

    @Test(arguments: ["00", "0b", "0c", "0e", "0f", "08", "0a03ff", "2003", "3002", "5080", "5100", "5203ff", "5500", "2080808080808080808002"])
    func malformedAuthResponseMapsToAuthenticationFailure(suffix: String) {
        let data = authEnvelope(hex("0a0101 120102") + hex(suffix))
        #expect(throws: CastError.authenticationFailed) { try CastDeviceAuthWire.response(from: data) }
    }

    @Test(arguments: ["1a00", "1a020800", "1a020801", "1a020802", "1a01ff"])
    func anyAuthErrorRejectsEvenAValidResponse(error: String) {
        let response = hex("1206 0a0101 120102")
        #expect(throws: CastError.authenticationFailed) { try CastDeviceAuthWire.response(from: response + hex(error)) }
        #expect(throws: CastError.authenticationFailed) { try CastDeviceAuthWire.response(from: hex(error) + response) }
    }

    @Test func malformedAuthEnvelopeMapsToAuthenticationFailure() {
        for data in [hex("12ff"), hex("1207 0a0101 120102"), hex("1001"), hex("5080"), Data(repeating: 0, count: 65_537)] {
            #expect(throws: CastError.authenticationFailed) { try CastDeviceAuthWire.response(from: data) }
        }
        for count in [0, 15, 17] {
            #expect(throws: CastError.authenticationFailed) {
                try CastDeviceAuthWire.challenge(nonce: Data(repeating: 0, count: count))
            }
        }
    }

    private func authEnvelope(_ response: Data) -> Data {
        precondition(response.count < 128)
        return Data([0x12, UInt8(response.count)]) + response
    }

    private func capturedCastError(_ body: () throws -> Void) -> CastError? {
        do {
            try body()
            return nil
        } catch let error as CastError {
            return error
        } catch {
            Issue.record("Unexpected error: \(error)")
            return nil
        }
    }

    private func hex(_ value: String) -> Data {
        let digits = value.filter { !$0.isWhitespace }
        precondition(digits.count.isMultiple(of: 2))
        var bytes = Data()
        var index = digits.startIndex
        while index != digits.endIndex {
            let end = digits.index(index, offsetBy: 2)
            bytes.append(UInt8(digits[index..<end], radix: 16)!)
            index = end
        }
        return bytes
    }
}
