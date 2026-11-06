import Foundation

enum CastDERError: Error { case malformed }

struct CastDERNode {
    let tag: UInt8
    let value: Data
    let encoded: Data
    let children: [CastDERNode]

    func require(_ tag: UInt8, count: Int? = nil) throws {
        guard self.tag == tag, count == nil || children.count == count else { throw CastDERError.malformed }
    }

    var oid: String {
        get throws {
            try require(0x06)
            guard !value.isEmpty else { throw CastDERError.malformed }
            var components: [UInt64] = []
            var number: UInt64 = 0
            var first = true
            for byte in value {
                guard !(first && byte == 0x80), number <= (UInt64.max >> 7) else {
                    throw CastDERError.malformed
                }
                number = (number << 7) | UInt64(byte & 0x7f)
                first = byte & 0x80 == 0
                if first { components.append(number); number = 0 }
            }
            guard first, let head = components.first else { throw CastDERError.malformed }
            let prefix: [UInt64] = head < 40 ? [0, head] : head < 80 ? [1, head - 40] : [2, head - 80]
            return (prefix + components.dropFirst()).map(String.init).joined(separator: ".")
        }
    }

    var unsignedInteger: UInt64? {
        guard tag == 0x02, let first = value.first, first & 0x80 == 0 else { return nil }
        let bytes = first == 0 ? value.dropFirst() : value[...]
        guard bytes.count <= 8 else { return nil }
        return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    var string: String? {
        switch tag {
        case 0x0c: String(data: value, encoding: .utf8)
        case 0x12, 0x13, 0x16: String(data: value, encoding: .ascii)
        case 0x14: String(data: value, encoding: .isoLatin1)
        case 0x1e: String(data: value, encoding: .utf16BigEndian)
        case 0x1c: String(data: value, encoding: .utf32BigEndian)
        default: nil
        }
    }

    var date: Date {
        get throws {
            guard tag == 0x17 || tag == 0x18,
                  let text = String(data: value, encoding: .ascii), text.last == "Z",
                  text.count == (tag == 0x17 ? 13 : 15),
                  text.dropLast().allSatisfy({ $0.isASCII && $0.isNumber }) else {
                throw CastDERError.malformed
            }
            let digits = Array(text.dropLast())
            let yearLength = tag == 0x17 ? 2 : 4
            func number(_ start: Int, _ count: Int = 2) -> Int { Int(String(digits[start..<(start + count)]))! }
            var year = number(0, yearLength)
            if yearLength == 2 { year += year >= 50 ? 1900 : 2000 }
            let parts = DateComponents(
                year: year, month: number(yearLength), day: number(yearLength + 2),
                hour: number(yearLength + 4), minute: number(yearLength + 6), second: number(yearLength + 8)
            )
            var calendar = Calendar(identifier: .gregorian)
            calendar.timeZone = TimeZone(secondsFromGMT: 0)!
            guard let result = calendar.date(from: parts) else { throw CastDERError.malformed }
            let actual = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: result)
            guard actual.year == parts.year, actual.month == parts.month, actual.day == parts.day,
                  actual.hour == parts.hour, actual.minute == parts.minute, actual.second == parts.second else {
                throw CastDERError.malformed
            }
            return result
        }
    }
}

enum CastDER {
    static func encode(_ tag: UInt8, _ value: Data) -> Data {
        var length = value.count
        var encodedLength = Data()
        if length < 128 { encodedLength.append(UInt8(length)) }
        else {
            while length > 0 {
                encodedLength.insert(UInt8(length & 0xff), at: 0)
                length >>= 8
            }
            encodedLength.insert(0x80 | UInt8(encodedLength.count), at: 0)
        }
        return Data([tag]) + encodedLength + value
    }

    static func parse(_ data: Data) throws -> CastDERNode {
        guard !data.isEmpty, data.count <= 65_536 else { throw CastDERError.malformed }
        let bytes = [UInt8](data)
        var offset = 0
        var budget = 8_192
        let node = try read(bytes, offset: &offset, end: bytes.count, depth: 0, budget: &budget)
        guard offset == bytes.count else { throw CastDERError.malformed }
        return node
    }

    private static func read(
        _ bytes: [UInt8], offset: inout Int, end: Int, depth: Int, budget: inout Int
    ) throws -> CastDERNode {
        guard depth < 32, budget > 0, end - offset >= 2 else { throw CastDERError.malformed }
        budget -= 1
        let start = offset
        let tag = bytes[offset]
        offset += 1
        guard tag & 0x1f != 0x1f, tag != 0 else { throw CastDERError.malformed }
        let firstLength = bytes[offset]
        offset += 1
        var length = Int(firstLength)
        if firstLength & 0x80 != 0 {
            let count = Int(firstLength & 0x7f)
            guard count > 0, count <= 3, count <= end - offset, bytes[offset] != 0 else {
                throw CastDERError.malformed
            }
            length = 0
            for _ in 0..<count { length = (length << 8) | Int(bytes[offset]); offset += 1 }
            guard length >= 128 else { throw CastDERError.malformed }
        }
        guard length <= end - offset else { throw CastDERError.malformed }
        let valueStart = offset
        let valueEnd = offset + length
        var children: [CastDERNode] = []
        if tag & 0x20 != 0 {
            while offset < valueEnd {
                children.append(try read(bytes, offset: &offset, end: valueEnd, depth: depth + 1, budget: &budget))
            }
            if tag == 0x31 {
                for pair in zip(children, children.dropFirst()) {
                    guard !pair.1.encoded.lexicographicallyPrecedes(pair.0.encoded) else { throw CastDERError.malformed }
                }
            }
        } else {
            offset = valueEnd
        }
        let value = Data(bytes[valueStart..<valueEnd])
        if tag & 0xc0 == 0 {
            switch tag {
            case 0x01:
                guard value == Data([0]) || value == Data([0xff]) else { throw CastDERError.malformed }
            case 0x02:
                guard !value.isEmpty else { throw CastDERError.malformed }
                if value.count > 1 {
                    let first = value[value.startIndex], second = value[value.startIndex + 1]
                    guard !(first == 0 && second & 0x80 == 0), !(first == 0xff && second & 0x80 != 0) else {
                        throw CastDERError.malformed
                    }
                }
            case 0x03:
                guard let unused = value.first, unused <= 7, value.count > 1 || unused == 0 else {
                    throw CastDERError.malformed
                }
                if unused > 0, let last = value.last {
                    guard last & UInt8((1 << unused) - 1) == 0 else { throw CastDERError.malformed }
                }
            case 0x05:
                guard value.isEmpty else { throw CastDERError.malformed }
            case 0x10, 0x11: throw CastDERError.malformed
            default: break
            }
        }
        let node = CastDERNode(tag: tag, value: value, encoded: Data(bytes[start..<valueEnd]), children: children)
        if tag == 0x06 { _ = try node.oid }
        return node
    }
}
