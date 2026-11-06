import Foundation

// SecTrust performs RFC 5280 validation; these checks also enforce constraints on the custom anchor.
enum CastPathConstraints {
    private struct Name {
        var tag: UInt8
        var bytes: Data
        var directory: [[String]]?
    }

    static func validateNames(_ path: [CastCertificate]) throws {
        let names = try path.map { certificate -> [Name] in
            var names = [Name(tag: 0xa4, bytes: Data(), directory: try directory(certificate.subject))]
            if let san = try certificate.extensionNode("2.5.29.17") {
                try san.require(0x30)
                guard !san.children.isEmpty else { throw CastDERError.malformed }
                names += try san.children.map { try name($0, constraint: false) }
            } else {
                for rdn in certificate.subject.children {
                    for attribute in rdn.children where try attribute.children[0].oid == "1.2.840.113549.1.9.1" {
                        guard let email = attribute.children[1].string else { throw CastDERError.malformed }
                        names.append(Name(tag: 0x81, bytes: Data(email.utf8)))
                    }
                }
            }
            return names
        }
        for (issuerIndex, certificate) in path.enumerated() {
            guard let constraints = try certificate.extensionNode("2.5.29.30") else { continue }
            try constraints.require(0x30)
            guard !constraints.children.isEmpty else { throw CastDERError.malformed }
            var permitted: [Name] = [], excluded: [Name] = []
            var last: UInt8 = 0x9f
            for group in constraints.children {
                guard (group.tag == 0xa0 || group.tag == 0xa1), group.tag > last,
                      !group.children.isEmpty else { throw CastDERError.malformed }
                last = group.tag
                for subtree in group.children {
                    try subtree.require(0x30)
                    // Nonzero minimum or any maximum has no supported RFC 5280 semantics here.
                    guard subtree.children.count == 1 else { throw CastAuthError.invalidNameConstraints }
                    let base = try name(subtree.children[0], constraint: true)
                    if group.tag == 0xa0 { permitted.append(base) } else { excluded.append(base) }
                }
            }
            for childIndex in 0..<issuerIndex {
                let child = path[childIndex]
                if childIndex != 0, child.issuer == child.normalizedSubject { continue }
                for candidate in names[childIndex] {
                    if try excluded.contains(where: { try matches(candidate, $0) }) {
                        throw CastAuthError.invalidNameConstraints
                    }
                    let applicable = permitted.filter { $0.tag == candidate.tag }
                    if !applicable.isEmpty, !(try applicable.contains(where: { try matches(candidate, $0) })) {
                        throw CastAuthError.invalidNameConstraints
                    }
                }
            }
        }
    }

    private static func name(_ node: CastDERNode, constraint: Bool) throws -> Name {
        switch node.tag {
        case 0xa4:
            guard node.children.count == 1 else { throw CastDERError.malformed }
            return Name(tag: node.tag, bytes: Data(), directory: try directory(node.children[0]))
        case 0x81, 0x82, 0x86:
            guard let text = String(data: node.value, encoding: .ascii), !text.isEmpty,
                  !node.value.contains(0) else { throw CastDERError.malformed }
        case 0x87:
            guard (constraint ? [8, 32] : [4, 16]).contains(node.value.count) else { throw CastDERError.malformed }
        case 0xa0, 0xa3, 0xa5, 0x88:
            // Unconstrained SAN types are left to SecTrust. Constraints of these types fail closed.
            guard !constraint else { throw CastAuthError.invalidNameConstraints }
        default: throw CastDERError.malformed
        }
        return Name(tag: node.tag, bytes: node.value)
    }

    private static func directory(_ node: CastDERNode) throws -> [[String]] {
        try node.require(0x30)
        return try node.children.map { rdn in
            try rdn.require(0x31)
            guard !rdn.children.isEmpty else { throw CastDERError.malformed }
            return try rdn.children.map { attribute in
                try attribute.require(0x30, count: 2)
                guard let value = attribute.children[1].string else { throw CastDERError.malformed }
                let normalized = value.precomposedStringWithCanonicalMapping
                    .folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
                    .split(whereSeparator: \.isWhitespace).joined(separator: " ")
                return try attribute.children[0].oid + "=" + normalized
            }.sorted()
        }
    }

    private static func matches(_ name: Name, _ constraint: Name) throws -> Bool {
        guard name.tag == constraint.tag else { return false }
        if name.tag == 0xa4 {
            guard let subject = name.directory, let base = constraint.directory else { throw CastDERError.malformed }
            return subject.count >= base.count && Array(subject.prefix(base.count)) == base
        }
        if name.tag == 0x87 {
            let address = [UInt8](name.bytes), base = [UInt8](constraint.bytes)
            guard base.count == address.count * 2 else { return false }
            return address.indices.allSatisfy {
                (address[$0] & base[$0 + address.count]) == (base[$0] & base[$0 + address.count])
            }
        }
        guard let candidate = String(data: name.bytes, encoding: .ascii)?.lowercased(),
              let base = String(data: constraint.bytes, encoding: .ascii)?.lowercased() else {
            throw CastAuthError.invalidNameConstraints
        }
        func domain(_ host: String, _ base: String, subdomains: Bool) -> Bool {
            if base.hasPrefix(".") { return host.hasSuffix(base) && host.count > base.count }
            return host == base || (subdomains && host.hasSuffix("." + base))
        }
        switch name.tag {
        case 0x82: return domain(candidate, base, subdomains: true)
        case 0x81:
            if base.contains("@") { return candidate == base }
            guard let host = candidate.split(separator: "@", omittingEmptySubsequences: false).last,
                  candidate.filter({ $0 == "@" }).count == 1 else { throw CastAuthError.invalidNameConstraints }
            return domain(String(host), base, subdomains: false)
        case 0x86:
            guard let host = URLComponents(string: candidate)?.host, !host.isEmpty else {
                throw CastAuthError.invalidNameConstraints
            }
            return domain(host, base, subdomains: false)
        default: throw CastAuthError.invalidNameConstraints
        }
    }

    static func validatePolicies(_ path: [CastCertificate]) throws {
        let anyPolicy = "2.5.29.32.0"
        // A node's expected set retains separate branches when policy mappings change an OID.
        var expected: [Set<String>] = [[anyPolicy]]
        var explicit = path.count + 1
        var mapping = path.count + 1
        var inhibitAny = path.count + 1
        for (index, certificate) in path.enumerated().reversed() {
            let isAnchor = index == path.count - 1
            let isLeaf = index == 0
            let selfIssued = certificate.issuer == certificate.normalizedSubject
            let policies = try certificate.policies()
            if !isAnchor {
                if let policies {
                    var next: [Set<String>] = []
                    let allowAny = policies.contains(anyPolicy) && (inhibitAny > 0 || (selfIssued && !isLeaf))
                    for branch in expected {
                        if branch.contains(anyPolicy) {
                            let concrete = policies.subtracting([anyPolicy])
                            next += concrete.map { Set([$0]) }
                            if allowAny { next.append([anyPolicy]) }
                        } else {
                            for oid in branch where policies.contains(oid) || allowAny { next.append([oid]) }
                        }
                    }
                    expected = next
                } else { expected = [] }
                if !selfIssued || isLeaf {
                    explicit = max(0, explicit - 1)
                    mapping = max(0, mapping - 1)
                    inhibitAny = max(0, inhibitAny - 1)
                }
            }
            if let mappings = try certificate.extensionNode("2.5.29.33") {
                try mappings.require(0x30)
                guard !mappings.children.isEmpty else { throw CastDERError.malformed }
                var table: [String: Set<String>] = [:]
                for pair in mappings.children {
                    try pair.require(0x30, count: 2)
                    let from = try pair.children[0].oid, to = try pair.children[1].oid
                    guard from != anyPolicy, to != anyPolicy else { throw CastAuthError.invalidCertificatePolicy }
                    table[from, default: []].insert(to)
                }
                if !isLeaf {
                    expected = expected.compactMap { branch in
                        guard let oid = branch.first, let mapped = table[oid] else { return branch }
                        return mapping > 0 ? mapped : nil
                    }
                }
            }
            if let constraints = try certificate.extensionNode("2.5.29.36") {
                try constraints.require(0x30)
                guard !constraints.children.isEmpty else { throw CastDERError.malformed }
                var previous: UInt8 = 0x7f
                for field in constraints.children {
                    guard field.tag > previous, field.tag == 0x80 || field.tag == 0x81 else { throw CastDERError.malformed }
                    previous = field.tag
                    let value = try constraintInteger(field)
                    if field.tag == 0x80 { explicit = min(explicit, value) } else { mapping = min(mapping, value) }
                }
            }
            if let inhibit = try certificate.extensionNode("2.5.29.54") {
                guard let value = inhibit.unsignedInteger else { throw CastDERError.malformed }
                inhibitAny = min(inhibitAny, Int(clamping: value))
            }
            guard explicit > 0 || !expected.isEmpty else { throw CastAuthError.invalidCertificatePolicy }
        }
    }

    private static func constraintInteger(_ node: CastDERNode) throws -> Int {
        let bytes = [UInt8](node.value)
        guard let first = bytes.first, first & 0x80 == 0,
              bytes.count == 1 || first != 0 || bytes[1] & 0x80 != 0 else { throw CastDERError.malformed }
        if bytes.count > 8 { return Int.max }
        return Int(clamping: bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
    }
}
