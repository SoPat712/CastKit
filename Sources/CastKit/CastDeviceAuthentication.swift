import Foundation

// The contract between the Cast v2 connection (which runs the challenge) and device authentication (which
// decides whether a device is a genuine Cast device). Field numbers and enum values follow the protocol
// (see the CastKit research notes); keep them in sync with the wire format.

/// `AuthChallenge.signature_algorithm` / `AuthResponse.signature_algorithm`.
public enum CastSignatureAlgorithm: Int, Sendable, Equatable {
    case unspecified = 0
    case rsassaPKCS1v15 = 1
    case rsassaPSS = 2
}

/// `AuthChallenge.hash_algorithm` / `AuthResponse.hash_algorithm`. Absent on the wire means SHA-1.
public enum CastHashAlgorithm: Int, Sendable, Equatable {
    case sha1 = 0
    case sha256 = 1
}

/// A device's answer to the authentication challenge, decoded from `DeviceAuthMessage.response`.
public struct CastAuthResponse: Sendable, Equatable {
    /// RSA signature over the echoed nonce followed by the TLS certificate's DER.
    public var signature: Data
    /// The device (leaf) certificate, DER.
    public var deviceCertificate: Data
    /// Intermediate certificates, DER, in any order.
    public var intermediateCertificates: [Data]
    public var signatureAlgorithm: CastSignatureAlgorithm
    /// SHA-1 when the device left the field out.
    public var hashAlgorithm: CastHashAlgorithm
    /// The nonce as echoed by the device, or nil when it left it out.
    public var senderNonce: Data?
    /// A serialized `CrlBundle`, when the device sent one.
    public var crl: Data?

    public init(
        signature: Data, deviceCertificate: Data, intermediateCertificates: [Data],
        signatureAlgorithm: CastSignatureAlgorithm = .rsassaPKCS1v15, hashAlgorithm: CastHashAlgorithm = .sha1,
        senderNonce: Data? = nil, crl: Data? = nil
    ) {
        self.signature = signature
        self.deviceCertificate = deviceCertificate
        self.intermediateCertificates = intermediateCertificates
        self.signatureAlgorithm = signatureAlgorithm
        self.hashAlgorithm = hashAlgorithm
        self.senderNonce = senderNonce
        self.crl = crl
    }
}

/// What the connection knows when it asks for a verdict.
public struct CastAuthContext: Sendable, Equatable {
    /// The 16 random bytes the sender sent in the challenge.
    public var sentNonce: Data
    /// The exact DER of the certificate the device presented in the TLS handshake.
    public var tlsCertificate: Data
    /// Whether the device's discovery record advertises video output (`ca` capability bits).
    public var advertisesVideoOutput: Bool
    /// The verification time; tests pass a fixed date.
    public var now: Date

    public init(sentNonce: Data, tlsCertificate: Data, advertisesVideoOutput: Bool, now: Date = Date()) {
        self.sentNonce = sentNonce
        self.tlsCertificate = tlsCertificate
        self.advertisesVideoOutput = advertisesVideoOutput
        self.now = now
    }
}

/// A verified device.
public struct CastDeviceIdentity: Sendable, Equatable {
    /// The device certificate's common name.
    public var commonName: String
    /// The chain carries the audio-only policy.
    public var isAudioOnly: Bool

    public init(commonName: String, isAudioOnly: Bool) {
        self.commonName = commonName
        self.isAudioOnly = isAudioOnly
    }
}

/// Decides whether a device is a genuine Cast device. Any thrown error means: close the connection and
/// never send the device anything else (no stream URLs, no tokens).
public protocol CastDeviceAuthenticating: Sendable {
    func verify(_ response: CastAuthResponse, context: CastAuthContext) throws -> CastDeviceIdentity
}
