import Foundation
import Security

enum CastNamespace {
    static let authentication = "urn:x-cast:com.google.cast.tp.deviceauth"
    static let connection = "urn:x-cast:com.google.cast.tp.connection"
    static let heartbeat = "urn:x-cast:com.google.cast.tp.heartbeat"
    static let receiver = "urn:x-cast:com.google.cast.receiver"
    static let media = "urn:x-cast:com.google.cast.media"
}

/// An authenticated, framed Cast connection. A channel is used for one connection attempt.
public actor CastChannel {
    /// The single-consumer stream of messages received after authentication succeeds.
    public nonisolated let messages: AsyncThrowingStream<CastMessage, any Error>
    private let continuation: AsyncThrowingStream<CastMessage, any Error>.Continuation
    private let device: CastDevice
    private let transport: any CastTransport
    private let authenticator: any CastDeviceAuthenticating
    private var framer = CastFramer()
    private var reader: Task<Void, Never>?
    private var started = false
    private var authenticated = false
    private var closed = false

    /// Uses the real TLS transport unless an in-memory byte stream is supplied.
    public init(device: CastDevice, authenticator: any CastDeviceAuthenticating, transport: (any CastTransport)? = nil) {
        self.device = device
        self.authenticator = authenticator
        self.transport = transport ?? CastNetworkTransport(device: device)
        let pair = AsyncThrowingStream<CastMessage, any Error>.makeStream()
        messages = pair.stream
        continuation = pair.continuation
    }

    deinit {
        reader?.cancel()
        continuation.finish()
        let transport = transport
        Task { await transport.close() }
    }

    /// Completes TLS and device authentication within ten seconds before permitting other traffic.
    @discardableResult
    public func connect() async throws -> CastDeviceIdentity {
        try await connect(timeout: .seconds(10))
    }

    func connect(timeout: Duration) async throws -> CastDeviceIdentity {
        guard !started, !closed else { throw CastError.invalidState }
        started = true
        do {
            let identity = try await withThrowingTaskGroup(of: CastDeviceIdentity.self) { group in
                group.addTask { try await self.authenticate() }
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw CastError.timedOut
                }
                defer { group.cancelAll() }
                do {
                    guard let result = try await group.next() else { throw CastError.connectionClosed }
                    return result
                } catch {
                    await transport.close()
                    throw error
                }
            }
            guard !closed else { throw CastError.connectionClosed }
            authenticated = true
            reader = Task { [weak self, transport] in
                do {
                    while !Task.isCancelled, let bytes = try await transport.read() {
                        guard let self else { await transport.close(); return }
                        try await self.received(bytes)
                    }
                    await self?.finish(error: CastError.connectionClosed)
                } catch {
                    await self?.finish(error: error)
                }
            }
            return identity
        } catch {
            await finish(error: error)
            throw error
        }
    }

    /// Writes an application message only after authentication has passed.
    public func send(_ message: CastMessage) async throws {
        guard authenticated, !closed else { throw CastError.invalidState }
        do { try await transport.write(CastFramer.frame(message)) }
        catch {
            await finish(error: error)
            throw error
        }
    }

    /// Closes the byte stream and finishes message delivery.
    public func close() async { await finish(error: nil) }

    private func authenticate() async throws -> CastDeviceIdentity {
        let certificate = try await transport.open()
        do {
            var nonce = Data(count: 16)
            let result = nonce.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!)
            }
            guard result == errSecSuccess, !certificate.isEmpty else { throw CastError.authenticationFailed }
            let challenge = CastMessage(
                sourceID: "sender-0", destinationID: "receiver-0", namespace: CastNamespace.authentication,
                payloadType: .binary, payloadBinary: try CastDeviceAuthWire.challenge(nonce: nonce)
            )
            try await transport.write(CastFramer.frame(challenge))
            while let bytes = try await transport.read() {
                let messages = try framer.append(bytes)
                guard let message = messages.first else { continue }
                guard message.sourceID == "receiver-0",
                      message.destinationID == "sender-0" || message.destinationID == "*",
                      message.namespace == CastNamespace.authentication, message.payloadType == .binary,
                      let payload = message.payloadBinary else { throw CastError.authenticationFailed }
                let response = try CastDeviceAuthWire.response(from: payload)
                let identity = try authenticator.verify(response, context: CastAuthContext(
                    sentNonce: nonce, tlsCertificate: certificate,
                    advertisesVideoOutput: device.advertisesVideoOutput
                ))
                for buffered in messages.dropFirst() { continuation.yield(buffered) }
                return identity
            }
            throw CastError.authenticationFailed
        } catch {
            throw CastError.authenticationFailed
        }
    }

    private func received(_ bytes: Data) throws {
        guard !closed else { return }
        for message in try framer.append(bytes) { continuation.yield(message) }
    }

    private func finish(error: (any Error)?) async {
        guard !closed else { return }
        closed = true
        authenticated = false
        reader?.cancel()
        reader = nil
        continuation.finish(throwing: error)
        await transport.close()
    }
}
