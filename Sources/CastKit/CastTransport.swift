import Foundation
import Network
import Security

/// The encrypted byte stream used by a channel. Only one read is in flight at a time.
public protocol CastTransport: Sendable {
    /// Opens the stream and returns the exact TLS peer leaf certificate DER.
    func open() async throws -> Data
    /// Reads bytes, or returns nil when the peer closes the stream.
    func read() async throws -> Data?
    /// Writes all bytes in order.
    func write(_ data: Data) async throws
    /// Closes the stream and unblocks pending operations.
    func close() async
}

// NSLock guards the DER shared between the TLS verification queue and the transport actor.
private final class CastPeerCertificate: @unchecked Sendable {
    private let lock = NSLock()
    private var certificate: Data?

    func store(_ data: Data) { lock.withLock { certificate = data } }
    func load() -> Data? { lock.withLock { certificate } }
}

/// Network.framework's TLS transport. Device authentication supplies trust after the handshake.
public actor CastNetworkTransport: CastTransport {
    private let connection: NWConnection
    private let certificate: CastPeerCertificate
    private let validEndpoint: Bool
    private let queue = DispatchQueue(label: "castkit.transport")
    private var opening: CheckedContinuation<Data, any Error>?
    private var reading: CheckedContinuation<Data?, any Error>?
    private var writes: [UUID: CheckedContinuation<Void, any Error>] = [:]
    private var started = false
    private var closed = false
    private var ready = false
    private var endOfStream = false

    /// Creates TLS 1.2 or later to the resolved port, including speaker-group ports.
    public init(device: CastDevice) {
        let tls = NWProtocolTLS.Options()
        let certificate = CastPeerCertificate()
        self.certificate = certificate
        validEndpoint = device.port != 0 && !device.host.isEmpty
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            let peerTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            guard let chain = SecTrustCopyCertificateChain(peerTrust) as? [SecCertificate],
                  let leaf = chain.first else {
                complete(false)
                return
            }
            certificate.store(SecCertificateCopyData(leaf) as Data)
            // This accepts the handshake only; no application traffic is allowed before device auth.
            complete(true)
        }, DispatchQueue(label: "castkit.tls"))
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        connection = NWConnection(
            host: NWEndpoint.Host(device.host), port: NWEndpoint.Port(rawValue: device.port) ?? .any, using: parameters
        )
    }

    /// Performs the TLS handshake and captures its peer certificate without granting device trust.
    public func open() async throws -> Data {
        guard validEndpoint else { throw CastError.invalidArgument }
        guard !started, !closed else { throw CastError.invalidState }
        started = true
        return try await withCheckedThrowingContinuation { continuation in
            opening = continuation
            connection.stateUpdateHandler = { [weak self] state in
                Task { await self?.stateChanged(state) }
            }
            connection.start(queue: queue)
        }
    }

    /// Reads a bounded chunk from the TLS byte stream.
    public func read() async throws -> Data? {
        guard ready, !closed else { throw CastError.connectionClosed }
        if endOfStream { return nil }
        guard reading == nil else { throw CastError.invalidState }
        return try await withCheckedThrowingContinuation { continuation in
            reading = continuation
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_540) { [weak self] data, _, complete, error in
                Task { await self?.received(data, complete: complete, error: error) }
            }
        }
    }

    /// Writes bytes in stream order, completing when Network.framework processes them.
    public func write(_ data: Data) async throws {
        guard ready, !closed else { throw CastError.connectionClosed }
        let id = UUID()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            writes[id] = continuation
            connection.send(content: data, completion: .contentProcessed { [weak self] error in
                Task { await self?.sent(id, error: error) }
            })
        }
    }

    /// Cancels the socket and resumes outstanding operations with a closed error.
    public func close() {
        fail(CastError.connectionClosed)
    }

    private func stateChanged(_ state: NWConnection.State) {
        guard !closed else { return }
        switch state {
        case .ready:
            guard let der = certificate.load(), !der.isEmpty else {
                fail(CastError.authenticationFailed)
                return
            }
            ready = true
            let continuation = opening
            opening = nil
            continuation?.resume(returning: der)
        case .failed: fail(CastError.connectionFailed)
        case .cancelled: fail(CastError.connectionClosed)
        // Network.framework retries a refused or unreachable endpoint indefinitely; a cast attempt fails now.
        case .waiting where !ready: fail(CastError.connectionFailed)
        default: break
        }
    }

    private func received(_ data: Data?, complete: Bool, error: NWError?) {
        let continuation = reading
        reading = nil
        if error != nil {
            continuation?.resume(throwing: CastError.connectionFailed)
            fail(CastError.connectionFailed)
        } else if let data, !data.isEmpty {
            endOfStream = complete
            continuation?.resume(returning: data)
        } else if complete {
            continuation?.resume(returning: nil)
            fail(CastError.connectionClosed)
        } else {
            continuation?.resume(throwing: CastError.connectionClosed)
            fail(CastError.connectionClosed)
        }
    }

    private func sent(_ id: UUID, error: NWError?) {
        guard let continuation = writes.removeValue(forKey: id) else { return }
        if error != nil {
            continuation.resume(throwing: CastError.connectionFailed)
            fail(CastError.connectionFailed)
        } else {
            continuation.resume()
        }
    }

    private func fail(_ error: CastError) {
        guard !closed else { return }
        closed = true
        ready = false
        connection.cancel()
        opening?.resume(throwing: error)
        opening = nil
        reading?.resume(throwing: error)
        reading = nil
        for continuation in writes.values { continuation.resume(throwing: error) }
        writes.removeAll()
    }
}
