import Foundation
import Network

/// A resolved Bonjour receiver. A group's identity is independent of its current leader.
public struct CastDevice: Sendable, Equatable, Identifiable {
    /// Stable mDNS identity; a group ID differs from its leader's certificate identity.
    public let id: String
    /// The UTF-8 friendly name advertised as fn.
    public let name: String
    /// The advertised model, or an empty string when absent.
    public let model: String
    /// The resolved host, including an IPv6 scope when required.
    public let host: String
    /// The resolved SRV port, which may differ from 8009 for groups.
    public let port: UInt16
    /// Whether the endpoint advertises multizone capability or a group port.
    public let isGroup: Bool
    /// Capability bit zero, also supplied to device authentication.
    public let advertisesVideoOutput: Bool
    /// The advertised capability mask, including unknown bits.
    public let capabilities: UInt64
    /// Running-app text advertised as rs.
    public let runningAppStatus: String?
    /// The discovery protocol version advertised as ve.
    public let protocolVersion: Int?
    /// The discovery activity status advertised as st (zero idle, one busy).
    public let status: Int?
    /// The device-relative icon path advertised as ic.
    public let iconPath: String?

    /// Creates a resolved device, preserving its advertised port.
    public init(
        id: String, name: String, model: String, host: String, port: UInt16,
        isGroup: Bool = false, advertisesVideoOutput: Bool = false,
        capabilities: UInt64 = 0, runningAppStatus: String? = nil,
        protocolVersion: Int? = nil, status: Int? = nil, iconPath: String? = nil
    ) {
        self.id = id
        self.name = name
        self.model = model
        self.host = host
        self.port = port
        self.isGroup = isGroup
        self.advertisesVideoOutput = advertisesVideoOutput
        self.capabilities = capabilities
        self.runningAppStatus = runningAppStatus
        self.protocolVersion = protocolVersion
        self.status = status
        self.iconPath = iconPath
    }

    init?(txt: [String: String], host: String, port: UInt16) {
        guard let id = txt["id"], !id.isEmpty, let name = txt["fn"], !name.isEmpty,
              port != 0 else { return nil }
        let capabilities = UInt64(txt["ca"] ?? "") ?? 0
        self.init(
            id: id, name: name, model: txt["md"] ?? "", host: host, port: port,
            isGroup: port != 8009 || capabilities & 32 != 0,
            advertisesVideoOutput: capabilities & 1 != 0, capabilities: capabilities,
            runningAppStatus: txt["rs"], protocolVersion: txt["ve"].flatMap(Int.init),
            status: txt["st"].flatMap(Int.init), iconPath: txt["ic"]
        )
    }
}

/// Browses only between explicit start and stop calls.
public actor CastDiscovery {
    private let queue = DispatchQueue(label: "castkit.discovery")
    private var browser: NWBrowser?
    private var generation = UUID()
    private var resolutions: [NWEndpoint: NWConnection] = [:]
    private var expiryTasks: [NWEndpoint: Task<Void, Never>] = [:]
    private var records: [NWEndpoint: CastDevice] = [:]
    private var results: [NWEndpoint: NWBrowser.Result] = [:]
    private var observers: [UUID: AsyncStream<[CastDevice]>.Continuation] = [:]

    /// Creates an idle browser; call start only while device discovery is requested.
    public init() {}

    deinit {
        browser?.cancel()
        for connection in resolutions.values { connection.cancel() }
        for task in expiryTasks.values { task.cancel() }
        for observer in observers.values { observer.finish() }
    }

    /// Each subscriber receives the current list, followed by discovery changes.
    public func devices() -> AsyncStream<[CastDevice]> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<[CastDevice]>.makeStream(bufferingPolicy: .bufferingNewest(1))
        observers[id] = continuation
        continuation.yield(snapshot)
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeObserver(id) }
        }
        return stream
    }

    /// Starts Bonjour browsing and resolves each service's actual host and port.
    public func start() {
        guard browser == nil else { return }
        let token = UUID()
        generation = token
        let browser = NWBrowser(
            for: .bonjourWithTXTRecord(type: "_googlecast._tcp", domain: "local."), using: .tcp
        )
        self.browser = browser
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            Task { await self?.update(results, generation: token) }
        }
        browser.stateUpdateHandler = { [weak self] state in
            if case .failed = state {
                Task { await self?.failed(generation: token) }
            }
        }
        browser.start(queue: queue)
    }

    /// Stops browsing and cancels outstanding resolutions, without keeping LAN activity alive.
    public func stop() {
        generation = UUID()
        browser?.cancel()
        browser = nil
        for connection in resolutions.values { connection.cancel() }
        for task in expiryTasks.values { task.cancel() }
        resolutions.removeAll()
        expiryTasks.removeAll()
        results.removeAll()
        records.removeAll()
        publish()
    }

    /// Re-resolves current services after a failed connection instead of reusing an old group leader.
    public func refresh() {
        guard browser != nil else { return }
        stop()
        start()
    }

    private var snapshot: [CastDevice] {
        var unique: [String: CastDevice] = [:]
        for device in records.values { unique[device.id] = device }
        return unique.values.sorted { ($0.name, $0.id) < ($1.name, $1.id) }
    }

    private func removeObserver(_ id: UUID) { observers[id] = nil }
    private func publish() { for observer in observers.values { observer.yield(snapshot) } }
    private func failed(generation token: UUID) { if token == generation { stop() } }

    private func update(_ updated: Set<NWBrowser.Result>, generation token: UUID) {
        guard token == generation else { return }
        let endpoints = Set(updated.map(\.endpoint))
        for endpoint in Set(results.keys).subtracting(endpoints) {
            resolutions.removeValue(forKey: endpoint)?.cancel()
            expiryTasks.removeValue(forKey: endpoint)?.cancel()
            records[endpoint] = nil
            results[endpoint] = nil
        }
        for result in updated {
            guard case .service(_, let type, _, _) = result.endpoint,
                  type == "_googlecast._tcp" || type == "_googlecast._tcp." else { continue }
            guard results[result.endpoint] != result else { continue }
            results[result.endpoint] = result
            resolutions.removeValue(forKey: result.endpoint)?.cancel()
            expiryTasks.removeValue(forKey: result.endpoint)?.cancel()
            records[result.endpoint] = nil
            // A short TCP resolution exposes the selected SRV endpoint, including group ports.
            let connection = NWConnection(to: result.endpoint, using: .tcp)
            resolutions[result.endpoint] = connection
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready, .failed, .cancelled:
                    Task { await self?.resolved(result, state: state, generation: token) }
                default: break
                }
            }
            connection.start(queue: queue)
            expiryTasks[result.endpoint] = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(10)) } catch { return }
                await self?.expire(result.endpoint, generation: token)
            }
        }
        publish()
    }

    private func expire(_ endpoint: NWEndpoint, generation token: UUID) {
        guard token == generation else { return }
        resolutions.removeValue(forKey: endpoint)?.cancel()
        expiryTasks[endpoint] = nil
    }

    private func resolved(_ result: NWBrowser.Result, state: NWConnection.State, generation token: UUID) {
        guard token == generation, results[result.endpoint] == result,
              let connection = resolutions[result.endpoint] else { return }
        if case .ready = state,
           case .hostPort(let host, let port)? = connection.currentPath?.remoteEndpoint,
           case .bonjour(let txt) = result.metadata {
            records[result.endpoint] = CastDevice(txt: txt.dictionary, host: "\(host)", port: port.rawValue)
            publish()
        }
        resolutions[result.endpoint] = nil
        expiryTasks.removeValue(forKey: result.endpoint)?.cancel()
        connection.cancel()
    }
}
