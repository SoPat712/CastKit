import Foundation

struct CastSessionTiming: Sendable {
    var heartbeatInterval: Duration = .seconds(5)
    var silenceTimeout: Duration = .seconds(15)
    var requestTimeout: Duration = .seconds(5)
    var launchTimeout: Duration = .seconds(120)
}

/// Owns the platform and media virtual connections of one authenticated Cast session.
public actor CastSession {
    /// Google's Default Media Receiver application ID.
    public static let defaultMediaReceiverID = "CC1AD845"
    /// Preserve this ID when creating a replacement session after reconnecting to the same app.
    public nonisolated let senderID: String
    private let userAgent: String
    /// The current lifecycle state, also delivered by states().
    public private(set) var state: CastSessionState = .disconnected
    /// The identity returned by the injected device authenticator.
    public private(set) var identity: CastDeviceIdentity?
    /// The most recent platform status, including unsolicited broadcasts.
    public private(set) var receiverStatus: CastReceiverStatus?
    /// The most recent media status, or nil when no media session exists.
    public private(set) var mediaStatus: CastMediaStatus?

    private struct Pending {
        let namespace: String
        let source: String
        let type: String
        let continuation: CheckedContinuation<CastJSON, any Error>
        let timeout: Task<Void, Never>
    }

    private let channel: CastChannel
    private let timing: CastSessionTiming
    private var nextRequestID = Int.random(in: 1...1_000_000)
    private var pending: [Int: Pending] = [:]
    private var app: CastApplication?
    private var ownedMediaID: Int?
    private var mediaCache: [Int: CastMedia] = [:]
    private var queueCache: [Int: [Int: CastQueueItemStatus]] = [:]
    private var ownsQueue = false
    private var listener: Task<Void, Never>?
    private var heartbeat: Task<Void, Never>?
    private var lastInbound = ContinuousClock.now
    private var active = false
    private var closing = false
    private var terminated = false
    private var receiverObservers: [UUID: AsyncStream<CastReceiverStatus>.Continuation] = [:]
    private var mediaObservers: [UUID: AsyncStream<CastMediaStatus?>.Continuation] = [:]
    private var stateObservers: [UUID: AsyncStream<CastSessionState>.Continuation] = [:]

    /// Creates a session with an injected authenticator and optional byte transport.
    /// - Parameter userAgent: the sender name the receiver sees when this session connects to it.
    public init(
        device: CastDevice, authenticator: any CastDeviceAuthenticating,
        transport: (any CastTransport)? = nil, senderID: String = "sender-\(UUID().uuidString.lowercased())",
        userAgent: String = "CastKit"
    ) {
        channel = CastChannel(device: device, authenticator: authenticator, transport: transport)
        self.senderID = senderID
        self.userAgent = userAgent
        timing = CastSessionTiming()
    }

    /// Uses an existing channel; the app source ID remains stable throughout this session.
    /// - Parameter userAgent: the sender name the receiver sees when this session connects to it.
    public init(channel: CastChannel, senderID: String = "sender-\(UUID().uuidString.lowercased())", userAgent: String = "CastKit") {
        self.channel = channel
        self.senderID = senderID
        self.userAgent = userAgent
        timing = CastSessionTiming()
    }

    init(channel: CastChannel, senderID: String, timing: CastSessionTiming, userAgent: String = "CastKit") {
        self.channel = channel
        self.senderID = senderID
        self.userAgent = userAgent
        self.timing = timing
    }

    deinit {
        listener?.cancel()
        heartbeat?.cancel()
        for observer in receiverObservers.values { observer.finish() }
        for observer in mediaObservers.values { observer.finish() }
        for observer in stateObservers.values { observer.finish() }
        let channel = channel
        Task { await channel.close() }
    }

    /// Delivers platform status, including device volume and mute changes.
    public func receiverStatuses() -> AsyncStream<CastReceiverStatus> {
        let id = UUID()
        let pair = AsyncStream<CastReceiverStatus>.makeStream(bufferingPolicy: .bufferingNewest(1))
        if let receiverStatus { pair.continuation.yield(receiverStatus) }
        if terminated { pair.continuation.finish() }
        else { receiverObservers[id] = pair.continuation }
        pair.continuation.onTermination = { [weak self] _ in Task { await self?.removeReceiverObserver(id) } }
        return pair.stream
    }

    /// Delivers playback updates; nil means the receiver has no media session.
    public func mediaStatuses() -> AsyncStream<CastMediaStatus?> {
        let id = UUID()
        let pair = AsyncStream<CastMediaStatus?>.makeStream(bufferingPolicy: .bufferingNewest(1))
        pair.continuation.yield(mediaStatus)
        if terminated { pair.continuation.finish() }
        else { mediaObservers[id] = pair.continuation }
        pair.continuation.onTermination = { [weak self] _ in Task { await self?.removeMediaObserver(id) } }
        return pair.stream
    }

    /// Delivers lifecycle changes, including takeover and heartbeat failure.
    public func states() -> AsyncStream<CastSessionState> {
        let id = UUID()
        let pair = AsyncStream<CastSessionState>.makeStream(bufferingPolicy: .bufferingNewest(8))
        pair.continuation.yield(state)
        if terminated { pair.continuation.finish() }
        else { stateObservers[id] = pair.continuation }
        pair.continuation.onTermination = { [weak self] _ in Task { await self?.removeStateObserver(id) } }
        return pair.stream
    }

    /// Authenticates and joins the DMR, optionally launching it when no running instance exists.
    public func connect(launchIfNeeded: Bool = true) async throws {
        guard state == .disconnected, !terminated else { throw CastError.invalidState }
        setState(.connecting)
        do {
            identity = try await channel.connect()
            guard !terminated else { throw CastError.connectionClosed }
            active = true
            lastInbound = .now
            listener = Task { [weak self, channel] in
                do {
                    for try await message in channel.messages { try await self?.receive(message) }
                    await self?.channelFinished(error: .connectionClosed)
                } catch {
                    await self?.channelFinished(error: error as? CastError ?? .connectionFailed)
                }
            }
            try await virtualConnection(type: "CONNECT", destination: "receiver-0", source: "sender-0")
            startHeartbeat()
            _ = try await refreshReceiverStatus()
            var application = receiverStatus?.applications.first { $0.appID == Self.defaultMediaReceiverID && !$0.isIdleScreen }
            if application == nil {
                guard launchIfNeeded else { throw CastError.sessionEnded }
                _ = try await request(
                    namespace: CastNamespace.receiver, destination: "receiver-0", source: "sender-0",
                    body: ["type": .string("LAUNCH"), "appId": .string(Self.defaultMediaReceiverID),
                           "language": .string("en-US"), "supportedAppTypes": .array([.string("WEB")])],
                    timeout: timing.launchTimeout
                )
                application = receiverStatus?.applications.first { $0.appID == Self.defaultMediaReceiverID && !$0.isIdleScreen }
            }
            guard let application, !application.transportID.isEmpty, !application.sessionID.isEmpty else {
                throw CastError.invalidMessage
            }
            guard !terminated, state == .connecting else { throw CastError.sessionEnded }
            app = application
            try await virtualConnection(type: "CONNECT", destination: application.transportID, source: senderID)
            _ = try await mediaRequest(["type": .string("GET_STATUS")], requiresMedia: false)
            guard !terminated, state == .connecting else { throw CastError.sessionEnded }
            setState(.connected)
        } catch {
            if !terminated {
                await shutdown(state: state == .ended ? .ended : .failed(error as? CastError ?? .connectionFailed), error: error)
            }
            throw error
        }
    }

    /// Re-queries platform status without launching an application.
    @discardableResult
    public func refreshReceiverStatus() async throws -> CastReceiverStatus {
        _ = try await request(
            namespace: CastNamespace.receiver, destination: "receiver-0", source: "sender-0",
            body: ["type": .string("GET_STATUS")]
        )
        guard let receiverStatus else { throw CastError.invalidMessage }
        return receiverStatus
    }

    /// Loads a buffered track with receiver-fetchable media and artwork URLs.
    public func load(_ media: CastMedia, currentTime: TimeInterval = 0, autoplay: Bool = true) async throws {
        guard state == .connected else { throw CastError.invalidState }
        guard currentTime.isFinite, currentTime >= 0, validMedia(media) else { throw CastError.invalidArgument }
        guard !hasPendingLoad else { throw CastError.invalidState }
        _ = try await mediaRequest([
            "type": .string("LOAD"), "media": media.json, "autoplay": .bool(autoplay), "currentTime": .number(currentTime)
        ], requiresMedia: false)
    }

    /// Replaces playback with a receiver queue, starting at an array index and time in seconds.
    public func loadQueue(_ items: [CastQueueItem], startIndex: Int = 0, currentTime: TimeInterval = 0) async throws {
        guard state == .connected else { throw CastError.invalidState }
        guard validQueue(items), items.indices.contains(startIndex), currentTime.isFinite,
              currentTime >= 0 else { throw CastError.invalidArgument }
        guard !hasPendingLoad else { throw CastError.invalidState }
        _ = try await mediaRequest([
            "type": .string("QUEUE_LOAD"), "items": .array(items.map(\.json)),
            "startIndex": .number(Double(startIndex)), "repeatMode": .string("REPEAT_OFF"),
            "currentTime": .number(currentTime)
        ], requiresMedia: false)
    }

    /// Appends entries to the current receiver queue without changing the current entry.
    public func insertQueueItems(_ items: [CastQueueItem]) async throws {
        guard validQueue(items) else { throw CastError.invalidArgument }
        _ = try await mediaRequest(["type": .string("QUEUE_INSERT"), "items": .array(items.map(\.json))])
        ownsQueue = ownedMediaID != nil
    }

    /// Resumes the current media session.
    public func play() async throws { try await command("PLAY") }
    /// Pauses the current media session.
    public func pause() async throws { try await command("PAUSE") }
    /// Seeks in seconds, optionally selecting the resulting playback state.
    public func seek(to time: TimeInterval, resumeState: CastSeekResumeState? = nil) async throws {
        guard time.isFinite, time >= 0 else { throw CastError.invalidArgument }
        var body: [String: CastJSON] = ["type": .string("SEEK"), "currentTime": .number(time)]
        if let resumeState { body["resumeState"] = .string(resumeState.rawValue) }
        _ = try await mediaRequest(body)
    }
    /// Ends media playback while leaving the receiver application running.
    public func stop() async throws {
        try await command("STOP")
        ownedMediaID = nil
        mediaStatus = nil
        mediaCache.removeAll()
        queueCache.removeAll()
        ownsQueue = false
        publishMedia()
    }
    /// Queries playback status on the application virtual connection.
    public func refreshMediaStatus() async throws { _ = try await mediaRequest(["type": .string("GET_STATUS")], requiresMedia: false) }

    /// Claims an observed session after a reconnect, enabling takeover detection without reloading it.
    /// Callers must first verify that its media belongs to their earlier playback.
    public func adoptMediaSession(_ mediaSessionID: Int) throws {
        guard state == .connected, let mediaStatus,
              mediaStatus.mediaSessionID == mediaSessionID, mediaStatus.playerState != .idle else {
            throw CastError.invalidState
        }
        ownedMediaID = mediaSessionID
        ownsQueue = !mediaStatus.items.isEmpty
    }

    /// Sets device or group volume. Fixed-volume receivers may ignore it.
    public func setVolume(_ level: Double) async throws {
        guard level.isFinite, (0...1).contains(level) else { throw CastError.invalidArgument }
        try await receiverVolume(["level": .number(level)])
    }
    /// Sets the current media stream volume independently of device or group volume.
    public func setStreamVolume(_ level: Double) async throws {
        guard level.isFinite, (0...1).contains(level) else { throw CastError.invalidArgument }
        _ = try await mediaRequest(["type": .string("SET_VOLUME"), "volume": .object(["level": .number(level)])])
    }
    /// Sets device or group mute separately from the volume level.
    public func setMuted(_ muted: Bool) async throws { try await receiverVolume(["muted": .bool(muted)]) }

    /// Quits the receiver application for every sender.
    public func stopReceiverApplication() async throws {
        guard let app, state == .connected else { throw CastError.invalidState }
        _ = try await request(
            namespace: CastNamespace.receiver, destination: "receiver-0", source: "sender-0",
            body: ["type": .string("STOP"), "sessionId": .string(app.sessionID)]
        )
    }

    /// Closes both virtual connections and the underlying transport.
    public func disconnect() async {
        guard !terminated, !closing else { return }
        closing = true
        heartbeat?.cancel()
        heartbeat = nil
        if active {
            if let app { try? await virtualConnection(type: "CLOSE", destination: app.transportID, source: senderID) }
            try? await virtualConnection(type: "CLOSE", destination: "receiver-0", source: "sender-0")
        }
        await shutdown(state: .disconnected, error: CastError.connectionClosed)
    }

    private func command(_ type: String) async throws { _ = try await mediaRequest(["type": .string(type)]) }
    private var hasPendingLoad: Bool { pending.values.contains { $0.type == "LOAD" || $0.type == "QUEUE_LOAD" } }
    private func validMedia(_ media: CastMedia) -> Bool {
        !media.contentID.isEmpty && media.contentID.utf8.count <= 1024 && !media.contentType.isEmpty
            && (media.duration.map { $0.isFinite && $0 >= 0 } ?? true)
    }
    private func validQueue(_ items: [CastQueueItem]) -> Bool {
        !items.isEmpty && items.allSatisfy { validMedia($0.media) && $0.preloadTime.isFinite }
    }
    private func receiverVolume(_ volume: [String: CastJSON]) async throws {
        guard state == .connected else { throw CastError.invalidState }
        _ = try await request(
            namespace: CastNamespace.receiver, destination: "receiver-0", source: "sender-0",
            body: ["type": .string("SET_VOLUME"), "volume": .object(volume)]
        )
    }

    private func mediaRequest(_ body: [String: CastJSON], requiresMedia: Bool = true) async throws -> CastJSON {
        guard let app, state == .connected || state == .connecting else { throw CastError.invalidState }
        var body = body
        if requiresMedia {
            guard let mediaStatus, mediaStatus.playerState != .idle else { throw CastError.invalidState }
            body["mediaSessionId"] = .number(Double(mediaStatus.mediaSessionID))
        }
        return try await request(namespace: CastNamespace.media, destination: app.transportID, source: senderID, body: body)
    }

    private func request(
        namespace: String, destination: String, source: String,
        body: [String: CastJSON], timeout: Duration? = nil
    ) async throws -> CastJSON {
        guard active, !terminated, !closing, nextRequestID <= Int(Int32.max) else { throw CastError.invalidState }
        let id = nextRequestID
        nextRequestID += 1
        let waitDuration = timeout ?? timing.requestTimeout
        var body = body
        body["requestId"] = .number(Double(id))
        let message = try jsonMessage(body, namespace: namespace, destination: destination, source: source)
        let type = body["type"]?.string ?? ""
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                let timer = Task { [weak self] in
                    do { try await Task.sleep(for: waitDuration) } catch { return }
                    await self?.failRequest(id, error: CastError.timedOut)
                }
                pending[id] = Pending(
                    namespace: namespace, source: destination, type: type,
                    continuation: continuation, timeout: timer
                )
                Task { [weak self, channel] in
                    guard await self?.hasPendingRequest(id) == true else { return }
                    do { try await channel.send(message) }
                    catch { await self?.failRequest(id, error: error) }
                }
            }
        } onCancel: {
            Task { await self.failRequest(id, error: CancellationError()) }
        }
    }

    private func hasPendingRequest(_ id: Int) -> Bool { pending[id] != nil && !terminated && !closing }

    private func failRequest(_ id: Int, error: any Error) {
        guard let request = pending.removeValue(forKey: id) else { return }
        request.timeout.cancel()
        request.continuation.resume(throwing: error)
    }

    private func jsonMessage(_ body: [String: CastJSON], namespace: String, destination: String, source: String) throws -> CastMessage {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(CastJSON.object(body))
        return CastMessage(sourceID: source, destinationID: destination, namespace: namespace, payloadUTF8: String(decoding: data, as: UTF8.self))
    }

    private func virtualConnection(type: String, destination: String, source: String) async throws {
        var body: [String: CastJSON] = ["type": .string(type)]
        if type == "CONNECT" {
            body["userAgent"] = .string(userAgent)
            body["connType"] = .number(0)
            body["origin"] = .object([:])
            body["senderInfo"] = .object([
                "sdkType": .number(2), "version": .string("1.0"), "browserVersion": .string("1.0"),
                "platform": .number(4), "systemVersion": .string(ProcessInfo.processInfo.operatingSystemVersionString),
                "connectionType": .number(1)
            ])
        } else { body["reasonCode"] = .number(5) }
        try await channel.send(jsonMessage(body, namespace: CastNamespace.connection, destination: destination, source: source))
    }

    private func receive(_ message: CastMessage) async throws {
        lastInbound = .now
        if active, !terminated, !closing { startHeartbeat() }
        guard !terminated, !closing, message.destinationID == "*" || message.destinationID == "sender-0" || message.destinationID == senderID else { return }
        guard [CastNamespace.heartbeat, CastNamespace.connection, CastNamespace.receiver, CastNamespace.media].contains(message.namespace) else { return }
        guard let data = message.jsonData else { throw CastError.invalidMessage }
        let json = try JSONDecoder().decode(CastJSON.self, from: data)
        guard let type = json["type"].string else { throw CastError.invalidMessage }
        if message.namespace == CastNamespace.heartbeat, message.sourceID == "receiver-0" {
            if type == "PING" {
                try await channel.send(jsonMessage(["type": .string("PONG")], namespace: CastNamespace.heartbeat, destination: "receiver-0", source: "sender-0"))
            }
            return
        }
        if message.namespace == CastNamespace.connection, type == "CLOSE",
           message.sourceID == "receiver-0" || message.sourceID == app?.transportID {
            endSession(requery: true)
            return
        }
        let requestID = json["requestId"].integer ?? 0
        var id = requestID
        if pending[id] == nil, let launchID = json["launchRequestId"].integer { id = launchID }
        if id == 0, type == "LAUNCH_ERROR", message.namespace == CastNamespace.receiver,
           let launchID = pending.first(where: { $0.value.type == "LAUNCH" })?.key { id = launchID }
        let matching = pending[id].flatMap { $0.namespace == message.namespace && $0.source == message.sourceID ? $0 : nil }
        let errors = ["LAUNCH_ERROR", "INVALID_REQUEST", "LOAD_FAILED", "LOAD_CANCELLED", "INVALID_PLAYER_STATE", "ERROR"]
        if errors.contains(type) {
            if matching != nil { failRequest(id, error: CastError.requestFailed(json["reason"].string ?? type)) }
            return
        }
        var accepted = false
        if message.namespace == CastNamespace.receiver, message.sourceID == "receiver-0", type == "RECEIVER_STATUS" {
            let status = try CastReceiverStatus(json["status"])
            receiverStatus = status
            for observer in receiverObservers.values { observer.yield(status) }
            accepted = true
            if let app, !status.applications.contains(where: {
                $0.appID == app.appID && $0.sessionID == app.sessionID && $0.transportID == app.transportID && !$0.isIdleScreen
            }) {
                // Resolve an intentional receiver STOP before ending its virtual connection.
                if matching?.type == "STOP" { completeRequest(id, json: json) }
                endSession(requery: false)
                return
            }
            let hasDMR = status.applications.contains { $0.appID == Self.defaultMediaReceiverID && !$0.isIdleScreen }
            if hasDMR {
                for launchID in pending.filter({ $0.value.type == "LAUNCH" && $0.value.namespace == CastNamespace.receiver }).map(\.key) {
                    completeRequest(launchID, json: json)
                }
            } else if matching?.type == "LAUNCH" { accepted = false }
        } else if message.namespace == CastNamespace.media, message.sourceID == app?.transportID, type == "MEDIA_STATUS" {
            try updateMedia(json, loadType: matching.flatMap { ["LOAD", "QUEUE_LOAD"].contains($0.type) ? $0.type : nil })
            accepted = true
        }
        if accepted, matching != nil { completeRequest(id, json: json) }
    }

    private func updateMedia(_ json: CastJSON, loadType: String?) throws {
        guard let statuses = json["status"].array else { throw CastError.invalidMessage }
        let isLoad = loadType != nil
        let loading = hasPendingLoad
        if statuses.isEmpty {
            mediaStatus = nil
            ownedMediaID = nil
            mediaCache.removeAll()
            queueCache.removeAll()
            ownsQueue = false
            publishMedia()
            return
        }
        let value: CastJSON
        if isLoad {
            value = statuses.first { $0["playerState"].string != "IDLE" } ?? statuses[0]
        } else {
            value = statuses.first { $0["mediaSessionId"].integer == ownedMediaID } ?? statuses[0]
        }
        guard let id = value["mediaSessionId"].integer else { throw CastError.invalidMessage }
        let previous = mediaStatus.flatMap { !isLoad && $0.mediaSessionID == id ? $0 : nil }
        let currentItemID = value["currentItemId"].integer ?? previous?.currentItemID
        let queueHandoff = !isLoad && ownsQueue && id != ownedMediaID && currentItemID.map { itemID in
            ownedMediaID.flatMap { queueCache[$0]?[itemID] } != nil
        } == true
        if queueHandoff, let ownedMediaID { queueCache[id] = queueCache[ownedMediaID] }
        var cachedItems: [Int: CastQueueItemStatus] = isLoad ? [:] : (queueCache[id] ?? [:])
        let itemIDs: [Int]
        if let items = value["items"].array {
            itemIDs = items.compactMap { item in
                guard let itemID = item["itemId"].integer else { return nil }
                let old = cachedItems[itemID]
                cachedItems[itemID] = CastQueueItemStatus(
                    itemID: itemID, media: CastMedia(item["media"]) ?? old?.media,
                    customData: item["customData"].stringDictionary ?? old?.customData
                )
                return itemID
            }
        } else { itemIDs = (previous ?? (queueHandoff ? mediaStatus : nil))?.items.map(\.itemID) ?? [] }
        let media: CastMedia?
        if let supplied = CastMedia(value["media"]) {
            media = supplied
            if let currentItemID {
                cachedItems[currentItemID] = CastQueueItemStatus(
                    itemID: currentItemID, media: supplied, customData: cachedItems[currentItemID]?.customData
                )
            }
        } else if let currentItemID { media = cachedItems[currentItemID]?.media }
        else { media = isLoad ? nil : mediaCache[id] }
        mediaCache[id] = media
        queueCache[id] = cachedItems
        let rawState = value["extendedStatus"]["playerState"].string == "LOADING"
            ? "LOADING" : value["playerState"].string ?? ""
        let playerState = CastPlayerState(rawValue: rawState) ?? .unknown
        let status = CastMediaStatus(
            mediaSessionID: id, playerState: playerState, idleReason: value["idleReason"].string,
            currentTime: value["currentTime"].number ?? (currentItemID == previous?.currentItemID ? previous?.currentTime : nil) ?? 0,
            media: media, volume: CastVolume(value["volume"]) ?? previous?.volume,
            currentItemID: currentItemID,
            loadingItemID: value["loadingItemId"].integer,
            preloadedItemID: value["preloadedItemId"].integer,
            items: itemIDs.compactMap { cachedItems[$0] },
            supportedMediaCommands: value["supportedMediaCommands"].integer ?? previous?.supportedMediaCommands
        )
        mediaStatus = status
        publishMedia()
        if let ownedMediaID, !loading, ((!queueHandoff && id != ownedMediaID) || status.idleReason == "INTERRUPTED") {
            endSession(requery: false)
            return
        }
        if isLoad || queueHandoff { ownedMediaID = id }
        if isLoad { ownsQueue = loadType == "QUEUE_LOAD" }
        if playerState == .idle {
            ownedMediaID = nil
            mediaCache[id] = nil
            queueCache[id] = nil
            ownsQueue = false
        } else {
            mediaCache = mediaCache.filter { $0.key == id }
            queueCache = queueCache.filter { $0.key == id }
        }
    }

    private func completeRequest(_ id: Int, json: CastJSON) {
        guard let request = pending.removeValue(forKey: id) else { return }
        request.timeout.cancel()
        request.continuation.resume(returning: json)
    }

    private func startHeartbeat() {
        heartbeat?.cancel()
        heartbeat = Task { [weak self, timing] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: timing.heartbeatInterval) } catch { return }
                guard let self else { return }
                await self.heartbeatTick()
            }
        }
    }

    private func heartbeatTick() async {
        guard active, !terminated, !closing else { return }
        let silence = lastInbound.duration(to: .now)
        if silence >= timing.silenceTimeout {
            await shutdown(state: .failed(.deviceLost), error: CastError.deviceLost)
        } else if silence >= timing.heartbeatInterval {
            do {
                try await channel.send(jsonMessage(["type": .string("PING")], namespace: CastNamespace.heartbeat, destination: "receiver-0", source: "sender-0"))
            } catch { await channelFinished(error: error as? CastError ?? .connectionFailed) }
        }
    }

    private func endSession(requery: Bool) {
        guard state != .ended, !terminated else { return }
        setState(.ended)
        ownedMediaID = nil
        app = nil
        for id in Array(pending.keys) { failRequest(id, error: CastError.sessionEnded) }
        Task { [weak self] in
            guard let self else { return }
            if requery { _ = try? await self.refreshReceiverStatus() }
            await self.shutdown(state: .ended, error: CastError.sessionEnded)
        }
    }

    private func channelFinished(error: CastError) async {
        guard !terminated else { return }
        await shutdown(state: closing ? .disconnected : (state == .ended ? .ended : .failed(error)), error: error)
    }

    private func shutdown(state: CastSessionState, error: any Error) async {
        guard !terminated else { return }
        terminated = true
        active = false
        heartbeat?.cancel()
        heartbeat = nil
        listener?.cancel()
        listener = nil
        setState(state)
        for id in Array(pending.keys) { failRequest(id, error: error) }
        for observer in receiverObservers.values { observer.finish() }
        for observer in mediaObservers.values { observer.finish() }
        for observer in stateObservers.values { observer.finish() }
        receiverObservers.removeAll()
        mediaObservers.removeAll()
        stateObservers.removeAll()
        await channel.close()
    }

    private func setState(_ value: CastSessionState) {
        guard state != value else { return }
        state = value
        for observer in stateObservers.values { observer.yield(value) }
    }
    private func publishMedia() { for observer in mediaObservers.values { observer.yield(mediaStatus) } }
    private func removeReceiverObserver(_ id: UUID) { receiverObservers[id] = nil }
    private func removeMediaObserver(_ id: UUID) { mediaObservers[id] = nil }
    private func removeStateObserver(_ id: UUID) { stateObservers[id] = nil }
}
