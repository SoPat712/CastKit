import Foundation
import Testing
@testable import CastKit

struct CastKitSessionTests: Sendable {
    @Test func queueLoadAppendAndStreamVolumeSendExpectedJSON() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            let media = CastMedia(contentID: "https://example.test/song.mp3", contentType: "audio/mpeg", customData: ["track": "same"])
            let first = CastQueueItem(media: media, autoplay: false, preloadTime: 10, customData: ["entry": "one"])
            let second = CastQueueItem(media: media, preloadTime: 20, customData: ["entry": "two"])
            let third = CastQueueItem(media: media, preloadTime: -1, customData: ["entry": "three"])
            try await harness.session.loadQueue([first, second], startIndex: 1, currentTime: 2.5)
            try await harness.session.insertQueueItems([third])
            try await harness.session.setStreamVolume(0.35)
            let status = await harness.session.mediaStatus
            #expect(status?.items.map(\.itemID) == [101, 102, 103])
            #expect(status?.currentItemID == 102)
            #expect(status?.media?.customData == ["track": "same"])
            #expect(status?.items.map(\.customData) == [["entry": "one"], ["entry": "two"], ["entry": "three"]])
            #expect(status?.volume?.level == 0.35)
            #expect(status?.supportsStreamVolume == true)
            let receiverLevel = await harness.session.receiverStatus?.volume?.level
            #expect(receiverLevel == 0.5)

            let snapshot = await harness.transport.snapshot()
            let wireMedia: CastJSON = .object([
                "contentId": .string("https://example.test/song.mp3"), "contentType": .string("audio/mpeg"),
                "streamType": .string("BUFFERED"), "customData": .object(["track": .string("same")]),
                "metadata": .object(["metadataType": .number(3), "images": .array([])]),
            ])
            func item(_ entry: String, autoplay: Bool, preload: Double) -> CastJSON {
                .object(["media": wireMedia, "autoplay": .bool(autoplay), "preloadTime": .number(preload),
                         "customData": .object(["entry": .string(entry)])])
            }
            assertMessages(snapshot.written.filter { $0.namespace == CastNamespace.media }, expected: [
                expectedMedia(["type": .string("GET_STATUS")]),
                expectedMedia([
                    "type": .string("QUEUE_LOAD"), "items": .array([item("one", autoplay: false, preload: 10), item("two", autoplay: true, preload: 20)]),
                    "startIndex": .number(1), "repeatMode": .string("REPEAT_OFF"), "currentTime": .number(2.5),
                ]),
                expectedMedia([
                    "type": .string("QUEUE_INSERT"), "mediaSessionId": .number(41),
                    "items": .array([item("three", autoplay: true, preload: -1)]),
                ]),
                expectedMedia([
                    "type": .string("SET_VOLUME"), "mediaSessionId": .number(41), "volume": .object(["level": .number(0.35)]),
                ]),
            ])
        }
    }

    @Test func loadPreservesCustomDataOnTheWire() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            let media = CastMedia(contentID: "https://example.test/song.mp3", contentType: "audio/mpeg", customData: ["entry": "one"])
            try await harness.session.loadQueue([CastQueueItem(media: fixtureMedia())])
            try await harness.session.load(media)
            let status = await harness.session.mediaStatus
            #expect(status?.media == media)
            #expect(status?.currentItemID == nil)
            #expect(status?.items.isEmpty == true)
            let written = await harness.transport.snapshot().written
            let load = try #require(written.first { json($0)?["type"].string == "LOAD" })
            #expect(json(load)?["media"]["customData"] == .object(["entry": .string("one")]))
        }
    }

    @Test func queueStatusRetainsMediaPerItemAcrossHandoff() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            let first = CastMedia(contentID: "https://example.test/song.mp3", contentType: "audio/mpeg", customData: ["entry": "one"])
            let second = CastMedia(contentID: first.contentID, contentType: first.contentType, customData: ["entry": "two"])
            try await harness.session.loadQueue([
                CastQueueItem(media: first, customData: ["entry": "one"]),
                CastQueueItem(media: second, customData: ["entry": "two"]),
            ])
            try await harness.transport.broadcastStatus([
                "mediaSessionId": .number(41), "playerState": .string("PLAYING"), "currentItemId": .number(102),
                "loadingItemId": .number(103), "preloadedItemId": .number(103), "supportedMediaCommands": .number(7),
                "items": .array([.object(["itemId": .number(101)]), .object(["itemId": .number(102)])]),
            ])
            try await waitUntil { await harness.session.mediaStatus?.currentItemID == 102 }
            let switched = try #require(await harness.session.mediaStatus)
            #expect(switched.media == second)
            #expect(switched.items.map(\.media) == [first, second])
            #expect(switched.items.map(\.customData) == [["entry": "one"], ["entry": "two"]])
            #expect(switched.loadingItemID == 103)
            #expect(switched.preloadedItemID == 103)
            #expect(switched.supportsStreamVolume)

            try await harness.transport.broadcastStatus([
                "mediaSessionId": .number(41), "playerState": .string("IDLE"), "currentItemId": .number(103),
                "extendedStatus": .object(["playerState": .string("LOADING")]),
                "supportedMediaCommands": .number(0),
            ])
            try await waitUntil { await harness.session.mediaStatus?.currentItemID == 103 }
            let unknown = await harness.session.mediaStatus
            #expect(unknown?.media == nil)
            #expect(unknown?.playerState == .loading)
            #expect(unknown?.supportsStreamVolume == false)
            #expect(unknown?.loadingItemID == nil)
            #expect(unknown?.preloadedItemID == nil)

            try await harness.transport.broadcastStatus([
                "mediaSessionId": .number(42), "playerState": .string("PLAYING"), "currentItemId": .number(102),
            ])
            try await waitUntil { await harness.session.mediaStatus?.mediaSessionID == 42 }
            let handoff = await harness.session.mediaStatus
            #expect(handoff?.media == second)
            #expect(handoff?.items.map(\.media) == [first, second])
            let state = await harness.session.state
            #expect(state == .connected)
        }
    }

    @Test func mediaAndQueueCachesDoNotLeakAcrossUnownedSessions() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            let media = fixtureMedia()
            try await harness.transport.broadcastStatus([
                "mediaSessionId": .number(41), "playerState": .string("PLAYING"), "currentItemId": .number(101),
                "media": media.json, "supportedMediaCommands": .number(4),
                "items": .array([.object(["itemId": .number(101), "media": media.json, "customData": .object(["entry": .string("one")])])]),
            ])
            try await waitUntil { await harness.session.mediaStatus?.media == media }
            try await harness.transport.broadcastStatus([
                "mediaSessionId": .number(42), "playerState": .string("PLAYING"), "currentItemId": .number(101),
                "items": .array([.object(["itemId": .number(101)])]),
            ])
            try await waitUntil { await harness.session.mediaStatus?.mediaSessionID == 42 }
            let status = await harness.session.mediaStatus
            #expect(status?.media == nil)
            #expect(status?.items.first?.media == nil)
            #expect(status?.items.first?.customData == nil)
            #expect(status?.supportedMediaCommands == nil)
            #expect(status?.supportsStreamVolume == false)
            let state = await harness.session.state
            #expect(state == .connected)
        }
    }

    @Test func queueAndStreamVolumeRejectInvalidArguments() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            let item = CastQueueItem(media: fixtureMedia())
            #expect(await captureError { try await harness.session.loadQueue([]) } == .invalidArgument)
            #expect(await captureError { try await harness.session.loadQueue([item], startIndex: 1) } == .invalidArgument)
            #expect(await captureError { try await harness.session.loadQueue([item], currentTime: .nan) } == .invalidArgument)
            #expect(await captureError { try await harness.session.insertQueueItems([]) } == .invalidArgument)
            #expect(await captureError {
                try await harness.session.loadQueue([CastQueueItem(media: fixtureMedia(), preloadTime: .infinity)])
            } == .invalidArgument)
            for level in [Double.nan, .infinity, -0.1, 1.1] {
                #expect(await captureError { try await harness.session.setStreamVolume(level) } == .invalidArgument)
            }
            #expect(await captureError { try await harness.session.setStreamVolume(0.5) } == .invalidState)
        }
    }

    @Test func fullSequenceSendsExpectedJSON() async throws {
        try await withHarness { harness in
            let observations = SessionObservations()
            let tasks = await observe(harness.session, into: observations)
            defer { tasks.forEach { $0.cancel() } }

            try await harness.session.connect()
            let connected = await harness.session.state
            #expect(connected == .connected)
            try await assertAuthentication(harness)

            let media = fixtureMedia()
            try await harness.session.load(media, currentTime: 5.25, autoplay: false)
            try await harness.session.play()
            try await harness.session.pause()
            try await harness.session.seek(to: 37.5, resumeState: .play)
            let afterSeek = await harness.session.mediaStatus
            #expect(afterSeek?.media == media)
            #expect(afterSeek?.currentTime == 37.5)
            #expect(afterSeek?.playerState == .playing)

            try await harness.transport.broadcastMedia(time: 55, state: .paused)
            try await waitUntil {
                let status = await harness.session.mediaStatus
                return status?.currentTime == 55 && status?.playerState == .paused
            }
            let incremental = await harness.session.mediaStatus
            #expect(incremental?.media == media)
            #expect(incremental?.duration == 240)
            try await harness.transport.broadcastReceiverVolume(level: 0.67, muted: false)
            try await waitUntil { await harness.session.receiverStatus?.volume?.level == 0.67 }
            try await waitUntil {
                let snapshot = await observations.snapshot()
                return snapshot.media.contains { $0?.currentTime == 55 && $0?.media == media }
                    && snapshot.receivers.contains { $0.volume?.level == 0.67 }
            }

            try await harness.transport.sendHeartbeatPing()
            try await waitUntil {
                let snapshot = await harness.transport.snapshot()
                return snapshot.written.contains { $0.namespace == CastNamespace.heartbeat && json($0)?["type"].string == "PONG" }
            }
            try await harness.session.setVolume(0.42)
            try await harness.session.setMuted(true)
            let receiver = await harness.session.receiverStatus
            #expect(receiver?.volume?.level == 0.42)
            #expect(receiver?.volume?.muted == true)
            try await harness.session.stop()
            let stoppedMedia = await harness.session.mediaStatus
            #expect(stoppedMedia == nil)
            try await harness.session.stopReceiverApplication()
            try await waitUntil { await harness.transport.snapshot().closed }
            try await waitUntil { await harness.session.state == .ended }
            try await waitUntil { await observations.snapshot().states.contains(.ended) }
            let observed = await observations.snapshot()
            #expect(observed.states.contains(.connecting))
            #expect(observed.states.contains(.connected))

            let snapshot = await harness.transport.snapshot()
            assertMessages(snapshot.written, expected: [
                expectedConnect(source: "sender-0", destination: "receiver-0"),
                expectedReceiver(["type": .string("GET_STATUS")]),
                expectedReceiver([
                    "type": .string("LAUNCH"), "appId": .string("CC1AD845"),
                    "language": .string("en-US"), "supportedAppTypes": .array([.string("WEB")]),
                ]),
                expectedConnect(source: appSender, destination: appTransport),
                expectedMedia(["type": .string("GET_STATUS")]),
                expectedMedia([
                    "type": .string("LOAD"), "media": expectedMediaJSON,
                    "autoplay": .bool(false), "currentTime": .number(5.25),
                ]),
                expectedMedia(["type": .string("PLAY"), "mediaSessionId": .number(41)]),
                expectedMedia(["type": .string("PAUSE"), "mediaSessionId": .number(41)]),
                expectedMedia([
                    "type": .string("SEEK"), "mediaSessionId": .number(41),
                    "currentTime": .number(37.5), "resumeState": .string("PLAYBACK_START"),
                ]),
                expectedReceiver(["type": .string("SET_VOLUME"), "volume": .object(["level": .number(0.42)])]),
                expectedReceiver(["type": .string("SET_VOLUME"), "volume": .object(["muted": .bool(true)])]),
                expectedMedia(["type": .string("STOP"), "mediaSessionId": .number(41)]),
                expectedReceiver(["type": .string("STOP"), "sessionId": .string(appSession)]),
            ])
            let pongs = snapshot.written.filter { $0.namespace == CastNamespace.heartbeat }
            #expect(pongs.count == 1)
            for pong in pongs {
                #expect(pong.sourceID == "sender-0")
                #expect(pong.destinationID == "receiver-0")
                #expect(json(pong) == .object(["type": .string("PONG")]))
            }
        }
    }

    @Test func authFailureClosesBeforeVirtualConnect() async throws {
        let firstNonce = try await rejectedAuthenticationNonce()
        let secondNonce = try await rejectedAuthenticationNonce()
        #expect(firstNonce.count == 16)
        #expect(secondNonce.count == 16)
        #expect(firstNonce != secondNonce)
    }

    @Test func authErrorClosesBeforeVirtualConnect() async throws {
        try await withHarness(options: ScriptOptions(authReply: .error)) { harness in
            let error = await captureError { try await harness.session.connect() }
            #expect(error == .authenticationFailed)
            let snapshot = await harness.transport.snapshot()
            #expect(snapshot.closed)
            #expect(snapshot.written.count == 1)
            #expect(snapshot.written.first?.namespace == CastNamespace.authentication)
            #expect(harness.authenticator.snapshot().contexts.isEmpty)
            let state = await harness.session.state
            #expect(state == .failed(.authenticationFailed))
        }
    }

    @Test func heartbeatLossEndsSession() async throws {
        let timing = CastSessionTiming(
            heartbeatInterval: .milliseconds(20), silenceTimeout: .milliseconds(100),
            requestTimeout: .seconds(2), launchTimeout: .seconds(2)
        )
        try await withHarness(options: ScriptOptions(replyToHeartbeat: false), timing: timing) { harness in
            try await harness.session.connect()
            try await waitUntil { await harness.session.state == .failed(.deviceLost) }
            try await waitUntil { await harness.transport.snapshot().closed }
            let snapshot = await harness.transport.snapshot()
            let pings = snapshot.written.filter { $0.namespace == CastNamespace.heartbeat }
            #expect(!pings.isEmpty)
            for ping in pings {
                #expect(ping.sourceID == "sender-0")
                #expect(ping.destinationID == "receiver-0")
                #expect(json(ping) == .object(["type": .string("PING")]))
            }
        }
    }

    @Test func binaryJSONAndMissingApplicationsAreAccepted() async throws {
        try await withHarness(options: ScriptOptions(binaryJSON: true)) { harness in
            try await harness.session.connect()
            let state = await harness.session.state
            #expect(state == .connected)
            let snapshot = await harness.transport.snapshot()
            let replies = snapshot.delivered.filter { $0.namespace != CastNamespace.authentication }
            #expect(!replies.isEmpty)
            #expect(replies.allSatisfy { $0.protocolVersion == 3 && $0.payloadType == .string && $0.payloadUTF8 == nil && $0.payloadBinary != nil })
            let receiverReplies = replies.filter { $0.namespace == CastNamespace.receiver }
            let initial = try #require(receiverReplies.first)
            #expect(json(initial)?["status"]["applications"] == .null)
            let receiver = await harness.session.receiverStatus
            #expect(receiver?.applications.first?.appID == "CC1AD845")
            #expect(receiver?.applications.first?.namespaces == [CastNamespace.media, "urn:x-cast:example"])
        }
    }

    @Test func joinsRunningReceiverWithoutLaunch() async throws {
        try await withHarness(options: ScriptOptions(initiallyRunning: true)) { harness in
            try await harness.session.connect()
            let snapshot = await harness.transport.snapshot()
            assertMessages(snapshot.written, expected: [
                expectedConnect(source: "sender-0", destination: "receiver-0"),
                expectedReceiver(["type": .string("GET_STATUS")]),
                expectedConnect(source: appSender, destination: appTransport),
                expectedMedia(["type": .string("GET_STATUS")]),
            ])
            #expect(!snapshot.written.contains { json($0)?["type"].string == "LAUNCH" })
            let state = await harness.session.state
            #expect(state == .connected)
        }
    }

    @Test func takeoverEndsSession() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            try await harness.session.load(fixtureMedia())
            try await harness.transport.broadcastMedia(time: 0, state: .playing, mediaSessionID: 42)
            try await waitUntil { await harness.session.state == .ended }
            try await waitUntil { await harness.transport.snapshot().closed }
            let error = await captureError { try await harness.session.play() }
            #expect(error == .invalidState)
            let snapshot = await harness.transport.snapshot()
            #expect(snapshot.written.filter { json($0)?["type"].string == "LAUNCH" }.count == 1)
        }
    }

    @Test func resumeDoesNotLaunchAMissingReceiverApplication() async throws {
        try await withHarness { harness in
            let error = await captureError { try await harness.session.connect(launchIfNeeded: false) }
            #expect(error == .sessionEnded)
            let snapshot = await harness.transport.snapshot()
            #expect(!snapshot.written.contains { json($0)?["type"].string == "LAUNCH" })
            #expect(snapshot.closed)
        }
    }

    @Test func adoptedMediaSessionDetectsTakeoverWithoutReloading() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            try await harness.session.loadQueue([CastQueueItem(media: fixtureMedia())])
            try await harness.session.adoptMediaSession(41)
            let before = await harness.transport.snapshot().written.count
            // Another sender's load starts a new media session whose queue items this sender never sent.
            try await harness.transport.broadcastStatus([
                "mediaSessionId": .number(42), "playerState": .string("PLAYING"), "currentTime": .number(0),
                "currentItemId": .number(900),
            ])
            try await waitUntil { await harness.session.state == .ended }
            let written = await harness.transport.snapshot().written
            #expect(!written.dropFirst(before).contains { ["LOAD", "QUEUE_LOAD", "LAUNCH"].contains(json($0)?["type"].string ?? "") })
        }
    }

    @Test func requestTimeoutIgnoresUnmatchedResponse() async throws {
        let timing = CastSessionTiming(
            heartbeatInterval: .seconds(30), silenceTimeout: .seconds(60),
            requestTimeout: .milliseconds(100), launchTimeout: .seconds(2)
        )
        try await withHarness(options: ScriptOptions(unmatchedRequestType: "PLAY"), timing: timing) { harness in
            try await harness.session.connect()
            try await harness.session.load(fixtureMedia())
            let error = await captureError { try await harness.session.play() }
            #expect(error == .timedOut)
            let state = await harness.session.state
            #expect(state == .connected)
            let snapshot = await harness.transport.snapshot()
            #expect(!snapshot.closed)
            let play = try #require(snapshot.written.last)
            let requestID = try #require(json(play)?["requestId"].integer)
            let candidates = snapshot.delivered.filter { json($0)?["requestId"].integer == requestID }
            #expect(candidates.contains { $0.namespace == CastNamespace.receiver })
            #expect(candidates.contains { $0.sourceID == "web-other" })
            #expect(candidates.contains { $0.destinationID == "another-sender" })
        }
    }

    @Test func disconnectClosesBothVirtualConnections() async throws {
        try await withHarness { harness in
            try await harness.session.connect()
            await harness.session.disconnect()
            let snapshot = await harness.transport.snapshot()
            #expect(snapshot.closed)
            let closes = snapshot.written.filter { json($0)?["type"].string == "CLOSE" }
            assertMessages(closes, expected: [
                ExpectedMessage(source: appSender, destination: appTransport, namespace: CastNamespace.connection,
                                body: ["type": .string("CLOSE"), "reasonCode": .number(5)], request: false),
                ExpectedMessage(source: "sender-0", destination: "receiver-0", namespace: CastNamespace.connection,
                                body: ["type": .string("CLOSE"), "reasonCode": .number(5)], request: false),
            ])
            let state = await harness.session.state
            #expect(state == .disconnected)
        }
    }

    @Test func authTimeoutClosesTransport() async throws {
        try await withHarness(options: ScriptOptions(authReply: .silent)) { harness in
            let error = await captureError { _ = try await harness.channel.connect(timeout: .milliseconds(50)) }
            #expect(error == .timedOut)
            let snapshot = await harness.transport.snapshot()
            #expect(snapshot.closed)
            #expect(snapshot.written.count == 1)
            #expect(harness.authenticator.snapshot().contexts.isEmpty)
        }
    }

    @Test func nonAuthFirstReplyFailsAuthentication() async throws {
        try await withHarness(options: ScriptOptions(authReply: .nonAuth)) { harness in
            let error = await captureError { try await harness.session.connect() }
            #expect(error == .authenticationFailed)
            let snapshot = await harness.transport.snapshot()
            #expect(snapshot.closed)
            #expect(snapshot.written.count == 1)
            #expect(harness.authenticator.snapshot().contexts.isEmpty)
        }
    }

    @Test func oversizedFrameAfterAuthClosesChannel() async throws {
        try await withHarness { harness in
            _ = try await harness.channel.connect(timeout: .seconds(2))
            let observation = ChannelObservation()
            let reader = Task {
                do {
                    for try await _ in harness.channel.messages {}
                    await observation.finish(error: nil)
                } catch {
                    await observation.finish(error: error as? CastError)
                }
            }
            defer { reader.cancel() }
            await harness.transport.inject(Data([0, 1, 0, 1]))
            try await waitUntil { await harness.transport.snapshot().closed }
            try await waitUntil { await observation.finished }
            let error = await observation.error
            #expect(error == .frameTooLarge)
        }
    }

    private func rejectedAuthenticationNonce() async throws -> Data {
        try await withHarness(rejectAuthentication: true) { harness in
            let error = await captureError { try await harness.session.connect() }
            #expect(error == .authenticationFailed)
            let snapshot = await harness.transport.snapshot()
            #expect(snapshot.closed)
            #expect(snapshot.written.count == 1)
            #expect(snapshot.written.first?.namespace == CastNamespace.authentication)
            try await assertAuthentication(harness)
            let context = try #require(harness.authenticator.snapshot().contexts.first)
            return context.sentNonce
        }
    }

    private func assertAuthentication(_ harness: SessionHarness) async throws {
        let verification = harness.authenticator.snapshot()
        let transport = await harness.transport.snapshot()
        #expect(verification.contexts.count == 1)
        #expect(verification.responses.count == 1)
        let context = try #require(verification.contexts.first)
        let response = try #require(verification.responses.first)
        let challenge = try #require(transport.challenge)
        #expect(challenge.message.protocolVersion == 0)
        #expect(challenge.message.sourceID == "sender-0")
        #expect(challenge.message.destinationID == "receiver-0")
        #expect(challenge.message.namespace == CastNamespace.authentication)
        #expect(challenge.message.payloadType == .binary)
        #expect(challenge.message.payloadUTF8 == nil)
        #expect(challenge.nonce.count == 16)
        #expect(challenge.nonce == context.sentNonce)
        #expect(challenge.hashAlgorithm == 1)
        #expect(challenge.signatureAlgorithm == nil)
        #expect(context.sentNonce.count == 16)
        #expect(context.tlsCertificate == fixtureTLSCertificate)
        #expect(context.advertisesVideoOutput)
        #expect(response.senderNonce == context.sentNonce)
        #expect(response.hashAlgorithm == .sha256)
        #expect(response.signature == Data([0xa1, 0xa2]))
        #expect(response.deviceCertificate == Data([0xb1, 0xb2]))
    }

    private func withHarness<Result: Sendable>(
        options: ScriptOptions = ScriptOptions(), rejectAuthentication: Bool = false,
        timing: CastSessionTiming? = nil,
        operation: @Sendable (SessionHarness) async throws -> Result
    ) async throws -> Result {
        let transport = ScriptedCastTransport(options: options)
        let authenticator = SessionAuthenticator(reject: rejectAuthentication)
        let device = CastDevice(
            id: "fixture-device", name: "Fixture speaker group", model: "Fixture model",
            host: "127.0.0.1", port: 32_041, isGroup: true, advertisesVideoOutput: true
        )
        let channel = CastChannel(device: device, authenticator: authenticator, transport: transport)
        let session = CastSession(channel: channel, senderID: appSender, timing: timing ?? CastSessionTiming(
            heartbeatInterval: .seconds(30), silenceTimeout: .seconds(60),
            requestTimeout: .seconds(2), launchTimeout: .seconds(2)
        ))
        let harness = SessionHarness(session: session, channel: channel, transport: transport, authenticator: authenticator)
        do {
            let result = try await operation(harness)
            await session.disconnect()
            await transport.close()
            return result
        } catch {
            await session.disconnect()
            await transport.close()
            throw error
        }
    }

    private func captureError(_ operation: @Sendable () async throws -> Void) async -> CastError? {
        do { try await operation(); return nil }
        catch let error as CastError { return error }
        catch { Issue.record("Unexpected error: \(error)"); return nil }
    }

    private func waitUntil(_ predicate: @Sendable () async throws -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while ContinuousClock.now < deadline {
            if try await predicate() { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw SessionTestError.deadlineExceeded
    }

    private func observe(_ session: CastSession, into observations: SessionObservations) async -> [Task<Void, Never>] {
        let receivers = await session.receiverStatuses()
        let media = await session.mediaStatuses()
        let states = await session.states()
        return [
            Task { for await value in receivers { await observations.receiver(value) } },
            Task { for await value in media { await observations.media(value) } },
            Task { for await value in states { await observations.state(value) } },
        ]
    }

    private func assertMessages(_ messages: [CastMessage], expected: [ExpectedMessage]) {
        let actual = messages.filter { $0.namespace != CastNamespace.authentication && $0.namespace != CastNamespace.heartbeat }
        #expect(actual.count == expected.count)
        var requestIDs: [Int] = []
        for (message, expected) in zip(actual, expected) {
            #expect(message.protocolVersion == 0)
            #expect(message.sourceID == expected.source)
            #expect(message.destinationID == expected.destination)
            #expect(message.namespace == expected.namespace)
            #expect(message.payloadType == .string)
            #expect(message.payloadBinary == nil)
            #expect(message.continued == nil)
            #expect(message.remainingLength == nil)
            guard var body = json(message)?.object else { Issue.record("Expected a JSON object"); continue }
            if expected.request {
                let id = body.removeValue(forKey: "requestId")?.integer
                #expect(id != nil)
                if let id { requestIDs.append(id) }
            }
            #expect(body == expected.body)
        }
        for (previous, next) in zip(requestIDs, requestIDs.dropFirst()) { #expect(next == previous + 1) }
    }

    private func expectedConnect(source: String, destination: String) -> ExpectedMessage {
        ExpectedMessage(source: source, destination: destination, namespace: CastNamespace.connection, body: [
            "type": .string("CONNECT"), "userAgent": .string("CastKit"), "connType": .number(0), "origin": .object([:]),
            "senderInfo": .object([
                "sdkType": .number(2), "version": .string("1.0"), "browserVersion": .string("1.0"),
                "platform": .number(4), "systemVersion": .string(ProcessInfo.processInfo.operatingSystemVersionString),
                "connectionType": .number(1),
            ]),
        ], request: false)
    }

    private func expectedReceiver(_ body: [String: CastJSON]) -> ExpectedMessage {
        ExpectedMessage(source: "sender-0", destination: "receiver-0", namespace: CastNamespace.receiver, body: body, request: true)
    }

    private func expectedMedia(_ body: [String: CastJSON]) -> ExpectedMessage {
        ExpectedMessage(source: appSender, destination: appTransport, namespace: CastNamespace.media, body: body, request: true)
    }
}

private let appSender = "sender-session-fixture"
private let appTransport = "web-session-fixture"
private let appSession = "receiver-session-fixture"
private let fixtureTLSCertificate = Data([0x30, 0x03, 0x02, 0x01, 0x7f])

private func fixtureMedia() -> CastMedia {
    CastMedia(
        contentID: "http://127.0.0.1:8090/song.m4a?token=fixture", contentType: "audio/mp4",
        title: "Fixture song", artist: "Fixture artist", album: "Fixture album",
        images: [URL(string: "http://127.0.0.1:8090/art.jpg")!], duration: 240
    )
}

private let expectedMediaJSON = CastJSON.object([
    "contentId": .string("http://127.0.0.1:8090/song.m4a?token=fixture"), "contentType": .string("audio/mp4"),
    "streamType": .string("BUFFERED"), "duration": .number(240),
    "metadata": .object([
        "metadataType": .number(3), "title": .string("Fixture song"), "artist": .string("Fixture artist"),
        "albumName": .string("Fixture album"),
        "images": .array([.object(["url": .string("http://127.0.0.1:8090/art.jpg")])]),
    ]),
])

private func json(_ message: CastMessage) -> CastJSON? {
    guard let data = message.jsonData else { return nil }
    return try? JSONDecoder().decode(CastJSON.self, from: data)
}

private struct ExpectedMessage: Sendable {
    let source: String
    let destination: String
    let namespace: String
    let body: [String: CastJSON]
    let request: Bool
}

private struct SessionHarness: Sendable {
    let session: CastSession
    let channel: CastChannel
    let transport: ScriptedCastTransport
    let authenticator: SessionAuthenticator
}

private enum SessionTestError: Error { case deadlineExceeded }

// NSLock guards SessionAuthenticator.contexts and responses across synchronous verification calls.
private final class SessionAuthenticator: CastDeviceAuthenticating, @unchecked Sendable {
    struct Snapshot: Sendable {
        let contexts: [CastAuthContext]
        let responses: [CastAuthResponse]
    }

    private let lock = NSLock()
    private let reject: Bool
    private var contexts: [CastAuthContext] = []
    private var responses: [CastAuthResponse] = []

    init(reject: Bool) { self.reject = reject }

    func verify(_ response: CastAuthResponse, context: CastAuthContext) throws -> CastDeviceIdentity {
        lock.withLock { contexts.append(context); responses.append(response) }
        if reject { throw CastError.authenticationFailed }
        return CastDeviceIdentity(commonName: "Fixture Cast device", isAudioOnly: false)
    }

    func snapshot() -> Snapshot { lock.withLock { Snapshot(contexts: contexts, responses: responses) } }
}

private actor SessionObservations {
    struct Snapshot: Sendable {
        let receivers: [CastReceiverStatus]
        let media: [CastMediaStatus?]
        let states: [CastSessionState]
    }
    private var receivers: [CastReceiverStatus] = []
    private var mediaValues: [CastMediaStatus?] = []
    private var states: [CastSessionState] = []
    func receiver(_ value: CastReceiverStatus) { receivers.append(value) }
    func media(_ value: CastMediaStatus?) { mediaValues.append(value) }
    func state(_ value: CastSessionState) { states.append(value) }
    func snapshot() -> Snapshot { Snapshot(receivers: receivers, media: mediaValues, states: states) }
}

private actor ChannelObservation {
    private(set) var finished = false
    private(set) var error: CastError?
    func finish(error: CastError?) { self.error = error; finished = true }
}

private struct ScriptOptions: Sendable {
    enum AuthReply: Sendable { case success, error, silent, nonAuth }
    var authReply: AuthReply = .success
    var initiallyRunning = false
    var binaryJSON = false
    var replyToHeartbeat = true
    var unmatchedRequestType: String?
}

private actor ScriptedCastTransport: CastTransport {
    struct Challenge: Sendable {
        let message: CastMessage
        let nonce: Data
        let hashAlgorithm: UInt64
        let signatureAlgorithm: UInt64?
    }

    struct Snapshot: Sendable {
        let written: [CastMessage]
        let delivered: [CastMessage]
        let challenge: Challenge?
        let closed: Bool
    }

    private let options: ScriptOptions
    private var opened = false
    private var closed = false
    private var incoming: [Data] = []
    private var reading: CheckedContinuation<Data?, any Error>?
    private var framer = CastFramer()
    private var written: [CastMessage] = []
    private var delivered: [CastMessage] = []
    private var challenge: Challenge?
    private var running: Bool
    private var loaded = false
    private var media = CastJSON.null
    private var mediaState = CastPlayerState.paused
    private var currentTime: Double = 0
    private var queueItems: [CastJSON] = []
    private var currentItemID: Int?
    private var streamLevel: Double = 0.6
    private var level: Double = 0.5
    private var muted = false

    init(options: ScriptOptions) { self.options = options; running = options.initiallyRunning }

    // Open and write complete on this actor; read is the only suspended operation.
    func open() async throws -> Data {
        guard !opened, !closed else { throw CastError.connectionClosed }
        opened = true
        return fixtureTLSCertificate
    }

    func read() async throws -> Data? {
        if closed { return nil }
        guard opened, reading == nil else { throw CastError.invalidState }
        if !incoming.isEmpty { return incoming.removeFirst() }
        return try await withCheckedThrowingContinuation { reading = $0 }
    }

    func write(_ data: Data) async throws {
        guard opened, !closed else { throw CastError.connectionClosed }
        let messages = try framer.append(data)
        for message in messages {
            written.append(message)
            if message.namespace == CastNamespace.authentication { try respondToAuthentication(message) }
            else { try respond(to: message) }
        }
    }

    func close() {
        guard !closed else { return }
        closed = true
        incoming.removeAll()
        let continuation = reading
        reading = nil
        continuation?.resume(returning: nil)
    }

    func snapshot() -> Snapshot { Snapshot(written: written, delivered: delivered, challenge: challenge, closed: closed) }
    func inject(_ data: Data) { enqueue(data) }

    func broadcastMedia(time: Double, state: CastPlayerState, mediaSessionID: Int = 41) throws {
        currentTime = time
        mediaState = state
        try sendJSON(
            ["type": .string("MEDIA_STATUS"), "requestId": .number(0),
             "status": .array([mediaStatus(id: mediaSessionID, includeMedia: false)])],
            namespace: CastNamespace.media, source: appTransport, destination: "*"
        )
    }

    func broadcastStatus(_ fields: [String: CastJSON]) throws {
        try sendJSON(
            ["type": .string("MEDIA_STATUS"), "requestId": .number(0), "status": .array([.object(fields)])],
            namespace: CastNamespace.media, source: appTransport, destination: "*"
        )
    }

    func broadcastReceiverVolume(level: Double, muted: Bool) throws {
        self.level = level
        self.muted = muted
        try sendJSON(receiverResponse(id: 0), namespace: CastNamespace.receiver, source: "receiver-0", destination: "*")
    }

    func sendHeartbeatPing() throws {
        try sendJSON(["type": .string("PING")], namespace: CastNamespace.heartbeat, source: "receiver-0", destination: "sender-0")
    }

    private func respondToAuthentication(_ message: CastMessage) throws {
        guard let payload = message.payloadBinary else { throw CastError.invalidMessage }
        var envelope = CastProtoReader(data: payload)
        var nonce: Data?
        var hashAlgorithm: UInt64?
        var signatureAlgorithm: UInt64?
        while let field = try envelope.nextField() {
            if field.number == 1 {
                var body = CastProtoReader(data: try envelope.bytes(wire: field.wire))
                while let item = try body.nextField() {
                    switch item.number {
                    case 1: signatureAlgorithm = try body.varint(wire: item.wire)
                    case 2: nonce = try body.bytes(wire: item.wire)
                    case 3: hashAlgorithm = try body.varint(wire: item.wire)
                    default: try body.skip(wire: item.wire)
                    }
                }
            } else { try envelope.skip(wire: field.wire) }
        }
        guard let nonce, let hashAlgorithm else { throw CastError.invalidMessage }
        challenge = Challenge(message: message, nonce: nonce, hashAlgorithm: hashAlgorithm, signatureAlgorithm: signatureAlgorithm)
        switch options.authReply {
        case .silent: return
        case .nonAuth:
            try sendHeartbeatPing()
        case .error:
            var error = CastProtoWriter()
            try error.appendVarint(field: 1, value: 0)
            var envelope = CastProtoWriter()
            try envelope.appendBytes(field: 3, value: error.data)
            try sendAuth(envelope.data)
        case .success:
            var response = CastProtoWriter()
            try response.appendBytes(field: 1, value: Data([0xa1, 0xa2]))
            try response.appendBytes(field: 2, value: Data([0xb1, 0xb2]))
            try response.appendBytes(field: 3, value: Data([0xc1]))
            try response.appendBytes(field: 5, value: nonce)
            try response.appendVarint(field: 6, value: 1)
            var envelope = CastProtoWriter()
            try envelope.appendBytes(field: 2, value: response.data)
            try sendAuth(envelope.data)
        }
    }

    private func sendAuth(_ payload: Data) throws {
        try send(CastMessage(
            sourceID: "receiver-0", destinationID: "sender-0", namespace: CastNamespace.authentication,
            payloadType: .binary, payloadBinary: payload
        ))
    }

    private func respond(to message: CastMessage) throws {
        guard let body = json(message), let type = body["type"].string else { throw CastError.invalidMessage }
        if message.namespace == CastNamespace.connection { return }
        if message.namespace == CastNamespace.heartbeat {
            if type == "PING", options.replyToHeartbeat {
                try sendJSON(["type": .string("PONG")], namespace: CastNamespace.heartbeat, source: "receiver-0", destination: message.sourceID)
            }
            return
        }
        guard let id = body["requestId"].integer else { throw CastError.invalidMessage }
        if type == options.unmatchedRequestType {
            try sendJSON(receiverResponse(id: id), namespace: CastNamespace.receiver, source: "receiver-0", destination: message.sourceID)
            let status: [String: CastJSON] = ["type": .string("MEDIA_STATUS"), "requestId": .number(Double(id)),
                                              "status": .array([mediaStatus(id: 41, includeMedia: false)])]
            try sendJSON(status, namespace: CastNamespace.media, source: "web-other", destination: message.sourceID)
            try sendJSON(status, namespace: CastNamespace.media, source: appTransport, destination: "another-sender")
            var wrongID = status
            wrongID["requestId"] = .number(Double(id + 1000))
            try sendJSON(wrongID, namespace: CastNamespace.media, source: appTransport, destination: message.sourceID)
            return
        }
        if message.namespace == CastNamespace.receiver {
            if type == "LAUNCH" { running = true }
            if type == "STOP" { running = false }
            if let value = body["volume"]["level"].number { level = value }
            if let value = body["volume"]["muted"].bool { muted = value }
            try sendJSON(receiverResponse(id: id), namespace: CastNamespace.receiver, source: "receiver-0", destination: message.sourceID)
        } else if message.namespace == CastNamespace.media {
            if type == "LOAD" {
                loaded = true
                media = body["media"]
                queueItems = []
                currentItemID = nil
                currentTime = body["currentTime"].number ?? 0
                mediaState = body["autoplay"].bool == false ? .paused : .playing
            } else if type == "QUEUE_LOAD" {
                loaded = true
                queueItems = (body["items"].array ?? []).enumerated().map { index, item in
                    var fields = item.object ?? [:]
                    fields["itemId"] = .number(Double(index + 101))
                    return .object(fields)
                }
                let index = body["startIndex"].integer ?? 0
                let current = queueItems[index]
                currentItemID = current["itemId"].integer
                media = current["media"]
                currentTime = body["currentTime"].number ?? 0
                mediaState = current["autoplay"].bool == false ? .paused : .playing
            } else if type == "QUEUE_INSERT" {
                for item in body["items"].array ?? [] {
                    var fields = item.object ?? [:]
                    fields["itemId"] = .number(Double(queueItems.count + 101))
                    queueItems.append(.object(fields))
                }
            } else if type == "SET_VOLUME" {
                streamLevel = body["volume"]["level"].number ?? streamLevel
            } else if type == "PLAY" { mediaState = .playing }
            else if type == "PAUSE" { mediaState = .paused }
            else if type == "SEEK" {
                currentTime = body["currentTime"].number ?? currentTime
                if body["resumeState"].string == "PLAYBACK_START" { mediaState = .playing }
                if body["resumeState"].string == "PLAYBACK_PAUSE" { mediaState = .paused }
            } else if type == "STOP" { loaded = false }
            try sendJSON([
                "type": .string("MEDIA_STATUS"), "requestId": .number(Double(id)),
                "status": .array(loaded ? [mediaStatus(id: 41, includeMedia: type == "LOAD" || type == "QUEUE_LOAD")] : []),
            ], namespace: CastNamespace.media, source: appTransport, destination: message.sourceID)
        }
    }

    private func receiverResponse(id: Int) -> [String: CastJSON] {
        var status: [String: CastJSON] = [
            "volume": .object(["level": .number(level), "muted": .bool(muted), "controlType": .string("attenuation")]),
            "isActiveInput": .bool(true), "isStandBy": .bool(false),
        ]
        if running {
            status["applications"] = .array([.object([
                "appId": .string("CC1AD845"), "sessionId": .string(appSession), "transportId": .string(appTransport),
                "displayName": .string("Default Media Receiver"), "isIdleScreen": .bool(false),
                "namespaces": .array([.object(["name": .string(CastNamespace.media)]), .string("urn:x-cast:example")]),
            ])])
        }
        return ["type": .string("RECEIVER_STATUS"), "requestId": .number(Double(id)), "status": .object(status)]
    }

    private func mediaStatus(id: Int, includeMedia: Bool) -> CastJSON {
        var status: [String: CastJSON] = [
            "mediaSessionId": .number(Double(id)), "playerState": .string(mediaState.rawValue),
            "currentTime": .number(currentTime), "volume": .object(["level": .number(streamLevel), "muted": .bool(false)]),
            "supportedMediaCommands": .number(7),
        ]
        if includeMedia { status["media"] = media }
        if let currentItemID { status["currentItemId"] = .number(Double(currentItemID)) }
        if !queueItems.isEmpty { status["items"] = .array(queueItems) }
        return .object(status)
    }

    private func sendJSON(_ object: [String: CastJSON], namespace: String, source: String, destination: String) throws {
        let data = try JSONEncoder().encode(CastJSON.object(object))
        let message = options.binaryJSON
            ? CastMessage(protocolVersion: 3, sourceID: source, destinationID: destination, namespace: namespace, payloadBinary: data)
            : CastMessage(sourceID: source, destinationID: destination, namespace: namespace, payloadUTF8: String(decoding: data, as: UTF8.self))
        try send(message)
    }

    private func send(_ message: CastMessage) throws {
        delivered.append(message)
        let frame = try CastFramer.frame(message)
        enqueue(Data(frame.prefix(2)))
        enqueue(Data(frame.dropFirst(2)))
    }

    private func enqueue(_ data: Data) {
        guard !closed else { return }
        if let continuation = reading {
            reading = nil
            continuation.resume(returning: data)
        } else { incoming.append(data) }
    }
}
