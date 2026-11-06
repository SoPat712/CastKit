import Foundation

/// Receiver or media volume; fixed receivers may ignore level changes.
public struct CastVolume: Sendable, Equatable {
    /// A level from zero through one when supplied.
    public let level: Double?
    /// Whether the receiver reports muted audio.
    public let muted: Bool?
    /// Receiver control mode, including fixed, attenuation, or master.
    public let controlType: String?
    /// The receiver's suggested volume step.
    public let stepInterval: Double?

    /// Creates receiver or stream volume information with optional reported fields.
    public init(level: Double? = nil, muted: Bool? = nil, controlType: String? = nil, stepInterval: Double? = nil) {
        self.level = level
        self.muted = muted
        self.controlType = controlType
        self.stepInterval = stepInterval
    }
}

/// An application advertised in RECEIVER_STATUS.
public struct CastApplication: Sendable, Equatable {
    /// The receiver application ID.
    public let appID: String
    /// The running application instance ID, required for receiver STOP.
    public let sessionID: String
    /// The endpoint used for application traffic.
    public let transportID: String
    /// The application's display name when supplied.
    public let displayName: String?
    /// Whether this is an idle backdrop or ambient application.
    public let isIdleScreen: Bool
    /// Supported namespaces, accepting both object and legacy string records.
    public let namespaces: [String]
}

/// Platform status, including device or speaker-group volume.
public struct CastReceiverStatus: Sendable, Equatable {
    /// Running applications; empty when the receiver omits applications while idle.
    public let applications: [CastApplication]
    /// Device or group volume, independent of the media stream volume.
    public let volume: CastVolume?
    /// Whether a video receiver is the active input, when supplied.
    public let isActiveInput: Bool?
    /// Whether a video receiver is in standby, when supplied.
    public let isStandBy: Bool?

    /// Creates a platform observation, including device or speaker-group volume.
    public init(
        applications: [CastApplication] = [], volume: CastVolume? = nil,
        isActiveInput: Bool? = nil, isStandBy: Bool? = nil
    ) {
        self.applications = applications
        self.volume = volume
        self.isActiveInput = isActiveInput
        self.isStandBy = isStandBy
    }
}

/// Receiver-fetchable media and music metadata for a buffered track.
public struct CastMedia: Sendable, Equatable {
    /// The receiver-fetchable media URL as a string.
    public let contentID: String
    /// The media MIME type.
    public let contentType: String
    /// Music-track title.
    public let title: String?
    /// Music-track artist.
    public let artist: String?
    /// Music-track album name.
    public let album: String?
    /// Receiver-fetchable artwork URLs.
    public let images: [URL]
    /// Track length in seconds, when known.
    public let duration: TimeInterval?
    /// Sender-defined string values retained by the receiver with this media.
    public let customData: [String: String]?

    /// URLs must be reachable by the receiver, including any required authorization.
    public init(
        contentID: String, contentType: String, title: String? = nil, artist: String? = nil,
        album: String? = nil, images: [URL] = [], duration: TimeInterval? = nil,
        customData: [String: String]? = nil
    ) {
        self.contentID = contentID
        self.contentType = contentType
        self.title = title
        self.artist = artist
        self.album = album
        self.images = images
        self.duration = duration
        self.customData = customData
    }
}

/// A queue entry sent without an item ID; the receiver assigns its identifier.
public struct CastQueueItem: Sendable, Equatable {
    /// Receiver-fetchable media for this entry.
    public let media: CastMedia
    /// Whether playback starts automatically when this entry becomes current.
    public let autoplay: Bool
    /// Seconds before the preceding entry ends to request preloading; negative disables it.
    public let preloadTime: TimeInterval
    /// Sender-defined string values associated with this queue entry.
    public let customData: [String: String]?

    /// Creates an entry with an optional preload hint and sender-defined identity.
    public init(
        media: CastMedia, autoplay: Bool = true, preloadTime: TimeInterval = 15,
        customData: [String: String]? = nil
    ) {
        self.media = media
        self.autoplay = autoplay
        self.preloadTime = preloadTime
        self.customData = customData
    }
}

/// A receiver-assigned queue entry with cached media and sender-defined values.
public struct CastQueueItemStatus: Sendable, Equatable {
    /// The receiver-assigned queue entry ID.
    public let itemID: Int
    /// Media retained when incremental queue updates omit it.
    public let media: CastMedia?
    /// Sender-defined string values associated with this queue entry.
    public let customData: [String: String]?

    /// Creates a reported queue entry, including entries whose media has not arrived.
    public init(itemID: Int, media: CastMedia? = nil, customData: [String: String]? = nil) {
        self.itemID = itemID
        self.media = media
        self.customData = customData
    }
}

/// The media receiver's current playback state.
public enum CastPlayerState: String, Sendable, Equatable {
    case idle = "IDLE"
    case playing = "PLAYING"
    case paused = "PAUSED"
    case buffering = "BUFFERING"
    case loading = "LOADING"
    case unknown = "UNKNOWN"
}

/// One media session. Media information is retained when incremental updates omit it.
public struct CastMediaStatus: Sendable, Equatable {
    /// The current media instance ID, which becomes invalid after media STOP.
    public let mediaSessionID: Int
    /// The receiver's playback state.
    public let playerState: CastPlayerState
    /// The receiver's idle reason, including FINISHED, CANCELLED, INTERRUPTED, or ERROR.
    public let idleReason: String?
    /// Playback position in seconds.
    public let currentTime: TimeInterval
    /// Cached media information for this media session.
    public let media: CastMedia?
    /// Stream volume when supplied by the media receiver.
    public let volume: CastVolume?
    /// The currently playing queue entry, when reported.
    public let currentItemID: Int?
    /// The queue entry currently loading, when reported.
    public let loadingItemID: Int?
    /// The queue entry the receiver has preloaded, when reported.
    public let preloadedItemID: Int?
    /// Queue entries in receiver order, retaining omitted media for each entry.
    public let items: [CastQueueItemStatus]
    /// The receiver's media command bit flags, when reported.
    public let supportedMediaCommands: Int?
    /// Whether the receiver advertises stream volume control (command bit 4).
    public var supportsStreamVolume: Bool { (supportedMediaCommands ?? 0) & 4 != 0 }
    /// Cached track length in seconds.
    public var duration: TimeInterval? { media?.duration }

    /// Creates playback status with optional queue and command capability information.
    public init(
        mediaSessionID: Int, playerState: CastPlayerState, idleReason: String? = nil,
        currentTime: TimeInterval = 0, media: CastMedia? = nil, volume: CastVolume? = nil,
        currentItemID: Int? = nil, loadingItemID: Int? = nil, preloadedItemID: Int? = nil,
        items: [CastQueueItemStatus] = [], supportedMediaCommands: Int? = nil
    ) {
        self.mediaSessionID = mediaSessionID
        self.playerState = playerState
        self.idleReason = idleReason
        self.currentTime = currentTime
        self.media = media
        self.volume = volume
        self.currentItemID = currentItemID
        self.loadingItemID = loadingItemID
        self.preloadedItemID = preloadedItemID
        self.items = items
        self.supportedMediaCommands = supportedMediaCommands
    }
}

/// The desired playback state after seeking. Nil leaves the state unchanged.
public enum CastSeekResumeState: String, Sendable {
    case play = "PLAYBACK_START"
    case pause = "PLAYBACK_PAUSE"
}

/// Session lifecycle. Ended sessions never automatically launch or take playback back.
public enum CastSessionState: Sendable, Equatable {
    case disconnected
    case connecting
    case connected
    case ended
    case failed(CastError)
}

enum CastJSON: Sendable, Equatable, Codable {
    case object([String: CastJSON])
    case array([CastJSON])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode([String: CastJSON].self) { self = .object(value) }
        else { self = .array(try container.decode([CastJSON].self)) }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    subscript(_ key: String) -> CastJSON { object?[key] ?? .null }
    var object: [String: CastJSON]? { if case .object(let value) = self { value } else { nil } }
    var array: [CastJSON]? { if case .array(let value) = self { value } else { nil } }
    var string: String? { if case .string(let value) = self { value } else { nil } }
    var number: Double? { if case .number(let value) = self { value } else { nil } }
    var bool: Bool? { if case .bool(let value) = self { value } else { nil } }
    var stringDictionary: [String: String]? {
        guard let object else { return nil }
        return object.compactMapValues(\.string)
    }
    var integer: Int? {
        guard let number, number.isFinite, number.rounded() == number,
              number >= 0, number <= Double(Int32.max) else { return nil }
        return Int(number)
    }
}

extension CastVolume {
    init?(_ json: CastJSON) {
        guard json.object != nil else { return nil }
        level = json["level"].number
        muted = json["muted"].bool
        controlType = json["controlType"].string
        stepInterval = json["stepInterval"].number
    }
}

extension CastReceiverStatus {
    init(_ json: CastJSON) throws {
        guard json.object != nil else { throw CastError.invalidMessage }
        applications = (json["applications"].array ?? []).compactMap { app in
            guard let appID = app["appId"].string, let sessionID = app["sessionId"].string,
                  let transportID = app["transportId"].string else { return nil }
            return CastApplication(
                appID: appID, sessionID: sessionID, transportID: transportID,
                displayName: app["displayName"].string, isIdleScreen: app["isIdleScreen"].bool ?? false,
                namespaces: (app["namespaces"].array ?? []).compactMap { $0["name"].string ?? $0.string }
            )
        }
        volume = CastVolume(json["volume"])
        isActiveInput = json["isActiveInput"].bool
        isStandBy = json["isStandBy"].bool
    }
}

extension CastMedia {
    var json: CastJSON {
        var metadata: [String: CastJSON] = ["metadataType": .number(3)]
        if let title { metadata["title"] = .string(title) }
        if let artist { metadata["artist"] = .string(artist) }
        if let album { metadata["albumName"] = .string(album) }
        metadata["images"] = .array(images.map { .object(["url": .string($0.absoluteString)]) })
        var media: [String: CastJSON] = [
            "contentId": .string(contentID), "contentType": .string(contentType),
            "streamType": .string("BUFFERED"), "metadata": .object(metadata)
        ]
        if let duration { media["duration"] = .number(duration) }
        if let customData { media["customData"] = .object(customData.mapValues(CastJSON.string)) }
        return .object(media)
    }

    init?(_ json: CastJSON) {
        guard let contentID = json["contentId"].string,
              let contentType = json["contentType"].string else { return nil }
        let metadata = json["metadata"]
        self.init(
            contentID: contentID, contentType: contentType, title: metadata["title"].string,
            artist: metadata["artist"].string, album: metadata["albumName"].string,
            images: (metadata["images"].array ?? []).compactMap { $0["url"].string.flatMap(URL.init(string:)) },
            duration: json["duration"].number, customData: json["customData"].stringDictionary
        )
    }
}

extension CastQueueItem {
    var json: CastJSON {
        var item: [String: CastJSON] = [
            "media": media.json, "autoplay": .bool(autoplay), "preloadTime": .number(preloadTime)
        ]
        if let customData { item["customData"] = .object(customData.mapValues(CastJSON.string)) }
        return .object(item)
    }
}
