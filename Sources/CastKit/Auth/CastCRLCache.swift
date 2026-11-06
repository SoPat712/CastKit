import Foundation
import Synchronization

/// Stores the freshest signed CRL bundle seen across connections. Loaded bytes are always reverified.
public protocol CastCRLCache: Sendable {
    /// Returns the previously saved bundle, if any.
    func load() -> Data?
    /// Saves a verified bundle if its signed issue time is newer than the stored issue time.
    func store(_ bundle: Data, issuedAt: Date)
}

/// A process-local CRL cache. Applications can inject a persistent implementation instead.
public final class InMemoryCastCRLCache: CastCRLCache {
    private struct Entry: Sendable {
        var bundle: Data
        var issuedAt: Date
    }

    private let entry = Mutex<Entry?>(nil)

    /// Creates an empty cache.
    public init() {}

    /// Returns the most recently issued bundle stored in this cache.
    public func load() -> Data? {
        entry.withLock { $0?.bundle }
    }

    /// Replaces the saved bundle only when the supplied issue time is newer.
    public func store(_ bundle: Data, issuedAt: Date) {
        entry.withLock {
            if let saved = $0, saved.issuedAt >= issuedAt { return }
            $0 = Entry(bundle: bundle, issuedAt: issuedAt)
        }
    }
}
