import Foundation

/// A discovery, transport, authentication, or receiver failure.
public enum CastError: Error, Sendable, Equatable {
    case connectionFailed
    case connectionClosed
    case authenticationFailed
    case timedOut
    case invalidMessage
    case frameTooLarge
    case invalidState
    case invalidArgument
    case deviceLost
    case sessionEnded
    case requestFailed(String)
}
