# CastKit

A Google Cast (Cast v2) sender for Apple platforms in pure Swift. It uses no Google SDK and has no dependencies, only Apple's frameworks (Network, Security, CryptoKit). It finds Chromecast and Google Home devices on the local network, checks that each one is a genuine Cast device, and plays audio on it through Google's Default Media Receiver.

CastKit talks only to the device you connect to. It makes no other network requests: no analytics and no Google services.

## Device check
Before CastKit sends anything to a device, the device must prove it's genuine. Google's own senders do the same check, and CastKit is at least as strict:

- **Signed challenge.** The device signs a random challenge and its own TLS certificate with its device key.
- **Trusted chain.** The device's certificate must chain to Google's Cast root certificates, which are built in.
- **Revocation list.** CastKit requires a valid revocation list and rejects revoked certificates.
  - If a device doesn't send a fresh list, the newest valid list you cached earlier is used.
  - With no valid list at all, the device is rejected.
- **Expired chains.** Expired 2nd-generation Chromecast chains get the same 7-day grace period Chromium allows.
- **Audio-only devices.** A device whose certificate says it's audio-only must not advertise video.
- **Challenge echo (stricter than Chromium).** The device must echo the challenge exactly. Chromium only logs a mismatch.

Persist the revocation list by implementing `CastCRLCache` (for example, as a small file). The list is public data.

## Requirements
- iOS 18 or macOS 15, Swift 6.
- **iOS apps** need to declare both of these in Info.plist, or iOS never shows the device list:
  - `NSBonjourServices` containing `_googlecast._tcp`
  - an `NSLocalNetworkUsageDescription`

## Usage
```swift
import CastKit

let discovery = CastDiscovery()
await discovery.start()
for await devices in await discovery.devices() {
    guard let speaker = devices.first else { continue }
    await discovery.stop()

    let session = CastSession(device: speaker, authenticator: CastDeviceVerifier(), userAgent: "MyApp/1.0")
    try await session.connect()           // device check, then join or launch the Default Media Receiver
    try await session.load(CastMedia(
        contentID: "https://music.example/stream/123.mp3", contentType: "audio/mpeg",
        title: "Song", artist: "Artist"
    ))
    for await status in await session.mediaStatuses() {
        print(status?.playerState as Any)
    }
}
```

The receiver fetches the media URL itself, so the URL must be reachable from the device (on the same network, or public HTTPS) and carry any authorization it needs.

What else you can do:
- **Queues:** `loadQueue` (with per-item `customData`) and `insertQueueItems`.
- **Playback:** `play`, `pause` and `seek`.
- **Volume:** `setVolume` sets the device volume, and `setStreamVolume` sets the stream volume when the receiver supports it.
- **Status:** `receiverStatuses`, `mediaStatuses` and `states` are async streams.
- **Reconnecting:** call `connect(launchIfNeeded: false)` and then `adoptMediaSession` to rejoin a running receiver.

## License
MIT. See [LICENSE](LICENSE). The built-in root certificates are Google's public Cast root certificates.
