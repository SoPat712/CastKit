import Foundation
import Testing
@testable import CastKit

struct CastKitDiscoveryTests {
    @Test func parsesUsefulTXTAndPreservesGroupPort() throws {
        let device = try #require(CastDevice(txt: [
            "id": "97F763F8-24B6-4865-AFA1-F6D29237F1B2", "fn": "Whole Home",
            "md": "Google Cast Group", "ca": "199204", "ve": "05", "st": "1",
            "rs": "Music", "ic": "/setup/icon.png", "cd": "unknown", "bs": "unknown"
        ], host: "192.168.1.20", port: 32041))
        #expect(device.id == "97F763F8-24B6-4865-AFA1-F6D29237F1B2")
        #expect(device.name == "Whole Home")
        #expect(device.model == "Google Cast Group")
        #expect(device.host == "192.168.1.20")
        #expect(device.port == 32041)
        #expect(device.isGroup)
        #expect(!device.advertisesVideoOutput)
        #expect(device.capabilities == 199204)
        #expect(device.protocolVersion == 5)
        #expect(device.status == 1)
        #expect(device.runningAppStatus == "Music")
        #expect(device.iconPath == "/setup/icon.png")
    }

    @Test func videoCapabilityIgnoresUnknownHighBits() throws {
        let device = try #require(CastDevice(
            txt: ["id": "tv", "fn": "Living Room", "ca": "268805"], host: "tv.local", port: 8009
        ))
        #expect(device.advertisesVideoOutput)
        #expect(!device.isGroup)
        #expect(device.capabilities == 268805)
        let group = try #require(CastDevice(
            txt: ["id": "group", "fn": "Rooms", "ca": "32"], host: "leader.local", port: 8009
        ))
        #expect(group.isGroup)
    }

    @Test func rejectsMissingIdentityOrFriendlyName() {
        for txt in [["fn": "Room"], ["id": "id"], ["id": "", "fn": "Room"], ["id": "id", "fn": ""]] {
            #expect(CastDevice(txt: txt, host: "host.local", port: 8009) == nil)
        }
        #expect(CastDevice(txt: ["id": "id", "fn": "Room"], host: "host.local", port: 0) == nil)
    }

    @Test func absentOptionalTXTDoesNotRejectDevice() throws {
        let device = try #require(CastDevice(txt: ["id": "id", "fn": "Room"], host: "host.local", port: 8009))
        #expect(device.model.isEmpty)
        #expect(device.capabilities == 0)
        #expect(device.runningAppStatus == nil)
        #expect(device.protocolVersion == nil)
        #expect(device.status == nil)
        #expect(device.iconPath == nil)
    }
}
