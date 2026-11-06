// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CastKit",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "CastKit", targets: ["CastKit"]),
    ],
    targets: [
        .target(name: "CastKit"),
        .testTarget(name: "CastKitTests", dependencies: ["CastKit"]),
    ],
    swiftLanguageModes: [.v6]
)
