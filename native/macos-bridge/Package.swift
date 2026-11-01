// swift-tools-version:5.9
import PackageDescription

// macOS bridge: CoreWLAN + SystemConfiguration metadata for Calm.
// Runs as a sidecar CLI (`calm-wifi-probe`) that prints canonical JSON to stdout;
// Rust core parses it. Transport choice (sidecar vs. FFI) is a WP1 spike decision.
let package = Package(
    name: "CalmMacOSBridge",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "CalmMacOSBridge", targets: ["CalmMacOSBridge"]),
        .executable(name: "calm-wifi-probe", targets: ["calm-wifi-probe"]),
    ],
    targets: [
        .target(name: "CalmMacOSBridge"),
        .executableTarget(name: "calm-wifi-probe", dependencies: ["CalmMacOSBridge"]),
        .testTarget(name: "CalmMacOSBridgeTests", dependencies: ["CalmMacOSBridge"]),
    ]
)
