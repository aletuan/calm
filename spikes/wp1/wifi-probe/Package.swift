// swift-tools-version:5.9
import PackageDescription

// WP1 spike — throwaway. Answers: which process can read SSID/BSSID via CoreWLAN
// once Location is authorized (in-process GUI app, LSUIElement agent, child CLI,
// Terminal-launched CLI)?
let package = Package(
    name: "WifiProbeSpike",
    platforms: [.macOS(.v14)],
    targets: [
        .target(
            name: "ProbeCore",
            linkerSettings: [.linkedFramework("CoreWLAN"), .linkedFramework("CoreLocation")]
        ),
        .executableTarget(name: "probe-cli", dependencies: ["ProbeCore"]),
        .executableTarget(
            name: "ProbeApp",
            dependencies: ["ProbeCore"],
            linkerSettings: [.linkedFramework("AppKit")]
        ),
    ]
)
