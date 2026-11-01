import AppKit
import CoreLocation
import ProbeCore

/// GUI container app. Sequence:
/// 1. snapshot before authorization        -> s1-<prefix>-before-auth.json
/// 2. request When-In-Use Location (prompt)
/// 3. snapshot in-process after decision   -> s1-<prefix>-in-process.json
/// 4. spawn bundled probe-cli as child     -> s1-<prefix>-child-cli.json
/// Launch with `open`, NOT by running the binary from Terminal (Terminal would
/// become the responsible process and pollute the result).
final class AppDelegate: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    let args = Args.parse()
    var done = false
    var prefix: String { args.variant }

    func applicationDidFinishLaunching(_ notification: Notification) {
        manager.delegate = self
        Probe.write(Probe.snapshot(variant: "\(prefix)-before-auth", raw: args.raw, manager: manager), to: args.outDir)
        if manager.authorizationStatus.rawValue == 0 {
            NSApp.activate(ignoringOtherApps: true)
            manager.requestWhenInUseAuthorization()
        } else {
            finish(reason: "already-decided")
        }
        // Do not hang forever if no prompt appears (itself a finding).
        DispatchQueue.main.asyncAfter(deadline: .now() + 90) { self.finish(reason: "timeout-90s") }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        if manager.authorizationStatus.rawValue != 0 { finish(reason: "decided") }
    }

    func finish(reason: String) {
        guard !done else { return }
        done = true
        Probe.write(Probe.snapshot(variant: "\(prefix)-in-process", raw: args.raw, manager: manager), to: args.outDir)

        let cli = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/probe-cli")
        let p = Process()
        p.executableURL = cli
        var childArgs = ["--variant", "\(prefix)-child-cli"]
        if let d = args.outDir { childArgs += ["--out-dir", d] }
        if args.raw { childArgs.append("--raw") }
        p.arguments = childArgs
        do {
            try p.run()
            p.waitUntilExit()
        } catch {
            FileHandle.standardError.write(Data("child launch failed: \(error)\n".utf8))
        }
        if let d = args.outDir {
            let note = "finish_reason=\(reason)\n"
            try? note.write(toFile: d + "/s1-\(prefix)-finish.txt", atomically: true, encoding: .utf8)
        }
        NSApp.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
