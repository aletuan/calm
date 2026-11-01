import CoreLocation
import CoreWLAN
import Foundation

/// A value we need to know is *present*, without leaking it by default.
public struct Field: Codable {
    public let present: Bool
    /// Masked unless `--raw` was passed.
    public let value: String?
}

public struct ProbeResult: Codable {
    public let variant: String
    public let timestamp: String
    public let pid: Int32
    public let parentPid: Int32
    public let executable: String
    public let bundleId: String?
    public let osVersion: String
    public let locationServicesEnabled: Bool
    public let authorization: String
    public let interfaceFound: Bool
    public let interfaceName: String?
    public let ssid: Field
    public let bssid: Field
    public let channel: String?
    public let rssi: Int?
    public let noise: Int?
    public let security: String?
    public let phyMode: String?
    public let transmitRate: Double?
    public let countryCode: String?
}

public enum Probe {
    public static func authorizationName(_ s: CLAuthorizationStatus) -> String {
        switch s.rawValue {
        case 0: return "notDetermined"
        case 1: return "restricted"
        case 2: return "denied"
        case 3: return "authorizedAlways"
        case 4: return "authorizedWhenInUse"
        default: return "unknown(\(s.rawValue))"
        }
    }

    static func securityName(_ raw: Int) -> String {
        let names = [
            0: "none", 1: "wep", 2: "wpaPersonal", 3: "wpaPersonalMixed", 4: "wpa2Personal",
            5: "personal", 6: "dynamicWEP", 7: "wpaEnterprise", 8: "wpaEnterpriseMixed",
            9: "wpa2Enterprise", 10: "enterprise", 11: "wpa3Personal", 12: "wpa3Enterprise",
            13: "wpa3Transition", 14: "owe", 15: "oweTransition",
        ]
        return "\(names[raw] ?? "unknown")(\(raw))"
    }

    static func phyName(_ raw: Int) -> String {
        let names = [0: "none", 1: "11a", 2: "11b", 3: "11g", 4: "11n", 5: "11ac", 6: "11ax", 7: "11be"]
        return "\(names[raw] ?? "unknown")(\(raw))"
    }

    static func mask(_ s: String?, raw: Bool, isBSSID: Bool) -> Field {
        guard let s, !s.isEmpty else { return Field(present: false, value: nil) }
        if raw { return Field(present: true, value: s) }
        if isBSSID {
            let parts = s.split(separator: ":")
            let head = parts.prefix(2).joined(separator: ":")
            return Field(present: true, value: head + ":**:**:**:**")
        }
        return Field(present: true, value: String(s.prefix(2)) + "***(len \(s.count))")
    }

    /// Reads CoreWLAN state as seen by *this* process.
    public static func snapshot(variant: String, raw: Bool, manager: CLLocationManager? = nil) -> ProbeResult {
        let lm = manager ?? CLLocationManager()
        let iface = CWWiFiClient.shared().interface()
        let channel = iface?.wlanChannel().map { "ch \($0.channelNumber) band \($0.channelBand.rawValue) width \($0.channelWidth.rawValue)" }
        return ProbeResult(
            variant: variant,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            pid: getpid(),
            parentPid: getppid(),
            executable: CommandLine.arguments.first ?? "?",
            bundleId: Bundle.main.bundleIdentifier,
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            locationServicesEnabled: CLLocationManager.locationServicesEnabled(),
            authorization: authorizationName(lm.authorizationStatus),
            interfaceFound: iface != nil,
            interfaceName: iface?.interfaceName,
            ssid: mask(iface?.ssid(), raw: raw, isBSSID: false),
            bssid: mask(iface?.bssid(), raw: raw, isBSSID: true),
            channel: channel,
            rssi: iface.map { $0.rssiValue() },
            noise: iface.map { $0.noiseMeasurement() },
            security: iface.map { securityName($0.security().rawValue) },
            phyMode: iface.map { phyName($0.activePHYMode().rawValue) },
            transmitRate: iface.map { $0.transmitRate() },
            countryCode: iface?.countryCode()
        )
    }

    public static func write(_ r: ProbeResult, to dir: String?) {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? enc.encode(r) else { return }
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
        if let dir {
            let url = URL(fileURLWithPath: dir).appendingPathComponent("s1-\(r.variant).json")
            try? data.write(to: url)
        }
    }
}

/// Minimal flag parsing: --variant NAME --out-dir DIR --raw
public struct Args {
    public var variant = "cli"
    public var outDir: String?
    public var raw = false

    public static func parse(_ argv: [String] = CommandLine.arguments) -> Args {
        var a = Args()
        var i = 1
        while i < argv.count {
            switch argv[i] {
            case "--variant" where i + 1 < argv.count: a.variant = argv[i + 1]; i += 1
            case "--out-dir" where i + 1 < argv.count: a.outDir = argv[i + 1]; i += 1
            case "--raw": a.raw = true
            default: break
            }
            i += 1
        }
        return a
    }
}
