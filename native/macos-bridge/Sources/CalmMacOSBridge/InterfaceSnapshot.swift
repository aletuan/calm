import Foundation

/// Mirrors the canonical `InterfaceSnapshot` (docs/architecture/02).
/// Every value carries its source; unknown stays `nil`, never guessed.
public struct InterfaceSnapshot: Codable, Equatable {
    public struct Sourced<T: Codable & Equatable>: Codable, Equatable {
        public let value: T?
        /// e.g. "corewlan", "scutil", "route", "unavailable:location_permission"
        public let source: String
        public init(value: T?, source: String) {
            self.value = value
            self.source = source
        }
    }

    public let schemaVersion: String
    public let interface: Sourced<String>
    public let ssid: Sourced<String>
    public let bssid: Sourced<String>
    public let observedAt: Date

    public init(interface: Sourced<String>, ssid: Sourced<String>, bssid: Sourced<String>, observedAt: Date) {
        self.schemaVersion = "calm-v1alpha1"
        self.interface = interface
        self.ssid = ssid
        self.bssid = bssid
        self.observedAt = observedAt
    }
}

public enum Probe {
    /// Skeleton: reports everything as not implemented. WP1 replaces this with
    /// CoreWLAN (`CWWiFiClient.shared().interface()`) — SSID/BSSID require
    /// Location authorization on macOS 14+, otherwise they come back nil.
    public static func snapshot(now: Date = Date()) -> InterfaceSnapshot {
        let na = "unavailable:not_implemented"
        return InterfaceSnapshot(
            interface: .init(value: nil, source: na),
            ssid: .init(value: nil, source: na),
            bssid: .init(value: nil, source: na),
            observedAt: now
        )
    }
}
