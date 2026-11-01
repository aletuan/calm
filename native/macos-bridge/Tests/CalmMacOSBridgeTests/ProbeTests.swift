import XCTest
@testable import CalmMacOSBridge

final class ProbeTests: XCTestCase {
    func testSkeletonNeverInventsValues() {
        let s = Probe.snapshot()
        XCTAssertNil(s.ssid.value)
        XCTAssertNil(s.bssid.value)
        XCTAssertTrue(s.ssid.source.hasPrefix("unavailable:"))
    }
}
