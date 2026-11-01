import { describe, expect, it } from "vitest";
import { CAPABILITIES, capabilityLevel, capsText, NSE_ALLOWLIST, toggleCapability } from "./capabilities";
import { emptyScopeForm } from "./scopeForm";

describe("capabilities (mirror of calm_domain::Capability, ADR-011)", () => {
  it("lists the seven capabilities in the Rust order with their levels", () => {
    expect(CAPABILITIES).toEqual(["tcp_connect", "host_discovery", "reverse_dns", "syn_scan", "service_detection", "os_detection", "nse"]);
    expect(CAPABILITIES.map(capabilityLevel)).toEqual(["L1", "L1", "L1", "L2", "L2", "L2", "L2"]);
  });

  it("mirrors the NSE allowlist of calm_orchestrator", () => {
    expect(NSE_ALLOWLIST).toEqual(["http-headers", "http-title", "ssh-hostkey", "ssl-cert"]);
  });

  it("names the ticked capabilities for the approval sentence, in a stable order", () => {
    const t = (k: string) => `<${k}>`;
    expect(capsText(["syn_scan", "tcp_connect"], t)).toBe("<capability.tcp_connect>, <capability.syn_scan>");
    expect(capsText([], t)).toBe("<scope.noneChosen>");
  });

  it("inside a sentence, names are lower case unless they start with an acronym", () => {
    const names: Record<string, string> = {
      "capability.tcp_connect": "TCP connect",
      "capability.host_discovery": "Dò máy",
      "capability.os_detection": "Nhận diện hệ điều hành",
      "capability.nse": "Script NSE",
      "capability.syn_scan": "SYN scan",
    };
    const t = (k: string) => names[k] ?? k;
    expect(capsText(["tcp_connect", "host_discovery", "syn_scan", "os_detection", "nse"], t)).toBe("TCP connect, dò máy, SYN scan, nhận diện hệ điều hành, script NSE");
  });

  it("toggles a capability; turning NSE off drops the scripts chosen for it", () => {
    let f = emptyScopeForm();
    expect(f.capabilities).toEqual(["tcp_connect"]);
    f = toggleCapability(f, "nse");
    f = { ...f, nse_scripts: ["http-title"] };
    expect(f.capabilities).toEqual(["tcp_connect", "nse"]);
    f = toggleCapability(f, "nse");
    expect(f.capabilities).toEqual(["tcp_connect"]);
    expect(f.nse_scripts).toEqual([]);
    f = toggleCapability(f, "tcp_connect");
    expect(f.capabilities).toEqual([]);
  });
});
