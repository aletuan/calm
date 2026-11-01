import type { MessageKey } from "../i18n/en";
import { isGroup } from "./format";
import type { Flow } from "./ipc";

/** A heard flow reached the interface as broadcast/multicast (or ARP), same rule as the engine. */
function heardAsGroup(f: Flow): boolean {
  if (f.origin === "local_broadcast") return true;
  if (f.origin === "local_interface") return false;
  return f.key.transport === "arp" || isGroup(f.key.local);
}

/** Whose point of view the direction is told from. */
export type Perspective = "mac" | "host";

/**
 * Direction label. "Opened" only when the TCP SYN was seen; UDP/ICMP have no
 * opener, so they show plain Out/In.
 */
export function dirKey(f: Flow, perspective: Perspective): MessageKey {
  if (f.direction === "heard") return heardAsGroup(f) ? "traffic.dir.heard" : "traffic.dir.heardUnicast";
  if (f.initiated_by === "local") return perspective === "host" ? "import.dir.outOpened" : "traffic.dir.outOpened";
  if (f.initiated_by === "remote") return "traffic.dir.inOpened";
  if (f.key.transport !== "tcp") return f.direction === "outbound" ? "traffic.dir.outPlain" : "traffic.dir.inPlain";
  return f.direction === "outbound" ? "traffic.dir.out" : "traffic.dir.in";
}

/**
 * The Local column. For a heard ARP request the "local" side is the address
 * someone is looking for (ARP target), not this Mac, so it is labelled so.
 */
export function localCell(f: Flow): { prefix: MessageKey | null; value: string } {
  if (f.direction === "heard") {
    return { prefix: f.key.transport === "arp" ? "traffic.local.askedAbout" : null, value: f.key.local };
  }
  return { prefix: null, value: f.key.local_port != null ? `:${f.key.local_port}` : "—" };
}
