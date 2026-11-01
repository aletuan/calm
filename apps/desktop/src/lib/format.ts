import type { Transport } from "./ipc";

/** Binary units, one decimal (two above 1 GB). */
export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export const fmtNum = (n: number) => n.toLocaleString();

/** mm:ss (minutes keep growing past 59). */
export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  return `${String(m).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

/** `[v6]:port` per RFC 3986; plain `v4:port` otherwise; no port → bare address. */
export function endpoint(ip: string, port: number | null): string {
  const host = ip.includes(":") ? `[${ip}]` : ip;
  return port != null ? `${host}:${port}` : ip;
}

/** Multicast or broadcast destination (display tag only; the engine decides semantics). */
export function isGroup(ip: string): boolean {
  if (ip.includes(":")) return ip.toLowerCase().startsWith("ff");
  const first = Number(ip.split(".")[0]);
  return (first >= 224 && first <= 239) || ip === "255.255.255.255" || ip.endsWith(".255");
}

export function transportName(t: Transport): string {
  return typeof t === "string" ? t.toUpperCase() : `IP/${t.other}`;
}

export function shortHash(h: string): string {
  return h.length <= 20 ? h : `${h.slice(0, 12)}…${h.slice(-6)}`;
}

/** UTC timestamp `YYYY-MM-DD HH:MM:SS UTC`. */
export function fmtUtc(ms: number): string {
  return `${new Date(ms).toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** Local wall-clock time of this Mac, `HH:MM:SS`. */
export function fmtLocalTime(ms: number): string {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** Local date and time with the UTC offset, e.g. `2026-10-31 16:00:00 (UTC+7)`. */
export function fmtLocal(ms: number): string {
  const d = new Date(ms);
  const off = -d.getTimezoneOffset();
  const h = Math.floor(Math.abs(off) / 60);
  const m = Math.abs(off) % 60;
  const zone = `UTC${off < 0 ? "−" : "+"}${h}${m ? `:${pad(m)}` : ""}`;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtLocalTime(ms)} (${zone})`;
}
