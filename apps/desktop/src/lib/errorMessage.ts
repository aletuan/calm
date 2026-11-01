/**
 * Error kinds → the sentence to show, plus an optional raw detail for a
 * separate "Detail" line. The sentence follows the voice guide (what Calm
 * could not do · whether data is safe · what to do); raw codes and sizes
 * never lead the message (docs/design/02-voice-and-terminology.md).
 */
import type { MessageKey } from "../i18n/en";
import { fmtBytes } from "./format";
import type { ImportError, StoreError } from "./ipc";

export interface ErrorMessage {
  key: MessageKey;
  detail?: string;
}

export function storeErrorMessage(e: StoreError): ErrorMessage {
  switch (e.kind) {
    case "key_mismatch":
      return { key: "store.err.keyMismatch" };
    case "not_found":
      return { key: "store.err.notFound" };
    case "unsupported_schema":
      return { key: "store.err.schema", detail: `schema ${e.detail}` };
    case "key_unavailable":
      return { key: "store.err.keyUnavailable", detail: e.detail };
    default:
      return { key: "store.err.other", detail: e.detail };
  }
}

/** `null` for a cancelled picker: nothing to report. */
export function importErrorMessage(e: ImportError): ErrorMessage | null {
  switch (e.kind) {
    case "cancelled":
      return null;
    case "not_a_capture":
      return { key: "import.err.notCapture" };
    case "too_large":
      return { key: "import.err.tooLarge", detail: `${fmtBytes(e.size_bytes)} > ${fmtBytes(e.limit_bytes)}` };
    case "unreadable":
      return { key: "import.err.unreadable", detail: e.detail };
  }
}

export const saveErrorDetail = (e: StoreError): string => ("detail" in e ? String(e.detail) : e.kind);
