import type { JsonValue } from "../domain/jsonValue.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import type { NativeCommandInvocation } from "../domain/native/nativeInspection.js";

/** Provider observation before shared execution/Evidence projection. */
export interface NativeObservation {
  readonly result: JsonValue;
  readonly provenance: readonly NativeCommandInvocation[];
  readonly limitations: readonly string[];
  readonly locations: readonly EvidenceLocation[];
}
