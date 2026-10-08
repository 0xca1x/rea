import type { InspectSignature } from "../domain/native/nativeInspection.js";
import type { NativeCommandCapture } from "./CommandRunner.js";

/** Strip the diagnostic's echoed pathname for classification, keeping the raw line elsewhere. */
export const codesignReason = (line: string, path: string): string => {
  if (line.startsWith(`${path}: `)) return line.slice(path.length + 2);
  if (line.startsWith("/")) {
    const delimiter = line.lastIndexOf(": ");
    return delimiter >= 0 ? line.slice(delimiter + 2) : "";
  }
  return line;
};

/** Classify only explicit diagnostic reasons; nonzero exit alone proves no invalidity. */
const verificationStatus = (
  capture: NativeCommandCapture,
  reasons: readonly string[],
  unsigned: boolean,
): NonNullable<InspectSignature["verification"]>["status"] => {
  if (capture.exitCode === 0) return "valid";
  if (
    reasons.some((reason) =>
      /^(?:permission denied|operation not permitted|EACCES\b|EPERM\b|I\/O error|input\/output error)/iu.test(
        reason,
      ),
    )
  )
    return "unknown";
  const unsignedReason = reasons.some((reason) =>
    /^(?:code object is not signed at all|code object is not signed|not signed at all)/iu.test(
      reason,
    ),
  );
  if (unsignedReason) return unsigned ? "unsigned" : "invalid";
  if (
    reasons.some((reason) =>
      /^(?:a sealed resource is missing or invalid|code or signature modified|invalid signature|invalid or unsupported format|resource envelope is obsolete|signature is invalid|unsealed contents present|file modified:|file added:|a resource envelope is obsolete)/iu.test(
        reason,
      ),
    )
  )
    return "invalid";
  return "unknown";
};

/** Project codesign verification without changing pathname bytes or discarding diagnostics. */
export const signatureVerification = (
  capture: NativeCommandCapture,
  path: string,
  unsigned: boolean,
): NonNullable<InspectSignature["verification"]> => {
  const lines = `${capture.stderr}\n${capture.stdout}`
    .split("\n")
    .filter((line) => line.length > 0);
  const diagnostics = lines.filter(
    (line) => !/^--(?:prepared|validated):/u.test(line),
  );
  return {
    path,
    status: verificationStatus(
      capture,
      diagnostics.map((line) => codesignReason(line, path)),
      unsigned,
    ),
    exit_code: capture.exitCode,
    diagnostics,
    validated_nested_code: [
      ...new Set(
        lines.flatMap((line) =>
          line.startsWith("--validated:")
            ? [line.slice("--validated:".length)]
            : [],
        ),
      ),
    ].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
  };
};
