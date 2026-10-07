import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";

import type { InspectSignature } from "../domain/nativeInspection.js";
import type { NativeCommandCapture } from "./CommandRunner.js";

/** Notarization tickets are a few kilobytes; larger files are hashed in chunks. */
const HASH_CHUNK_BYTES = 64 * 1024;

/** The code `codesign --verify` should check: the bundle when one was opened. */
export const signedCodePath = (target: {
  readonly path: string;
  readonly sourcePath?: string;
}): string =>
  target.sourcePath?.toLowerCase().endsWith(".app") === true
    ? target.sourcePath
    : target.path;

/**
 * Project a local `codesign --verify --strict` capture without reinterpreting
 * its messages. codesign validates nested code concurrently, so its
 * `--prepared:`/`--validated:` progress lines arrive in no fixed order; they
 * are reported as a sorted list of validated nested code instead.
 */
export const signatureVerification = (
  capture: NativeCommandCapture,
  path: string,
  unsigned: boolean,
): NonNullable<InspectSignature["verification"]> => {
  const lines = `${capture.stderr}\n${capture.stdout}`
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return {
    path,
    status:
      capture.exitCode === 0 ? "valid" : unsigned ? "unsigned" : "invalid",
    exit_code: capture.exitCode,
    diagnostics: lines.filter(
      (line) => !/^--(?:prepared|validated):/u.test(line),
    ),
    validated_nested_code: [
      ...new Set(
        lines.flatMap((line) =>
          line.startsWith("--validated:")
            ? [line.slice("--validated:".length)]
            : [],
        ),
      ),
    ].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
  };
};

/**
 * Report a ticket stapled to an app bundle, which `stapler` stores at
 * `Contents/CodeResources`. Presence is observed; the ticket's validity and
 * Apple's notarization record are not checked, because that needs the network.
 */
export const stapledTicket = async (
  target: { readonly sourcePath?: string },
  signal?: AbortSignal,
): Promise<InspectSignature["stapled_ticket"]> => {
  const bundle = target.sourcePath;
  if (bundle?.toLowerCase().endsWith(".app") !== true)
    return {
      status: "not-applicable",
      path: null,
      sha256: null,
      size: null,
      reason: null,
    };
  const relative = "Contents/CodeResources";
  const path = join(bundle, relative);
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile()) return absent;
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const hash = createHash("sha256");
      const buffer = new Uint8Array(HASH_CHUNK_BYTES);
      let size = 0;
      for (;;) {
        signal?.throwIfAborted();
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (bytesRead === 0) break;
        size += bytesRead;
        hash.update(buffer.subarray(0, bytesRead));
      }
      return {
        status: "present",
        path: relative,
        sha256: hash.digest("hex"),
        size,
        reason: null,
      };
    } finally {
      await handle.close();
    }
  } catch (cause: unknown) {
    const code = errorCode(cause);
    if (code === "ENOENT" || code === "ENOTDIR") return absent;
    // A privacy or ACL denial leaves the ticket's presence unknown, not the
    // whole signature inspection.
    if (code === "EACCES" || code === "EPERM")
      return {
        status: "unreadable",
        path: relative,
        sha256: null,
        size: null,
        reason: code,
      };
    throw cause;
  }
};

const absent = {
  status: "absent",
  path: null,
  sha256: null,
  size: null,
  reason: null,
} as const;

const errorCode = (cause: unknown): string | undefined =>
  cause instanceof Error && "code" in cause && typeof cause.code === "string"
    ? cause.code
    : undefined;

/** Limitations that keep verification and notarization claims bounded. */
export const SIGNATURE_POSTURE_LIMITATIONS = [
  "Signature verification is local `codesign --verify --deep --strict`; certificate revocation, Gatekeeper policy, and Apple's notarization records are not checked.",
  "Security facets are derived from CodeDirectory flags and entitlements; runtime policy such as System Integrity Protection, AMFI, and setuid bits can further restrict a process.",
];
