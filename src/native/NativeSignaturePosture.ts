import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { InspectSignature } from "../domain/native/nativeInspection.js";
import { ticketStructureIssue } from "./NotarizationTicket.js";

/** Notarization tickets are a few kilobytes; larger files are hashed in chunks. */
const HASH_CHUNK_BYTES = 64 * 1024;

/** The code `codesign --verify` should check: the bundle when one was opened. */
export const signedCodePath = (target: {
  readonly path: string;
  readonly sourcePath?: string;
  readonly bundleInfoPlist?: string;
}): string => appBundle(target) ?? target.path;

/**
 * The app bundle directory a target was opened from. Only a bundle opened as a
 * directory carries its Info.plist; a regular file named `X.app` is not one.
 * The bundle is derived from the Info.plist location, not from the outer
 * opening path, so an iOS-on-Mac wrapper resolves to the inner `Wrapper/*.app`
 * bundle whose executable and ticket were actually inspected.
 */
const appBundle = (target: {
  readonly sourcePath?: string;
  readonly bundleInfoPlist?: string;
}): string | undefined => {
  if (target.bundleInfoPlist === undefined) return undefined;
  const derived = bundleDirFromPlist(target.bundleInfoPlist);
  if (derived !== undefined) return derived;
  return target.sourcePath;
};

/**
 * Bundle directory containing an Info.plist: `.../Foo.app/Contents/Info.plist`
 * lives two levels below its bundle, while a flat `.../Foo.app/Info.plist`
 * lives one level below it.
 */
const bundleDirFromPlist = (plist: string): string | undefined => {
  const contentsSuffix = "/Contents/Info.plist";
  if (plist.endsWith(contentsSuffix))
    return plist.slice(0, -"/Contents/Info.plist".length) || undefined;
  const flatSuffix = "/Info.plist";
  if (plist.endsWith(flatSuffix))
    return plist.slice(0, -"/Info.plist".length) || undefined;
  return undefined;
};

/**
 * Report a ticket stapled to an app bundle, which `stapler` stores at
 * `Contents/CodeResources`. Presence is observed; the ticket's validity and
 * Apple's notarization record are not checked, because that needs the network.
 */
export const stapledTicket = async (
  target: { readonly sourcePath?: string; readonly bundleInfoPlist?: string },
  signal?: AbortSignal,
): Promise<InspectSignature["stapled_ticket"]> => {
  signal?.throwIfAborted();
  const bundle = appBundle(target);
  if (bundle === undefined) {
    signal?.throwIfAborted();
    return {
      status: "not-applicable",
      path: null,
      sha256: null,
      size: null,
      reason: null,
    };
  }
  const relative = "Contents/CodeResources";
  const path = join(bundle, relative);
  try {
    signal?.throwIfAborted();
    const metadata = await lstat(path);
    if (!metadata.isFile()) {
      signal?.throwIfAborted();
      return absent;
    }
    // Open nonblocking so a concurrent replacement with a FIFO cannot hang
    // inspect_signature; the opened handle is revalidated below.
    const handle = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const opened = await handle.stat();
      if (!opened.isFile()) return absent;
      // If the path was replaced between lstat and open, or mutated while
      // hashing, the digest would describe the wrong bytes: dev and ino catch
      // replacement, while size and mtime catch same-inode writes. Report any
      // drift as changed instead of a stale digest.
      if (!sameTicketFile(opened, metadata))
        return {
          status: "unreadable",
          path: relative,
          sha256: null,
          size: null,
          reason: "changed",
        };
      const structureIssue = await ticketStructureIssue(
        async (offset, length) => {
          signal?.throwIfAborted();
          const buffer = new Uint8Array(length);
          let done = 0;
          while (done < length) {
            const { bytesRead } = await handle.read(
              buffer,
              done,
              length - done,
              offset + done,
            );
            if (bytesRead === 0) break;
            done += bytesRead;
          }
          return buffer.subarray(0, done);
        },
        opened.size,
      );
      const hash = createHash("sha256");
      const buffer = new Uint8Array(HASH_CHUNK_BYTES);
      let size = 0;
      while (size < opened.size) {
        signal?.throwIfAborted();
        const { bytesRead } = await handle.read(
          buffer,
          0,
          Math.min(buffer.length, opened.size - size),
          size,
        );
        if (bytesRead === 0) break;
        size += bytesRead;
        hash.update(buffer.subarray(0, bytesRead));
      }
      signal?.throwIfAborted();
      const closing = await handle.stat();
      if (!sameTicketFile(closing, opened) || size !== opened.size)
        return {
          status: "unreadable",
          path: relative,
          sha256: null,
          size: null,
          reason: "changed",
        };
      // An atomic replacement swaps the pathname to a new inode while the
      // handle still describes the unlinked original: re-resolve the path and
      // refuse a digest that no longer belongs to the bundle.
      try {
        const current = await lstat(path);
        if (!sameTicketFile(current, opened))
          return {
            status: "unreadable",
            path: relative,
            sha256: null,
            size: null,
            reason: "changed",
          };
      } catch {
        return {
          status: "unreadable",
          path: relative,
          sha256: null,
          size: null,
          reason: "changed",
        };
      }
      return {
        status: structureIssue === null ? "present" : "unreadable",
        path: relative,
        sha256: hash.digest("hex"),
        size,
        reason: structureIssue,
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

/**
 * Whether two observations describe the same file version. Device and inode
 * catch replacement; size and mtime catch same-inode writes and truncations
 * whose digest would otherwise mix multiple file states.
 */
const sameTicketFile = (
  left: {
    readonly dev: number;
    readonly ino: number;
    readonly size: number;
    readonly mtimeMs: number;
    readonly ctimeMs: number;
  },
  right: {
    readonly dev: number;
    readonly ino: number;
    readonly size: number;
    readonly mtimeMs: number;
    readonly ctimeMs: number;
  },
): boolean =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeMs === right.mtimeMs &&
  left.ctimeMs === right.ctimeMs;

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
  "Ticket presence requires recognized local s8ch/g8tk container and DER framing; certificate authenticity, ticket signature validity, and ticket-to-code binding are not verified.",
];

/**
 * codesign prints one nested path per line, so a path that contains a newline
 * is split into fragments. A reported path that does not exist on disk is
 * named in a limitation instead of being trusted as complete. An existing
 * reported path is still ambiguous when it could be the first line of a
 * longer newline-containing path: either a diagnostic fragment completes it,
 * or its parent directory holds an entry with an embedded newline.
 */
export const unconfirmedNestedCode = async (
  verification: NonNullable<InspectSignature["verification"]>,
): Promise<string[]> => {
  const missing: string[] = [];
  const ambiguous: string[] = [];
  const denied: string[] = [];
  for (const validatedPath of verification.validated_nested_code) {
    try {
      await lstat(validatedPath);
    } catch (cause: unknown) {
      const code = errorCode(cause);
      // A denied lookup cannot confirm the path, but is no sign of a split one.
      if (code === "EACCES" || code === "EPERM") {
        denied.push(
          `Could not confirm completeness of codesign nested path ${JSON.stringify(validatedPath)}: permission denied (${code}); the reported path may be a fragment.`,
        );
        continue;
      }
      if (code !== "ENOENT" && code !== "ENOTDIR") throw cause;
      missing.push(validatedPath);
      continue;
    }
    if (await isNewlineFragment(validatedPath, verification.diagnostics)) {
      ambiguous.push(validatedPath);
    }
  }
  return [
    ...denied,
    ...missing.map(
      (path) =>
        `codesign reported validated nested code at ${JSON.stringify(path)}, which does not exist; a nested path probably contains a newline, so validated_nested_code and diagnostics hold fragments of it.`,
    ),
    ...ambiguous.map(
      (path) =>
        `codesign reported validated nested code at ${JSON.stringify(path)}, which exists but could be the first line of a nested path containing a newline; validated_nested_code is ambiguous and should not be trusted as complete.`,
    ),
  ];
};

/**
 * Whether an existing validated path could be a newline-split fragment: a
 * diagnostic line completes it to an existing path, or its parent directory
 * contains an entry with an embedded newline whose first line matches it.
 */
const isNewlineFragment = async (
  validated: string,
  diagnostics: readonly string[],
): Promise<boolean> => {
  for (const fragment of diagnostics) {
    if (fragment.length === 0 || fragment.includes("\n")) continue;
    // A continuation line is a bare fragment, not a `key: value` diagnostic.
    if (fragment.includes(":") || fragment.includes(" ")) continue;
    try {
      await lstat(`${validated}\n${fragment}`);
      return true;
    } catch {
      // Not completed by this diagnostic line; check directory entries below.
    }
  }
  try {
    const entries = await readdir(dirname(validated));
    const base = validated.slice(dirname(validated).length + 1);
    for (const entry of entries) {
      if (!entry.includes("\n")) continue;
      if (entry.split("\n")[0] === base) return true;
      // A suffix beginning with `--validated:` can inject a second record;
      // any newline entry in the same directory makes each record suspect.
      return true;
    }
  } catch {
    return false;
  }
  return false;
};
