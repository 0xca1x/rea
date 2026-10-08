import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import type { BinaryTarget } from "../domain/binaryTarget.js";

/** Binding of commands to the selected executable's registered content/version. */
export interface SignatureTargetBinding {
  readonly identity: string | null;
  readonly reason: string | null;
}

const identity = (stat: BigIntStats): string =>
  [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");

/** Establish a bounded-memory digest/version baseline before external commands run. */
export const bindSignatureTarget = async (
  target: BinaryTarget,
  signal?: AbortSignal,
): Promise<SignatureTargetBinding> => {
  signal?.throwIfAborted();
  try {
    const before = await lstat(target.path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink())
      return {
        identity: null,
        reason: `Signature target is no longer a regular file: ${target.path}`,
      };
    const file = await open(
      target.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const opened = await file.stat({ bigint: true });
      if (identity(opened) !== identity(before))
        return {
          identity: null,
          reason: `Signature target changed before open: ${target.path}`,
        };
      const size = Number(opened.size);
      if (!Number.isSafeInteger(size))
        return {
          identity: null,
          reason: `Signature target size is not exactly representable: ${target.path}`,
        };
      const hash = createHash("sha256");
      const chunk = Buffer.alloc(64 * 1024);
      let position = 0;
      while (position < size) {
        signal?.throwIfAborted();
        const { bytesRead } = await file.read(
          chunk,
          0,
          Math.min(chunk.length, size - position),
          position,
        );
        if (bytesRead === 0)
          return {
            identity: null,
            reason: `Signature target was truncated while hashing: ${target.path}`,
          };
        hash.update(chunk.subarray(0, bytesRead));
        position += bytesRead;
      }
      const observed = hash.digest("hex");
      if (observed !== target.sha256)
        return {
          identity: null,
          reason: `Signature target digest changed: ${target.path}; expected ${target.sha256}, observed ${observed}`,
        };
      const after = await file.stat({ bigint: true });
      const current = await lstat(target.path, { bigint: true });
      if (
        identity(after) !== identity(opened) ||
        identity(current) !== identity(opened)
      )
        return {
          identity: null,
          reason: `Signature target changed while establishing its version: ${target.path}`,
        };
      return { identity: identity(opened), reason: null };
    } finally {
      await file.close();
    }
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    if (cause instanceof Error && "code" in cause)
      return {
        identity: null,
        reason: `Signature target version is unavailable: ${target.path}; ${cause.message}`,
      };
    throw cause;
  }
};

/** Reject drift between display, entitlement and verification captures. */
export const signatureTargetIssue = async (
  target: BinaryTarget,
  binding: SignatureTargetBinding,
  signal?: AbortSignal,
): Promise<string | null> => {
  signal?.throwIfAborted();
  if (binding.identity === null) return binding.reason;
  try {
    const current = await lstat(target.path, { bigint: true });
    return current.isFile() && identity(current) === binding.identity
      ? null
      : `Signature target changed during inspection: ${target.path}`;
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    if (cause instanceof Error && "code" in cause)
      return `Signature target version could not be rechecked: ${target.path}; ${cause.message}`;
    throw cause;
  }
};
