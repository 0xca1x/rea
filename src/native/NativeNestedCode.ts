import { lstat, readdir } from "node:fs/promises";
import { dirname } from "node:path";

/** Filesystem seam for path-completeness checks and cancellation regressions. */
export interface NativeNestedPathView {
  lookup(path: string): Promise<void>;
  names(directory: string): Promise<string[]>;
}

const FILE_SYSTEM: NativeNestedPathView = {
  lookup: async (path) => {
    await lstat(path);
  },
  names: (path) => readdir(path),
};

const errorCode = (cause: unknown) =>
  cause instanceof Error && "code" in cause ? cause.code : undefined;

/** Preserve reported paths, but qualify missing, denied or newline-ambiguous records. */
export const unconfirmedNestedCode = async (
  verification: {
    readonly validated_nested_code: readonly string[];
    readonly prepared_nested_code?: readonly string[];
  },
  signal?: AbortSignal,
  view: NativeNestedPathView = FILE_SYSTEM,
): Promise<string[]> => {
  signal?.throwIfAborted();
  const limitations: string[] = [];
  const directories = new Map<string, Promise<boolean>>();
  const records = new Map<string, "prepared" | "validated">();
  for (const path of verification.prepared_nested_code ?? [])
    records.set(path, "prepared");
  for (const path of verification.validated_nested_code)
    records.set(path, "validated");
  for (const [path, record] of records) {
    signal?.throwIfAborted();
    try {
      await view.lookup(path);
    } catch (cause: unknown) {
      signal?.throwIfAborted();
      const code = errorCode(cause);
      if (code === "EACCES" || code === "EPERM") {
        limitations.push(
          `Could not confirm completeness of codesign nested path ${JSON.stringify(path)}: permission denied (${code}); the reported path may be a fragment.`,
        );
        continue;
      }
      if (code !== "ENOENT" && code !== "ENOTDIR") throw cause;
      limitations.push(
        `codesign reported ${record} nested code at ${JSON.stringify(path)}, which does not exist; a nested path probably contains a newline, so structured nested-code records and diagnostics may hold fragments of it.`,
      );
      continue;
    }
    signal?.throwIfAborted();
    const parent = dirname(path);
    let names = directories.get(parent);
    if (names === undefined) {
      names = view
        .names(parent)
        .then((entries) => entries.some((name) => name.includes("\n")));
      directories.set(parent, names);
    }
    try {
      const ambiguous = await names;
      signal?.throwIfAborted();
      if (ambiguous)
        limitations.push(
          `codesign reported ${record} nested code at ${JSON.stringify(path)}, which exists but could be the first line of a nested path containing a newline; structured nested-code records are ambiguous and should not be trusted as complete.`,
        );
    } catch (cause: unknown) {
      signal?.throwIfAborted();
      if (!(cause instanceof Error) || !("code" in cause)) throw cause;
      limitations.push(
        `Could not confirm completeness of codesign nested path ${JSON.stringify(path)} from parent directory ${JSON.stringify(parent)}: ${cause.message}`,
      );
    }
  }
  signal?.throwIfAborted();
  return limitations;
};
