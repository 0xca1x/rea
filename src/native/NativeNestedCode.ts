import { lstat, readdir } from "node:fs/promises";
import { dirname, basename } from "node:path";

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

/** Completeness of newline-delimited progress records, distinct from verification. */
export interface NestedCodePathInspection {
  readonly limitations: readonly string[];
  readonly progressAmbiguous: boolean;
}

/** Preserve reported paths and operational errors, and identify ambiguous progress. */
export const inspectNestedCodePaths = async (
  verification: {
    readonly validated_nested_code: readonly string[];
    readonly prepared_nested_code?: readonly string[];
  },
  signal?: AbortSignal,
  view: NativeNestedPathView = FILE_SYSTEM,
): Promise<NestedCodePathInspection> => {
  signal?.throwIfAborted();
  const limitations: string[] = [];
  const directories = new Map<string, Promise<ReadonlySet<string>>>();
  let progressAmbiguous = false;
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
        progressAmbiguous = true;
        limitations.push(
          `Could not confirm completeness of codesign nested path ${JSON.stringify(path)}: permission denied (${code}); the reported path may be a fragment.`,
        );
        continue;
      }
      if (code === "ENOENT" || code === "ENOTDIR")
        limitations.push(
          `codesign reported ${record} nested code at ${JSON.stringify(path)}, which does not exist; structured nested-code records may hold fragments of a path containing a newline.`,
        );
      else {
        progressAmbiguous = true;
        limitations.push(
          `Could not confirm completeness of codesign nested path ${JSON.stringify(path)}: ${cause instanceof Error ? cause.message : String(cause)} (${String(code ?? "unknown")}); the reported path may be a fragment.`,
        );
      }
    }
    signal?.throwIfAborted();
    const parent = dirname(path);
    let names = directories.get(parent);
    if (names === undefined) {
      names = view
        .names(parent)
        .then(
          (entries) =>
            new Set(
              entries
                .filter((name) => name.includes("\n"))
                .map((name) => name.slice(0, name.indexOf("\n"))),
            ),
        );
      directories.set(parent, names);
    }
    try {
      const prefixes = await names;
      const ambiguous = prefixes.has(basename(path));
      signal?.throwIfAborted();
      if (ambiguous) {
        progressAmbiguous = true;
        limitations.push(
          `codesign reported ${record} nested code at ${JSON.stringify(path)}, which could be the first line of a nested path containing a newline; structured nested-code records are ambiguous and should not be trusted as complete.`,
        );
      }
    } catch (cause: unknown) {
      signal?.throwIfAborted();
      progressAmbiguous = true;
      limitations.push(
        `Could not confirm completeness of codesign nested path ${JSON.stringify(path)} from parent directory ${JSON.stringify(parent)}: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
  }
  signal?.throwIfAborted();
  return { limitations, progressAmbiguous };
};
