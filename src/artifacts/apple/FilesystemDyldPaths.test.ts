import { expect, it } from "vitest";
import { resolveTreePath } from "../../domain/apple/dyldPaths.js";
import type { DylibTreeEntry } from "../../domain/apple/dylibResolution.js";
import {
  filesystemDyldLinkTarget,
  filesystemDyldLookupPath,
} from "./FilesystemDyldPaths.js";

it("normalizes Windows relative links before containment checks without probing an escaped path", async () => {
  const requested: string[] = [];
  const result = await resolveTreePath(
    {
      entry: async (path: string): Promise<DylibTreeEntry | undefined> => {
        requested.push(path);
        return path === "link"
          ? {
              kind: "symlink",
              target: filesystemDyldLinkTarget("..\\outside.dylib", "win32"),
            }
          : undefined;
      },
      image: async () => ({ status: "not-mach-o" }),
    },
    "link",
  );
  expect(result).toEqual({ kind: "escapes" });
  expect(requested).toEqual(["link"]);
});

it("keeps POSIX backslash bytes and preserves Windows dot segments for segment-wise traversal", () => {
  expect(filesystemDyldLinkTarget("..\\outside.dylib", "darwin")).toBe(
    "..\\outside.dylib",
  );
  expect(filesystemDyldLinkTarget("nested\\..\\target", "win32")).toBe(
    "nested/../target",
  );
  expect(filesystemDyldLinkTarget("C:\\outside", "win32")).toBe("/C:/outside");
  expect(filesystemDyldLinkTarget("C:/literal-posix-directory", "darwin")).toBe(
    "C:/literal-posix-directory",
  );
  expect(() => filesystemDyldLinkTarget("C:drive-relative", "win32")).toThrow(
    "Windows drive working directory",
  );
});

it("does not let Windows reinterpret a literal backslash-bearing loader name as traversal", () => {
  expect(() =>
    filesystemDyldLookupPath("C:\\root", "..\\outside.dylib", "win32"),
  ).toThrow("cannot be represented on Windows");
  expect(
    filesystemDyldLookupPath("/root", "literal\\name.dylib", "darwin"),
  ).toBe("/root/literal\\name.dylib");
});
