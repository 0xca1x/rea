import { posix, win32 } from "node:path";
import { ArtifactReaderFailure } from "../ArtifactReader.js";

/**
 * Convert host filesystem separators into the tree view's POSIX traversal
 * namespace. Dot segments stay intact so they apply after symlink expansion;
 * POSIX backslash filename bytes are never reinterpreted as separators.
 */
export const filesystemDyldLinkTarget = (
  reported: string,
  platform: NodeJS.Platform = process.platform,
): string => {
  if (platform !== "win32") return reported;
  const portable = reported.replaceAll("\\", "/");
  if (win32.isAbsolute(reported))
    return portable.startsWith("/") ? portable : `/${portable}`;
  if (/^[A-Za-z]:/u.test(reported))
    throw new ArtifactReaderFailure(
      "unavailable",
      `Drive-relative symlink target depends on a Windows drive working directory: ${reported}`,
    );
  return portable;
};

/** Map a portable lookup to the host without allowing extra native separators to escape it. */
export const filesystemDyldLookupPath = (
  root: string,
  lookup: string,
  platform: NodeJS.Platform = process.platform,
): string => {
  if (platform === "win32" && lookup.includes("\\"))
    throw new ArtifactReaderFailure(
      "unavailable",
      `Literal backslashes in a POSIX dyld lookup cannot be represented on Windows: ${lookup}. Analyze this tree on a POSIX host.`,
    );
  return platform === "win32"
    ? win32.join(root, lookup)
    : posix.join(root, lookup);
};
