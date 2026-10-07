import { AsarArtifactReader } from "../../artifacts/AsarArtifactReader.js";
import type { ArtifactReader } from "../../artifacts/ArtifactReader.js";
import { DirectoryArtifactReader } from "../../artifacts/DirectoryArtifactReader.js";
import { MachOSliceArtifactReader } from "../../artifacts/MachOSliceArtifactReader.js";
import { NativeDmgArtifactReader } from "../../artifacts/NativeDmgArtifactReader.js";
import { XarArtifactReader } from "../../artifacts/XarArtifactReader.js";
import { ZipArtifactReader } from "../../artifacts/ZipArtifactReader.js";
import type { ArtifactNode } from "../../domain/artifactGraph.js";

export const createReader = async (
  path: string,
  format: ArtifactNode["format"],
  signal?: AbortSignal,
  /** The caller verifies declared member checksums itself (inventory scans do). */
  options: { readonly callerVerifiesChecksums?: boolean } = {},
): Promise<ArtifactReader | undefined> => {
  switch (format) {
    case "directory":
      return new DirectoryArtifactReader(path);
    case "zip":
    case "ipa":
    case "apk":
    case "msix":
    case "appx":
      return new ZipArtifactReader(path, format);
    case "asar":
      return new AsarArtifactReader(path);
    case "pkg":
      return new XarArtifactReader(path, {
        verifyChecksums: options.callerVerifiesChecksums !== true,
      });
    case "mach-o-universal":
      return process.platform === "darwin"
        ? new MachOSliceArtifactReader(path)
        : undefined;
    case "dmg":
      if (process.platform !== "darwin") return undefined;
      return NativeDmgArtifactReader.create(path, signal);
    default:
      return undefined;
  }
};

export const inventoryLimitations = (
  format: ArtifactNode["format"],
  reader: ArtifactReader | undefined,
): string[] => {
  if (reader !== undefined) return [];
  if (format === "dmg")
    return [
      "DMG root hash is observed; child inventory requires a native macOS adapter.",
    ];
  if (format === "mach-o-universal" && process.platform !== "darwin")
    return ["Universal Mach-O slices require the native macOS lipo adapter."];
  return ["Artifact has no child container entries."];
};
