import type { Readable } from "node:stream";
import type { ArtifactCommand } from "../domain/artifactGraph.js";
import type { ZipPackageFormat } from "../domain/zipPackageFormat.js";
import type { ArtifactDecodedBudget } from "./ArtifactDecodedBudget.js";

/** Archive-neutral entry metadata. Reader adapters never choose output paths. */
export interface ArtifactEntry {
  readonly path: string;
  readonly kind: "file" | "directory" | "symlink" | "slice";
  readonly declaredSize: number | null;
  readonly compressedSize: number | null;
  readonly executable: boolean;
  readonly encrypted: boolean;
  readonly byteOffset: number | null;
  readonly declaredSha256: string | null;
  readonly unpacked: boolean;
  readonly limitations: readonly string[];
  readonly adapterKey: string;
  /**
   * Container checksum of the member's bytes in an algorithm other than
   * SHA-256 (xar declares SHA-1 or MD5). The scan verifies it under the
   * caller's integrity policy.
   */
  readonly declaredChecksum?: {
    readonly algorithm: "sha1" | "md5" | "sha512";
    readonly value: string;
  };
  /** The container records this member but does not hold its bytes, such as an unresolved hard link. */
  readonly contentUnavailable?: boolean;
  /** Archive format of this member's own bytes, when the scan should expand it. */
  readonly nestedArchive?: "gzip-cpio";
  /** Filesystem identity captured during traversal, when supplied by an adapter. */
  readonly sourceIdentity?: {
    readonly device: number;
    readonly inode: number;
  };
}

/** Checksum evidence for a member representation the scanner cannot hash itself. */
export interface ArtifactChecksumObservation {
  readonly representation: "stored" | "decoded";
  readonly algorithm: string;
  readonly declared: string;
  readonly observed: string;
}

/** Read-only adapter over one directory, archive, or virtual container. */
export interface ArtifactReader {
  readonly format: "directory" | ZipPackageFormat | "asar" | "pkg" | "file";
  /** Shared safety budget for compressed representations and nested archives. */
  readonly decodedBudget?: ArtifactDecodedBudget;
  entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry>;
  open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable>;
  /** Checksums observed after the complete member stream has been consumed. */
  integrityObservations?(
    entry: ArtifactEntry,
  ): readonly ArtifactChecksumObservation[];
  provenance(): readonly ArtifactCommand[];
  close(): Promise<void>;
}

/** Typed adapter failure translated at provider boundary. */
export class ArtifactReaderFailure extends Error {
  constructor(
    readonly reason:
      | "cancelled"
      | "format"
      | "integrity"
      | "io"
      | "limit"
      | "path"
      | "unavailable",
    message: string,
    options?: ErrorOptions,
    readonly details?: Readonly<{
      logicalPath: string;
      declaredSha256: string | null;
      calculatedSha256: string | null;
      unpacked: boolean;
    }>,
  ) {
    super(message, options);
    this.name = "ArtifactReaderFailure";
  }
}
