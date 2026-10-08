import { AnalysisError } from "./analysisErrorBase.js";

/** Declared and observed checksums of one consumed member representation. */
export interface ArtifactChecksumObservation {
  readonly representation: "stored" | "decoded";
  readonly algorithm: string;
  readonly declared: string;
  readonly observed: string;
}

/** Evidence identifying an artifact member's failed integrity constraints. */
export interface ArtifactIntegrityFailureDetails {
  readonly logicalPath: string;
  readonly declaredSha256: string | null;
  readonly calculatedSha256: string | null;
  readonly unpacked: boolean;
  readonly checksumMismatches?: readonly ArtifactChecksumObservation[];
}

/** Artifact inventory or extraction failed a typed safety boundary. */
export class ArtifactOperationError extends AnalysisError {
  readonly _tag = "ArtifactOperationError";

  constructor(
    readonly operation:
      | "inventory_artifact"
      | "inspect_artifact"
      | "extract_artifact"
      | "decode_interface_builder"
      | "inspect_asset_catalog"
      | "inspect_keyed_archive"
      | "trace_dylib_resolution"
      | "export_web_scripts"
      | "trace_web_module_imports"
      | "trace_web_source_location"
      | "analyze_javascript_application",
    readonly reason:
      | "cancelled"
      | "format"
      | "integrity"
      | "limit"
      | "path"
      | "unavailable"
      | "io",
    readonly artifactDetails?: ArtifactIntegrityFailureDetails,
    /** The specific constraint that failed, such as the colliding path. */
    readonly detail?: string,
  ) {
    super(
      artifactDetails === undefined
        ? `Artifact ${operation} failed: ${reason}`
        : `Artifact ${operation} failed: ${reason} at ${artifactDetails.logicalPath} (declared_sha256=${artifactDetails.declaredSha256 ?? "unavailable"}, calculated_sha256=${artifactDetails.calculatedSha256 ?? "unavailable"}, unpacked=${String(artifactDetails.unpacked)})`,
    );
  }
}
