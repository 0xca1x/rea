import { lstat, realpath } from "node:fs/promises";

import { canonicalDigest } from "../../domain/comparisonSemantics.js";
import { AsarArtifactReader } from "../AsarArtifactReader.js";
import {
  ArtifactPathRegistry,
  normalizeArtifactPath,
} from "../ArtifactPaths.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
  type ArtifactReader,
} from "../ArtifactReader.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { SafeOutputTree } from "../SafeOutputTree.js";
import { ZipArtifactReader } from "../ZipArtifactReader.js";
import { MachOSliceArtifactReader } from "../MachOSliceArtifactReader.js";
import {
  artifactExtractionResultSchema,
  type ArtifactExtractionResult,
  type ArtifactGraphManifest,
  type ArtifactNode,
  type ArtifactOccurrence,
  type IntegrityContradiction,
} from "../../domain/artifactGraph.js";
import type { BinaryTarget } from "../../domain/binaryTarget.js";
import { scanArtifactInventory } from "../inventory/ArtifactInventory.js";
import type { ArtifactIntegrityPolicy } from "../inventory/types.js";

/** Local extraction input with the output root chosen by the adapter. */
export interface ArtifactExtractionInput {
  readonly inputPath: string;
  readonly inputFormat: BinaryTarget["format"];
  readonly outputRoot: string;
  /** Integrity mismatches fail unless the caller records and continues. */
  readonly integrity?: ArtifactIntegrityPolicy;
}

/** Extract every regular inventory occurrence into an exclusively owned absent root. */
export const extractArtifact = async (
  input: ArtifactExtractionInput,
  signal?: AbortSignal,
): Promise<ArtifactExtractionResult> => {
  const sourcePath = await realpath(input.inputPath);
  const snapshot = await scanArtifactInventory(sourcePath, {
    signal,
    integrity: input.integrity,
  });
  const selectedOccurrences = snapshot.occurrences.filter(
    (occurrence) =>
      (occurrence.entry_kind === "file" || occurrence.entry_kind === "slice") &&
      occurrence.logical_path !== ".",
  );
  const occurrences = new Map(
    snapshot.occurrences.map((occurrence) => [
      occurrence.occurrence_id,
      occurrence,
    ]),
  );
  const nodes = new Map(snapshot.nodes.map((node) => [node.artifact_id, node]));
  const inventory: LoadedInventory = {
    manifest: snapshot.manifest,
    occurrences,
    nodes,
    integrityContradictions: snapshot.integrity_contradictions,
  };
  const selected = selectedOccurrences.map((occurrence) => {
    if (
      (occurrence.entry_kind !== "file" && occurrence.entry_kind !== "slice") ||
      occurrence.artifact_id === null ||
      occurrence.encrypted ||
      occurrence.logical_path === "."
    )
      throw new ArtifactReaderFailure(
        "format",
        `Selected occurrence is not an extractable regular child file: ${occurrence.occurrence_id}`,
      );
    const node = inventory.nodes.get(occurrence.artifact_id);
    if (node === undefined)
      throw new ArtifactReaderFailure(
        "integrity",
        `Selected occurrence has no inventory node: ${occurrence.occurrence_id}`,
      );
    return { occurrence, node };
  });
  return materializeSelection({
    input,
    sourcePath,
    inventory,
    selected,
    signal,
  });
};

interface SelectedOccurrence {
  readonly occurrence: ArtifactOccurrence;
  readonly node: ArtifactNode;
}

interface ExtractedOccurrence {
  readonly artifact_id: string;
  readonly relative_path: string;
  readonly sha256: string;
  readonly bytes_written: number;
  readonly created: true;
}

const materializeSelection = async ({
  input,
  sourcePath,
  inventory,
  selected,
  signal,
}: {
  readonly input: ArtifactExtractionInput;
  readonly sourcePath: string;
  readonly inventory: LoadedInventory;
  readonly selected: readonly SelectedOccurrence[];
  readonly signal: AbortSignal | undefined;
}): Promise<ArtifactExtractionResult> => {
  const byPath = new Map(
    selected.map((item) => [item.occurrence.logical_path, item]),
  );
  const reader = await createReader(sourcePath, input.inputFormat);
  const output = await SafeOutputTree.create(input.outputRoot);
  let readerClosed = false;
  const extracted: ExtractedOccurrence[] = [];
  try {
    const materialized: SelectedOccurrence[] = [];
    const registry = new ArtifactPathRegistry();
    for await (const entry of reader.entries(signal)) {
      const path = normalizeArtifactPath(entry.path);
      registry.add(path, entry.kind);
      const selectedItem = byPath.get(path);
      if (selectedItem === undefined) {
        if (entry.kind === "file" || entry.kind === "slice")
          throw new ArtifactReaderFailure(
            "integrity",
            `Regular artifact entry is missing from inventory: ${path}`,
          );
        continue;
      }
      preflight(entry);
      const stream = await reader.open(entry, signal);
      const written = await output.write(
        path,
        stream,
        selectedItem.node.sha256,
        signal,
      );
      extracted.push({
        artifact_id: selectedItem.node.artifact_id,
        relative_path: written.relativePath,
        sha256: written.sha256,
        bytes_written: written.bytesWritten,
        created: true,
      });
      materialized.push(selectedItem);
    }
    await reader.close();
    readerClosed = true;
    extracted.sort((left, right) =>
      left.relative_path.localeCompare(right.relative_path, "en"),
    );
    const result = createExtractionResult(
      input,
      inventory,
      materialized,
      extracted,
    );
    await output.commit();
    return result;
  } catch (cause: unknown) {
    if (!readerClosed)
      await reader.close().catch((cause: unknown) => {
        // best-effort cleanup: reader close must not mask the extraction failure.
        void cause;
      });
    await output.rollback();
    throw cause;
  }
};

const createExtractionResult = (
  input: ArtifactExtractionInput,
  inventory: LoadedInventory,
  selected: readonly SelectedOccurrence[],
  extracted: readonly ExtractedOccurrence[],
): ArtifactExtractionResult => {
  const materializedIds = new Set(
    selected.map(({ occurrence }) => occurrence.occurrence_id),
  );
  const materializedPaths = new Map(
    selected.map(({ occurrence }) => [occurrence.logical_path, occurrence]),
  );
  const wasMaterialized = (contradiction: IntegrityContradiction): boolean => {
    if (materializedIds.has(contradiction.occurrence_id)) return true;
    if (!contradiction.unpacked) return false;
    // An unpacked member is read beside its enclosing ASAR, not from ASAR bytes.
    const occurrence = inventory.occurrences.get(contradiction.occurrence_id);
    let parentId = occurrence?.parent_occurrence_id;
    while (parentId !== null && parentId !== undefined) {
      const parent = inventory.occurrences.get(parentId);
      if (parent === undefined) return false;
      if (
        parent.artifact_id !== null &&
        inventory.nodes.get(parent.artifact_id)?.format === "asar"
      ) {
        const companion = materializedPaths.get(
          `${parent.logical_path}.unpacked${contradiction.logical_path.slice(parent.logical_path.length)}`,
        );
        return companion?.artifact_id === occurrence?.artifact_id;
      }
      parentId = parent.parent_occurrence_id;
    }
    return false;
  };
  const writtenContradictions =
    inventory.integrityContradictions.filter(wasMaterialized);
  const nestedContradictions = inventory.integrityContradictions.filter(
    (contradiction) => !wasMaterialized(contradiction),
  );
  const extractionSemantic = {
    source_manifest_id: inventory.manifest.manifest_id,
    selected_occurrence_ids: selected
      .map(({ occurrence }) => occurrence.occurrence_id)
      .sort((left, right) => left.localeCompare(right)),
    files_sha256: canonicalDigest(extracted, "Artifact"),
    output_root_alias: "$OUTPUT_ROOT" as const,
  };
  return artifactExtractionResultSchema.parse({
    manifest: inventory.manifest,
    extraction_manifest: {
      ...extractionSemantic,
      extraction_id: `aex_${canonicalDigest(extractionSemantic, "Artifact")}`,
    },
    output_root: input.outputRoot,
    artifacts: extracted,
    containment_verified: true,
    cleanup: { attempted: false, verified: true, residual_paths: [] },
    provenance: [],
    integrity_contradictions: inventory.integrityContradictions,
    limitations: [
      "All regular files in the active artifact were materialized. The artifacts list identifies written files; nested inventory observations may refer to additional logical paths.",
      ...(writtenContradictions.length === 0
        ? []
        : [
            `${String(writtenContradictions.length)} extracted file(s) contradict declared integrity; their observed bytes were written and are untrusted.`,
          ]),
      ...(nestedContradictions.length === 0
        ? []
        : [
            `${String(nestedContradictions.length)} nested integrity contradiction(s) were not written as their own files (${nestedContradictions.map(({ logical_path }) => logical_path).join(", ")}); their records describe inventory observations, not materialized files.`,
          ]),
    ],
  });
};

interface LoadedInventory {
  readonly manifest: ArtifactGraphManifest;
  readonly occurrences: ReadonlyMap<string, ArtifactOccurrence>;
  readonly nodes: ReadonlyMap<string, ArtifactNode>;
  readonly integrityContradictions: readonly IntegrityContradiction[];
}

const createReader = async (
  path: string,
  format: BinaryTarget["format"],
): Promise<ArtifactReader> => {
  if ((await lstat(path)).isDirectory())
    return new DirectoryArtifactReader(path);
  if (format === "asar") return new AsarArtifactReader(path);
  if (
    format === "ipa" ||
    format === "apk" ||
    format === "msix" ||
    format === "appx" ||
    format === "zip"
  )
    return new ZipArtifactReader(path, format);
  if (format === "mach-o") return new MachOSliceArtifactReader(path);
  throw new ArtifactReaderFailure(
    "unavailable",
    `Artifact format has no extraction reader: ${format}`,
  );
};

const preflight = (entry: ArtifactEntry): void => {
  if ((entry.kind !== "file" && entry.kind !== "slice") || entry.encrypted)
    throw new ArtifactReaderFailure(
      "format",
      `Selected artifact entry cannot be read: ${entry.path}`,
    );
};
