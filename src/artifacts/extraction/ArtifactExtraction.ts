import { lstat, realpath } from "node:fs/promises";

import { canonicalDigest } from "../../domain/comparisonSemantics.js";
import { AsarArtifactReader } from "../AsarArtifactReader.js";
import { CpioArtifactReader } from "../CpioArtifactReader.js";
import { XarArtifactReader } from "../XarArtifactReader.js";
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
} from "../../domain/artifactGraph.js";
import type { BinaryTarget } from "../../domain/binaryTarget.js";
import { scanArtifactInventory } from "../inventory/ArtifactInventory.js";

/** Local extraction input with the output root chosen by the adapter. */
export interface ArtifactExtractionInput {
  readonly inputPath: string;
  readonly inputFormat: BinaryTarget["format"];
  readonly outputRoot: string;
}

/** Extract every regular inventory occurrence into an exclusively owned absent root. */
export const extractArtifact = async (
  input: ArtifactExtractionInput,
  signal?: AbortSignal,
): Promise<ArtifactExtractionResult> => {
  const sourcePath = await realpath(input.inputPath);
  const snapshot = await scanArtifactInventory(sourcePath, {
    signal,
  });
  const selectedOccurrences = snapshot.occurrences.filter(
    (occurrence) =>
      (occurrence.entry_kind === "file" || occurrence.entry_kind === "slice") &&
      occurrence.hash_status !== "unavailable" &&
      occurrence.logical_path !== ".",
  );
  const selectedIds = new Set(
    selectedOccurrences.map(({ occurrence_id: id }) => id),
  );
  const occurrences = new Map<string, ArtifactOccurrence>();
  const neededNodes = new Set<string>();
  collectOccurrences(
    snapshot.occurrences,
    selectedIds,
    occurrences,
    neededNodes,
  );
  const nodes = new Map<string, ArtifactNode>();
  collectNodes(snapshot.nodes, neededNodes, nodes);
  const inventory: LoadedInventory = {
    manifest: snapshot.manifest,
    occurrences,
    nodes,
    unavailablePaths: snapshot.occurrences
      .filter(({ hash_status }) => hash_status === "unavailable")
      .map(({ logical_path }) => logical_path),
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
  const stack: Array<{
    readonly reader: ArtifactReader;
    readonly prefix: string;
    readonly iterator: AsyncIterator<ArtifactEntry>;
    readonly owned: boolean;
  }> = [
    {
      reader,
      prefix: "",
      iterator: reader.entries(signal)[Symbol.asyncIterator](),
      owned: false,
    },
  ];
  try {
    const materialized: SelectedOccurrence[] = [];
    const registry = new ArtifactPathRegistry();
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      if (frame === undefined) break;
      const next = await frame.iterator.next();
      if (next.done === true) {
        stack.pop();
        if (frame.owned) await frame.reader.close();
        continue;
      }
      const entry = next.value;
      const path = normalizeArtifactPath(
        frame.prefix === "" ? entry.path : `${frame.prefix}/${entry.path}`,
      );
      // Traverse expanded PKG Payload/Scripts like inventory does, so nested
      // members are materialized instead of silently skipped. An expanded
      // member acts as a container: register it as a directory and leave its
      // archive bytes to its children, since a file and a directory cannot
      // share one output path.
      const expandable =
        entry.nestedArchive === "gzip-cpio" &&
        !entry.encrypted &&
        entry.contentUnavailable !== true;
      registry.add(path, expandable ? "directory" : entry.kind);
      if (expandable) {
        const parent = frame.reader;
        const nested = new CpioArtifactReader((nestedSignal) =>
          parent.open(entry, nestedSignal),
        );
        stack.push({
          reader: nested,
          prefix: path,
          iterator: nested.entries(signal)[Symbol.asyncIterator](),
          owned: true,
        });
        continue;
      }
      const selectedItem = byPath.get(path);
      if (selectedItem === undefined) {
        if (
          entry.contentUnavailable === true &&
          inventory.unavailablePaths.includes(path)
        )
          continue;
        if (entry.kind === "file" || entry.kind === "slice")
          throw new ArtifactReaderFailure(
            "integrity",
            `Regular artifact entry is missing from inventory: ${path}`,
          );
        continue;
      }
      preflight(entry);
      const stream = await frame.reader.open(entry, signal);
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
    await Promise.allSettled(
      stack
        .filter(({ owned }) => owned)
        .map(async ({ reader, iterator }) => {
          await iterator.return?.();
          await reader.close();
        }),
    );
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
    limitations: [
      "All available selected regular files were materialized; expanded PKG Payload/Scripts archives are represented by their extracted children.",
      ...inventory.unavailablePaths.map(
        (path) =>
          `Unavailable member ${path} was not extracted; see its inventory occurrence for the reason.`,
      ),
    ],
  });
};

interface LoadedInventory {
  readonly manifest: ArtifactGraphManifest;
  readonly occurrences: ReadonlyMap<string, ArtifactOccurrence>;
  readonly nodes: ReadonlyMap<string, ArtifactNode>;
  readonly unavailablePaths: readonly string[];
}

const collectOccurrences = (
  items: readonly ArtifactOccurrence[],
  selected: ReadonlySet<string>,
  output: Map<string, ArtifactOccurrence>,
  neededNodes: Set<string>,
): void => {
  for (const item of items) {
    if (!selected.has(item.occurrence_id)) continue;
    output.set(item.occurrence_id, item);
    if (item.artifact_id !== null) neededNodes.add(item.artifact_id);
  }
};

const collectNodes = (
  items: readonly ArtifactNode[],
  selected: ReadonlySet<string>,
  output: Map<string, ArtifactNode>,
): void => {
  for (const item of items)
    if (selected.has(item.artifact_id)) output.set(item.artifact_id, item);
};

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
  if (format === "pkg") return new XarArtifactReader(path);
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
