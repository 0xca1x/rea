import { isAbsolute } from "node:path";

import {
  ArtifactPathRegistry,
  normalizeArtifactPath,
} from "../ArtifactPaths.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
  type ArtifactReader,
} from "../ArtifactReader.js";
import { AsarArtifactReader } from "../AsarArtifactReader.js";
import { CpioArtifactReader } from "../CpioArtifactReader.js";
import type { ArtifactNode } from "../../domain/artifactGraph.js";
import {
  classifyArtifactContent,
  createArtifactNode,
  createOccurrence,
  nearestParent,
  type MutableOccurrence,
} from "./ArtifactGraphConstruction.js";
import {
  STRICT_INTEGRITY_POLICY,
  type ArtifactIntegrityPolicy,
} from "./types.js";
import { hashReadable } from "../ArtifactHash.js";

export interface PendingIntegrityContradiction {
  readonly logicalPath: string;
  readonly declaredSha256: string;
  readonly observedSha256: string;
  readonly entryKind: "file" | "slice";
  readonly unpacked: boolean;
}

const UNAVAILABLE_UNPACKED_LIMITATION =
  "ASAR unpacked companion bytes were unavailable; no content hash or child artifact was produced.";

const emptyScan = (): {
  readonly nodes: Map<string, ArtifactNode>;
  readonly occurrences: MutableOccurrence[];
  readonly pendingContradictions: PendingIntegrityContradiction[];
} => ({ nodes: new Map(), occurrences: [], pendingContradictions: [] });

interface ScanContext {
  readonly reader: ArtifactReader;
  readonly signal: AbortSignal | undefined;
  readonly integrity: ArtifactIntegrityPolicy;
  readonly nodes: Map<string, ArtifactNode>;
  readonly occurrences: MutableOccurrence[];
  readonly pendingContradictions: PendingIntegrityContradiction[];
  readonly occurrenceByPath: Map<string, MutableOccurrence>;
  readonly registry: ArtifactPathRegistry;
  readonly expandedContainerIds: Set<string>;
}

export const scanReader = async (
  reader: ArtifactReader | undefined,
  signal?: AbortSignal,
  integrity: ArtifactIntegrityPolicy = STRICT_INTEGRITY_POLICY,
): Promise<{
  readonly nodes: Map<string, ArtifactNode>;
  readonly occurrences: MutableOccurrence[];
  readonly pendingContradictions: PendingIntegrityContradiction[];
}> => {
  const { nodes, occurrences, pendingContradictions } = emptyScan();
  if (reader === undefined)
    return { nodes, occurrences, pendingContradictions };
  const context: ScanContext = {
    reader,
    signal,
    integrity,
    nodes,
    occurrences,
    pendingContradictions,
    occurrenceByPath: new Map<string, MutableOccurrence>(),
    registry: new ArtifactPathRegistry(),
    expandedContainerIds: new Set<string>(),
  };
  await visitArtifactEntries(context, reader, "");
  // Archive directories may appear after their children. Resolve containment
  // against the complete index before directory identities are materialized.
  for (const occurrence of occurrences)
    occurrence.parent_occurrence_id =
      nearestParent(
        occurrence.logical_path,
        context.occurrenceByPath,
        context.expandedContainerIds,
      )?.occurrence_id ?? null;
  return { nodes, occurrences, pendingContradictions };
};

const visitArtifactEntries = async (
  context: ScanContext,
  currentReader: ArtifactReader,
  prefix: string,
): Promise<void> => {
  const stack: Array<{
    readonly reader: ArtifactReader;
    readonly prefix: string;
    readonly iterator: AsyncIterator<ArtifactEntry>;
    readonly owned: boolean;
  }> = [
    {
      reader: currentReader,
      prefix,
      iterator: currentReader.entries(context.signal)[Symbol.asyncIterator](),
      owned: false,
    },
  ];
  try {
    while (stack.length > 0) {
      const frame = stack.at(-1);
      if (frame === undefined) break;
      const next = await frame.iterator.next();
      if (next.done) {
        stack.pop();
        if (frame.owned) await frame.reader.close();
        continue;
      }
      const entry = next.value;
      const logicalPath = normalizeArtifactPath(
        frame.prefix.length === 0
          ? entry.path
          : `${frame.prefix}/${entry.path}`,
      );
      const expandable =
        isExpandableAsar(entry, logicalPath) ||
        entry.nestedArchive === "gzip-cpio";
      context.registry.add(logicalPath, expandable ? "directory" : entry.kind);
      const occurrence = createOccurrence(entry, logicalPath, null);
      let digested: DigestedEntry | undefined;
      try {
        digested = await digestArtifactEntry(
          context,
          frame.reader,
          entry,
          logicalPath,
        );
      } catch (cause: unknown) {
        if (!isUnavailableUnpackedEntry(cause, entry)) {
          // A streamed CRC, size-bound, or format failure is per-member
          // evidence loss under record-and-continue: keep the occurrence
          // unavailable with its diagnostic, without inventing a node.
          if (
            context.integrity.mode !== "record-and-continue" ||
            !(cause instanceof ArtifactReaderFailure) ||
            (cause.reason !== "integrity" &&
              cause.reason !== "limit" &&
              cause.reason !== "format")
          )
            throw cause;
          occurrence.hash_status = "unavailable";
          occurrence.limitations.push(
            `Member content could not be verified: ${cause.message}`,
          );
          context.occurrences.push(occurrence);
          context.occurrenceByPath.set(logicalPath, occurrence);
          continue;
        }
        occurrence.hash_status = "unavailable";
        occurrence.limitations.push(UNAVAILABLE_UNPACKED_LIMITATION);
      }
      if (digested !== undefined) {
        context.nodes.set(digested.node.artifact_id, digested.node);
        occurrence.artifact_id = digested.node.artifact_id;
        occurrence.hash_status = digested.mismatched
          ? "mismatched"
          : "verified";
        if (digested.mismatched)
          occurrence.limitations.push(
            "Declared integrity metadata contradicts observed bytes.",
            ...digested.mismatchDetails,
          );
      }
      context.occurrences.push(occurrence);
      context.occurrenceByPath.set(logicalPath, occurrence);
      if (expandable && digested?.mismatched !== true) {
        const parent = frame.reader;
        const nested: ArtifactReader =
          entry.nestedArchive === "gzip-cpio"
            ? new CpioArtifactReader(
                (signal) => parent.open(entry, signal),
                context.integrity.mode,
                parent.decodedBudget,
              )
            : new AsarArtifactReader(entry.adapterKey);
        // Only traversed containers can own members, not opaque archive-named files.
        context.expandedContainerIds.add(occurrence.occurrence_id);
        stack.push({
          reader: nested,
          prefix: logicalPath,
          iterator: nested.entries(context.signal)[Symbol.asyncIterator](),
          owned: true,
        });
      }
    }
  } finally {
    await Promise.allSettled(
      stack
        .filter(({ owned }) => owned)
        .map(async ({ reader, iterator }) => {
          await iterator.return?.();
          await reader.close();
        }),
    );
  }
};

interface DigestedEntry {
  readonly node: ArtifactNode;
  readonly mismatched: boolean;
  /** Declared and observed values of a non-SHA-256 checksum that disagreed. */
  readonly mismatchDetails: readonly string[];
}

const digestArtifactEntry = async (
  context: ScanContext,
  currentReader: ArtifactReader,
  entry: ArtifactEntry,
  logicalPath: string,
): Promise<DigestedEntry | undefined> => {
  if (
    (entry.kind !== "file" && entry.kind !== "slice") ||
    entry.encrypted ||
    entry.contentUnavailable === true
  )
    return undefined;
  const checksum = entry.declaredChecksum;
  const digest = await hashReadable(
    await currentReader.open(entry, context.signal),
    context.signal,
    checksum?.algorithm,
  );
  const sha256Mismatch =
    entry.declaredSha256 !== null && entry.declaredSha256 !== digest.sha256;
  const checksumMismatch =
    checksum !== undefined && checksum.value !== digest.also;
  const storedMismatches = (
    currentReader.integrityObservations?.(entry) ?? []
  ).filter(({ declared, observed }) => declared !== observed);
  const mismatched =
    sha256Mismatch || checksumMismatch || storedMismatches.length > 0;
  if (mismatched && context.integrity.mode === "fail")
    throw new ArtifactReaderFailure(
      "integrity",
      sha256Mismatch || checksum === undefined
        ? `Artifact integrity metadata disagrees with content: ${logicalPath}`
        : `Declared ${checksum.algorithm} checksum disagrees with content: ${logicalPath}`,
      undefined,
      {
        logicalPath,
        declaredSha256: entry.declaredSha256,
        calculatedSha256: digest.sha256,
        unpacked: entry.unpacked,
      },
    );
  if (sha256Mismatch && entry.declaredSha256 !== null)
    context.pendingContradictions.push({
      logicalPath,
      declaredSha256: entry.declaredSha256,
      observedSha256: digest.sha256,
      entryKind: entry.kind,
      unpacked: entry.unpacked,
    });
  const classified =
    entry.kind === "slice"
      ? ({ kind: "universal-slice", format: "mach-o" } as const)
      : classifyArtifactContent(logicalPath, digest.prefix, digest.bytes);
  return {
    node: createArtifactNode({
      sha256: digest.sha256,
      size: digest.bytes,
      kind: classified.kind,
      format: classified.format,
      executable: entry.executable,
      contentState: "embedded",
      limitations: mismatched
        ? [
            "Observed content contradicts declared integrity metadata and is untrusted.",
          ]
        : [],
    }),
    mismatched,
    mismatchDetails: [
      ...(checksumMismatch
        ? [
            `Declared ${checksum.algorithm} ${checksum.value} disagrees with observed ${digest.also ?? "unavailable"}.`,
          ]
        : []),
      ...storedMismatches.map(
        ({ algorithm, declared, observed }) =>
          `Declared stored ${algorithm} ${declared} disagrees with observed ${observed}.`,
      ),
    ],
  };
};

const isExpandableAsar = (entry: ArtifactEntry, logicalPath: string): boolean =>
  entry.kind === "file" &&
  logicalPath.toLowerCase().endsWith(".asar") &&
  isAbsolute(entry.adapterKey);

const isUnavailableUnpackedEntry = (
  cause: unknown,
  entry: ArtifactEntry,
): boolean =>
  entry.unpacked &&
  cause instanceof ArtifactReaderFailure &&
  cause.reason === "unavailable";
