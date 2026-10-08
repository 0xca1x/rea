import { isAbsolute } from "node:path";
import { normalizeArtifactPath } from "./ArtifactPaths.js";
import type { ArtifactEntry, ArtifactReader } from "./ArtifactReader.js";
import { AsarArtifactReader } from "./AsarArtifactReader.js";
import { CpioArtifactReader } from "./CpioArtifactReader.js";

/** One reader entry plus its stable logical path and expansion eligibility. */
export interface ArtifactTreeEntry {
  readonly reader: ArtifactReader;
  readonly entry: ArtifactEntry;
  readonly path: string;
  readonly container: boolean;
}

/**
 * Shared inventory/extraction traversal. The visitor decides whether verified
 * content may expand; this boundary owns nested paths, reader creation and
 * cleanup so the two workflows cannot disagree about container topology.
 */
export const visitArtifactTree = async (
  root: ArtifactReader,
  visit: (item: ArtifactTreeEntry) => Promise<boolean>,
  options: {
    readonly signal?: AbortSignal | undefined;
    readonly integrity?: "fail" | "record-and-continue";
    readonly expandAsar?: boolean;
  } = {},
): Promise<void> => {
  const stack = [
    {
      reader: root,
      prefix: "",
      iterator: root.entries(options.signal)[Symbol.asyncIterator](),
      owned: false,
    },
  ];
  try {
    while (stack.length > 0) {
      const frame = stack.at(-1);
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
      const cpio = entry.nestedArchive === "gzip-cpio";
      const asar =
        options.expandAsar !== false &&
        entry.kind === "file" &&
        path.toLowerCase().endsWith(".asar") &&
        isAbsolute(entry.adapterKey);
      const container =
        !entry.encrypted && entry.contentUnavailable !== true && (cpio || asar);
      const expand = await visit({
        reader: frame.reader,
        entry,
        path,
        container,
      });
      if (!container || !expand) continue;
      const parent = frame.reader;
      const nested = cpio
        ? new CpioArtifactReader(
            (signal) => parent.open(entry, signal),
            options.integrity ?? "fail",
            parent.decodedBudget,
          )
        : new AsarArtifactReader(entry.adapterKey);
      stack.push({
        reader: nested,
        prefix: path,
        iterator: nested.entries(options.signal)[Symbol.asyncIterator](),
        owned: true,
      });
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
