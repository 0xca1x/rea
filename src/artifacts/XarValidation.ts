import { ArtifactReaderFailure } from "./ArtifactReader.js";

/**
 * Node ceiling for one TOC. The byte cap still allows millions of tiny
 * elements, comments, and processing instructions. The DOM is built before
 * member collection can charge the metadata budget.
 */
const MAX_TOC_NODES = 100_000;

/** Bound DOM-producing markup, including comments, CDATA and processing instructions. */
export const assertXarTocNodes = (xml: string): void => {
  let nodes = 0;
  let index = xml.indexOf("<");
  while (index !== -1) {
    if (xml[index + 1] !== "/") {
      nodes += 1;
      if (nodes > MAX_TOC_NODES)
        throw new ArtifactReaderFailure(
          "limit",
          `xar TOC exceeds ${MAX_TOC_NODES} XML nodes`,
        );
    }
    const terminator = xml.startsWith("<!--", index)
      ? "-->"
      : xml.startsWith("<![CDATA[", index)
        ? "]]>"
        : xml.startsWith("<?", index)
          ? "?>"
          : ">";
    const end = xml.indexOf(terminator, index + 1);
    if (end === -1) return; // The XML parser reports malformed framing.
    index = xml.indexOf("<", end + terminator.length);
  }
};

/** Required XAR integer syntax: nonempty unsigned decimal, exactly representable. */
export const xarInteger = (
  value: string | undefined,
  label: string,
): number => {
  const text = value?.trim() ?? "";
  const parsed = /^\d+$/u.test(text) ? Number(text) : Number.NaN;
  if (!Number.isSafeInteger(parsed))
    throw new ArtifactReaderFailure(
      "format",
      `xar TOC has an invalid ${label}`,
    );
  return parsed;
};

/** Optional mode metadata is accepted only as a complete unsigned octal field. */
export const xarMode = (value: string | undefined): number | null => {
  if (value === undefined) return null;
  const text = value.trim();
  const mode = /^[0-7]+$/u.test(text) ? Number.parseInt(text, 8) : Number.NaN;
  if (!Number.isSafeInteger(mode))
    throw new ArtifactReaderFailure("format", "xar TOC has an invalid mode");
  return mode;
};

/** Validate the entire absolute heap range before allocating or requesting it. */
export const xarHeapPosition = (
  heap: number,
  offset: number,
  length: number,
  size: number,
): number => {
  const position = heap + offset;
  const end = position + length;
  if (
    ![position, end, offset, length].every(Number.isSafeInteger) ||
    offset < 0 ||
    length < 0 ||
    end > size
  )
    throw new ArtifactReaderFailure(
      "format",
      "xar member has an invalid or out-of-file heap extent",
    );
  return position;
};

/** Bound retained path text before constructing paths from deeply nested TOCs. */
export class XarPathBudget {
  #used = 0;
  private readonly maximumPathBytes = 4096;
  private readonly maximumTotalBytes = 16 * 1024 * 1024;

  /** Form the next path only when individual and cumulative budgets permit it. */
  join(parent: string, name: string): string {
    const bytes =
      Buffer.byteLength(parent) +
      Buffer.byteLength(name) +
      (parent.length > 0 ? 1 : 0);
    if (
      bytes > this.maximumPathBytes ||
      bytes > this.maximumTotalBytes - this.#used
    )
      throw new ArtifactReaderFailure(
        "limit",
        `xar TOC path text exceeds its ${this.maximumPathBytes}-byte path or ${this.maximumTotalBytes}-byte cumulative budget`,
      );
    this.#used += bytes;
    return parent === "" ? name : `${parent}/${name}`;
  }
}
