import { createHash, type Hash } from "node:crypto";
import { open, type FileHandle } from "node:fs/promises";
import { Readable, Transform, type TransformCallback } from "node:stream";
import { createInflate, inflateSync } from "node:zlib";

import { DOMParser, type Element, type Node } from "@xmldom/xmldom";

import type { ArtifactCommand } from "../domain/artifactGraph.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
  type ArtifactReader,
} from "./ArtifactReader.js";

const XAR_MAGIC = 0x78617221;
/** A TOC describes members only; real installer TOCs are kilobytes. */
const MAX_TOC_BYTES = 64 * 1024 * 1024;
const READ_CHUNK_BYTES = 1024 * 1024;

const CHECKSUM_ALGORITHMS: Readonly<Record<string, string>> = {
  sha1: "sha1",
  md5: "md5",
  sha256: "sha256",
  sha512: "sha512",
};

/** One TOC `<data>` element: where a member's archived bytes live in the heap. */
interface XarData {
  readonly offset: number;
  readonly length: number;
  readonly size: number;
  readonly encoding: string;
  readonly extractedChecksum:
    | { readonly algorithm: string; readonly value: string }
    | undefined;
}

interface XarMember {
  readonly path: string;
  readonly kind: "file" | "directory" | "symlink";
  readonly mode: number | null;
  readonly data: XarData | undefined;
  readonly link: string | undefined;
}

const isElement = (node: Node): node is Element => node.nodeType === 1;

/** Direct child elements with one tag name, in document order. */
const childElements = (element: Element, name: string): Element[] =>
  Array.from(element.childNodes).filter(
    (child): child is Element => isElement(child) && child.tagName === name,
  );

const childElement = (element: Element, name: string): Element | undefined =>
  childElements(element, name)[0];

const textOf = (element: Element, name: string): string | undefined =>
  childElement(element, name)?.textContent ?? undefined;

const integer = (value: string | undefined, label: string): number => {
  const parsed = value === undefined ? Number.NaN : Number(value.trim());
  if (!Number.isSafeInteger(parsed) || parsed < 0)
    throw new ArtifactReaderFailure(
      "format",
      `xar TOC has an invalid ${label}`,
    );
  return parsed;
};

const parseData = (file: Element): XarData | undefined => {
  const data = childElement(file, "data");
  if (data === undefined) return undefined;
  const checksum = childElement(data, "extracted-checksum");
  const style = checksum?.getAttribute("style")?.toLowerCase() ?? "";
  return {
    offset: integer(textOf(data, "offset"), "data offset"),
    length: integer(textOf(data, "length"), "data length"),
    size: integer(textOf(data, "size"), "data size"),
    encoding:
      childElement(data, "encoding")?.getAttribute("style") ??
      "application/octet-stream",
    extractedChecksum:
      checksum === undefined || CHECKSUM_ALGORITHMS[style] === undefined
        ? undefined
        : {
            algorithm: style,
            value: (checksum.textContent ?? "").trim().toLowerCase(),
          },
  };
};

/** Walk nested `<file>` elements in document order. */
const collectMembers = (toc: Element): XarMember[] => {
  const members: XarMember[] = [];
  const pending: Array<{ readonly element: Element; readonly parent: string }> =
    childElements(toc, "file")
      .map((element) => ({ element, parent: "" }))
      .reverse();
  while (pending.length > 0) {
    const next = pending.pop();
    if (next === undefined) break;
    const name = textOf(next.element, "name");
    if (
      name === undefined ||
      name === "" ||
      name.includes("/") ||
      name === "." ||
      name === ".."
    )
      throw new ArtifactReaderFailure("path", "xar member has an unsafe name");
    const path = next.parent === "" ? name : `${next.parent}/${name}`;
    const type = textOf(next.element, "type")?.trim();
    const modeText = textOf(next.element, "mode");
    const mode =
      modeText === undefined ? Number.NaN : Number.parseInt(modeText.trim(), 8);
    const kind =
      type === "directory"
        ? "directory"
        : type === "symlink"
          ? "symlink"
          : "file";
    members.push({
      path,
      kind,
      mode: Number.isSafeInteger(mode) ? mode : null,
      data: kind === "file" ? parseData(next.element) : undefined,
      link: kind === "symlink" ? textOf(next.element, "link") : undefined,
    });
    pending.push(
      ...childElements(next.element, "file")
        .map((element) => ({ element, parent: path }))
        .reverse(),
    );
  }
  return members;
};

/** Verify a member's extracted checksum as its decoded bytes stream past. */
class ChecksumVerifier extends Transform {
  readonly #hash: Hash;

  constructor(
    private readonly path: string,
    private readonly expected: {
      readonly algorithm: string;
      readonly value: string;
    },
  ) {
    super();
    this.#hash = createHash(expected.algorithm);
  }

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    done: TransformCallback,
  ): void {
    this.#hash.update(chunk);
    done(null, chunk);
  }

  override _flush(done: TransformCallback): void {
    const observed = this.#hash.digest("hex");
    done(
      observed === this.expected.value
        ? null
        : new ArtifactReaderFailure(
            "integrity",
            `xar ${this.expected.algorithm} checksum disagrees with content: ${this.path}`,
          ),
    );
  }
}

/** First bytes that identify an installer archive member's own format. */
export type XarNestedArchive = "gzip-cpio";

/**
 * Read-only reader for xar archives, the container of flat installer
 * packages. Members are decoded and checksum-verified on demand. Gzip cpio
 * `Scripts` and `Payload` members are marked for nested expansion; pbzx
 * (LZMA) payloads are recorded as files with a limitation.
 */
export class XarArtifactReader implements ArtifactReader {
  readonly format = "pkg" as const;
  #handle: FileHandle | undefined;
  #heap = 0;
  #members: readonly XarMember[] = [];

  constructor(private readonly path: string) {}

  async #load(signal?: AbortSignal): Promise<void> {
    if (this.#handle !== undefined) return;
    signal?.throwIfAborted();
    const handle = await open(this.path, "r");
    this.#handle = handle;
    const header = Buffer.alloc(28);
    const { bytesRead } = await handle.read(header, 0, 28, 0);
    if (bytesRead < 28 || header.readUInt32BE(0) !== XAR_MAGIC)
      throw new ArtifactReaderFailure("format", "File is not a xar archive");
    const headerSize = header.readUInt16BE(4);
    const tocCompressed = header.readBigUInt64BE(8);
    const tocSize = header.readBigUInt64BE(16);
    if (headerSize < 28)
      throw new ArtifactReaderFailure("format", "xar header is too short");
    if (
      tocCompressed > BigInt(MAX_TOC_BYTES) ||
      tocSize > BigInt(MAX_TOC_BYTES)
    )
      throw new ArtifactReaderFailure(
        "limit",
        `xar TOC exceeds the ${MAX_TOC_BYTES}-byte limit`,
      );
    const compressed = Buffer.alloc(Number(tocCompressed));
    const toc = await handle.read(compressed, 0, compressed.length, headerSize);
    if (toc.bytesRead < compressed.length)
      throw new ArtifactReaderFailure("format", "xar TOC is truncated");
    this.#heap = headerSize + compressed.length;
    let xml: string;
    try {
      xml = inflateSync(compressed, {
        maxOutputLength: MAX_TOC_BYTES,
      }).toString("utf8");
    } catch (cause: unknown) {
      throw new ArtifactReaderFailure("format", "xar TOC is not zlib data", {
        cause,
      });
    }
    let document;
    try {
      document = new DOMParser({
        onError: (level, message) => {
          if (level !== "warning") throw new Error(message);
        },
      }).parseFromString(xml, "text/xml");
    } catch (cause: unknown) {
      throw new ArtifactReaderFailure(
        "format",
        "xar TOC is not well-formed XML",
        { cause },
      );
    }
    const root = document.documentElement;
    const tocElement = root === null ? undefined : childElement(root, "toc");
    if (tocElement === undefined)
      throw new ArtifactReaderFailure("format", "xar TOC has no <toc> element");
    await this.#verifyToc(tocElement, compressed);
    this.#members = collectMembers(tocElement);
  }

  /** The TOC checksum in the heap covers the compressed TOC bytes. */
  async #verifyToc(toc: Element, compressed: Buffer): Promise<void> {
    const checksum = childElement(toc, "checksum");
    const algorithm =
      CHECKSUM_ALGORITHMS[checksum?.getAttribute("style")?.toLowerCase() ?? ""];
    if (checksum === undefined || algorithm === undefined) return;
    const stored = await this.#heapBytes(
      integer(textOf(checksum, "offset"), "checksum offset"),
      integer(textOf(checksum, "size"), "checksum size"),
    );
    if (!createHash(algorithm).update(compressed).digest().equals(stored))
      throw new ArtifactReaderFailure(
        "integrity",
        "xar TOC checksum disagrees with the TOC",
      );
  }

  async #heapBytes(offset: number, length: number): Promise<Buffer> {
    const handle = this.#handle;
    if (handle === undefined)
      throw new ArtifactReaderFailure("unavailable", "xar archive is closed");
    const bytes = Buffer.alloc(length);
    const { bytesRead } = await handle.read(
      bytes,
      0,
      length,
      this.#heap + offset,
    );
    if (bytesRead < length)
      throw new ArtifactReaderFailure(
        "format",
        "xar member extends beyond the archive",
      );
    return bytes;
  }

  /** Classify a raw-stored installer member by its leading bytes. */
  async #nestedArchive(member: XarMember): Promise<{
    readonly nested: XarNestedArchive | undefined;
    readonly limitations: readonly string[];
  }> {
    const name = member.path.split("/").at(-1);
    const data = member.data;
    if (
      (name !== "Payload" && name !== "Scripts") ||
      data === undefined ||
      data.length < 4
    )
      return { nested: undefined, limitations: [] };
    if (data.encoding !== "application/octet-stream")
      return {
        nested: undefined,
        limitations: [
          `${name} is stored with ${data.encoding}; its archive is not expanded.`,
        ],
      };
    const head = await this.#heapBytes(data.offset, 4);
    if (head[0] === 0x1f && head[1] === 0x8b)
      return { nested: "gzip-cpio", limitations: [] };
    if (head.toString("latin1") === "pbzx")
      return {
        nested: undefined,
        limitations: [
          `${name} is a pbzx (LZMA) archive; its members are not expanded. Expand it with pkgutil --expand-full to inspect them.`,
        ],
      };
    return {
      nested: undefined,
      limitations: [
        `${name} has an unrecognized archive format and is not expanded.`,
      ],
    };
  }

  async *entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry> {
    await this.#load(signal);
    for (const member of this.#members) {
      signal?.throwIfAborted();
      const classified =
        member.kind === "file"
          ? await this.#nestedArchive(member)
          : { nested: undefined, limitations: [] };
      yield {
        path: member.path,
        kind: member.kind,
        declaredSize: member.data?.size ?? (member.kind === "file" ? 0 : null),
        compressedSize: member.data?.length ?? null,
        executable: member.mode !== null && (member.mode & 0o111) !== 0,
        encrypted: false,
        byteOffset:
          member.data?.encoding === "application/octet-stream"
            ? this.#heap + member.data.offset
            : null,
        // xar declares SHA-1/MD5 checksums, which open() verifies itself.
        declaredSha256: null,
        unpacked: false,
        limitations: [
          ...(member.kind === "symlink" && member.link !== undefined
            ? [`Symlink target recorded in the TOC: ${member.link}`]
            : []),
          ...classified.limitations,
        ],
        adapterKey: member.path,
        ...(classified.nested === undefined
          ? {}
          : { nestedArchive: classified.nested }),
      };
    }
  }

  async open(entry: ArtifactEntry, signal?: AbortSignal): Promise<Readable> {
    await this.#load(signal);
    const member = this.#members.find(({ path }) => path === entry.adapterKey);
    if (member === undefined || member.kind !== "file")
      throw new ArtifactReaderFailure(
        "path",
        `xar member is not a file: ${entry.path}`,
      );
    const data = member.data;
    if (data === undefined) return Readable.from([]);
    const raw = Readable.from(this.#chunks(data.offset, data.length, signal));
    let decoded: Readable;
    if (data.encoding === "application/octet-stream") decoded = raw;
    else if (data.encoding === "application/x-gzip")
      // xar's "x-gzip" members are zlib streams.
      decoded = raw.pipe(createInflate());
    else
      throw new ArtifactReaderFailure(
        "format",
        `xar member ${entry.path} uses unsupported encoding ${data.encoding}`,
      );
    const checksum = data.extractedChecksum;
    if (checksum === undefined) return decoded;
    const verified = new ChecksumVerifier(entry.path, checksum);
    decoded.on("error", (cause: unknown) =>
      verified.destroy(cause instanceof Error ? cause : undefined),
    );
    return decoded.pipe(verified);
  }

  async *#chunks(
    offset: number,
    length: number,
    signal?: AbortSignal,
  ): AsyncGenerator<Buffer> {
    for (let done = 0; done < length;) {
      signal?.throwIfAborted();
      const size = Math.min(READ_CHUNK_BYTES, length - done);
      yield await this.#heapBytes(offset + done, size);
      done += size;
    }
  }

  provenance(): readonly ArtifactCommand[] {
    return [];
  }

  async close(): Promise<void> {
    const handle = this.#handle;
    this.#handle = undefined;
    await handle?.close();
  }
}
