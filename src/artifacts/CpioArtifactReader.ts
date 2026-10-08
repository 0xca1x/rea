import { Readable, Transform, type TransformCallback } from "node:stream";
import { createGunzip } from "node:zlib";

import type { ArtifactCommand } from "../domain/artifactGraph.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
  type ArtifactReader,
} from "./ArtifactReader.js";

/** Longest member name accepted, including its terminating NUL. */
const MAX_NAME_BYTES = 64 * 1024;
/** Hard-link bytes are buffered to serve every linked path, within these bounds. */
const MAX_LINK_BUFFER_BYTES = 16 * 1024 * 1024;
const MAX_LINK_BUFFER_TOTAL = 64 * 1024 * 1024;
/** Longest symlink target read; PATH_MAX is 1024 on macOS and 4096 on Linux. */
const MAX_SYMLINK_TARGET_BYTES = 4096;
/** Total decompressed cpio bytes accepted from one archive (gzip-bomb budget). */
const MAX_TOTAL_DECOMPRESSED_BYTES = 512 * 1024 * 1024;
const TRAILER = "TRAILER!!!";
const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;
const S_IFLNK = 0o120000;

const UNRESOLVED_LINK =
  "Hard-link bytes are stored with another member of this archive and could not be associated with this path.";

/** Pull exactly the requested bytes from a stream, holding at most one chunk. */
class ByteSource {
  readonly #iterator: AsyncIterator<unknown>;
  #buffer: Buffer = Buffer.alloc(0);

  constructor(stream: Readable) {
    this.#iterator = stream[Symbol.asyncIterator]();
  }

  async #fill(): Promise<boolean> {
    let next: IteratorResult<unknown>;
    try {
      next = await this.#iterator.next();
    } catch (cause: unknown) {
      if (cause instanceof ArtifactReaderFailure) throw cause;
      throw new ArtifactReaderFailure(
        "format",
        "cpio stream is not valid gzip data",
        { cause },
      );
    }
    if (next.done === true) return false;
    if (!Buffer.isBuffer(next.value))
      throw new ArtifactReaderFailure(
        "format",
        "cpio stream yielded non-binary data",
      );
    this.#buffer =
      this.#buffer.length === 0
        ? next.value
        : Buffer.concat([this.#buffer, next.value]);
    return true;
  }

  async read(length: number, label: string): Promise<Buffer> {
    while (this.#buffer.length < length)
      if (!(await this.#fill()))
        throw new ArtifactReaderFailure("format", `cpio ${label} is truncated`);
    const bytes = this.#buffer.subarray(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return bytes;
  }

  /** Yield `length` bytes in chunks without buffering them together. */
  async *take(length: number, label: string): AsyncGenerator<Buffer> {
    let remaining = length;
    while (remaining > 0) {
      if (this.#buffer.length === 0 && !(await this.#fill()))
        throw new ArtifactReaderFailure("format", `cpio ${label} is truncated`);
      const size = Math.min(remaining, this.#buffer.length);
      const chunk = this.#buffer.subarray(0, size);
      this.#buffer = this.#buffer.subarray(size);
      remaining -= size;
      yield chunk;
    }
  }

  async close(): Promise<void> {
    await this.#iterator.return?.();
  }
}

/** Bound total decompressed bytes so a gzip bomb cannot exhaust the process. */
class DecodedBudget extends Transform {
  #seen = 0;

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    done: TransformCallback,
  ): void {
    this.#seen += chunk.length;
    if (this.#seen > MAX_TOTAL_DECOMPRESSED_BYTES) {
      done(
        new ArtifactReaderFailure(
          "limit",
          `cpio archive decodes beyond ${MAX_TOTAL_DECOMPRESSED_BYTES} bytes`,
        ),
      );
      return;
    }
    done(null, chunk);
  }
}

interface CpioHeader {
  readonly format: "odc" | "newc" | "crc";
  readonly mode: number;
  readonly fileSize: number;
  readonly nameSize: number;
  readonly links: number;
  /** Device and inode identifying hard links. */
  readonly identity: string;
  /** `c_check` of `070702` archives: the unsigned 32-bit sum of the data bytes. */
  readonly check: number;
}

const field = (
  bytes: Buffer,
  start: number,
  width: number,
  radix: 8 | 16,
): number => {
  const text = bytes.toString("latin1", start, start + width);
  const pattern = radix === 8 ? /^[0-7]+$/u : /^[0-9a-fA-F]+$/u;
  const value = pattern.test(text) ? Number.parseInt(text, radix) : Number.NaN;
  if (!Number.isSafeInteger(value))
    throw new ArtifactReaderFailure(
      "format",
      "cpio header has a malformed numeric field",
    );
  return value;
};

/** odc (`070707`, octal) and newc/crc (`070701`/`070702`, hexadecimal) headers. */
const readHeader = async (source: ByteSource): Promise<CpioHeader> => {
  const magic = (await source.read(6, "header")).toString("latin1");
  if (magic === "070707") {
    const rest = await source.read(70, "header");
    return {
      format: "odc",
      identity: `${field(rest, 0, 6, 8)}:${field(rest, 6, 6, 8)}`,
      mode: field(rest, 12, 6, 8),
      links: field(rest, 30, 6, 8),
      nameSize: field(rest, 53, 6, 8),
      fileSize: field(rest, 59, 11, 8),
      check: 0,
    };
  }
  if (magic === "070701" || magic === "070702") {
    const rest = await source.read(104, "header");
    return {
      format: magic === "070702" ? "crc" : "newc",
      identity: `${field(rest, 56, 8, 16)}:${field(rest, 64, 8, 16)}:${field(rest, 0, 8, 16)}`,
      mode: field(rest, 8, 8, 16),
      links: field(rest, 32, 8, 16),
      fileSize: field(rest, 48, 8, 16),
      nameSize: field(rest, 88, 8, 16),
      check: field(rest, 96, 8, 16),
    };
  }
  throw new ArtifactReaderFailure(
    "format",
    "cpio member has an unsupported header; only odc and newc archives are expanded",
  );
};

const padding = (format: CpioHeader["format"], length: number): number =>
  format === "odc" ? 0 : (4 - (length % 4)) % 4;

/** Normalize a member name; reject absolute and traversing names. */
const memberPath = (raw: string): string | undefined => {
  const segments = raw
    .split("/")
    .filter((segment) => segment !== "" && segment !== ".");
  if (raw.startsWith("/") || segments.includes(".."))
    throw new ArtifactReaderFailure(
      "path",
      `cpio member escapes its archive: ${raw}`,
    );
  return segments.length === 0 ? undefined : segments.join("/");
};

/** Project one cpio member as an archive-neutral entry. */
const entryOf = (member: {
  readonly path: string;
  readonly kind: ArtifactEntry["kind"];
  readonly key: string;
  readonly header: CpioHeader;
  readonly limitations: readonly string[];
  readonly size?: number | null;
  readonly contentUnavailable?: boolean;
}): ArtifactEntry => ({
  path: member.path,
  kind: member.kind,
  declaredSize:
    member.size !== undefined
      ? member.size
      : member.kind === "file"
        ? member.header.fileSize
        : null,
  compressedSize: null,
  executable: (member.header.mode & 0o111) !== 0,
  encrypted: false,
  byteOffset: null,
  declaredSha256: null,
  unpacked: false,
  limitations: member.limitations,
  adapterKey: member.key,
  ...(member.contentUnavailable === true ? { contentUnavailable: true } : {}),
});

interface PendingLink {
  readonly path: string;
  readonly key: string;
  readonly header: CpioHeader;
}

const drain = async (chunks: AsyncIterable<Buffer>): Promise<void> => {
  for await (const chunk of chunks) void chunk;
};

/** Human-readable limitation for a collected (or skipped) symlink target. */
const symlinkTargetLimitation = (
  header: CpioHeader,
  target: Buffer | undefined,
): string => {
  if (target === undefined)
    return `Symlink target of ${header.fileSize} bytes exceeds ${MAX_SYMLINK_TARGET_BYTES} bytes and was not read.`;
  try {
    return `Symlink target: ${new TextDecoder("utf-8", { fatal: true }).decode(target)}`;
  } catch {
    return "Symlink target is not valid UTF-8 and was not decoded; the archived bytes are preserved only as a byte count.";
  }
};

/**
 * Sequential reader for a gzip-compressed cpio archive, such as an installer
 * package's Scripts or Payload. Members are decompressed once, in order: open
 * an entry before advancing to the next one. `070702` data is checked against
 * its CRC. Hard links whose bytes are stored on another member are served
 * from that member's bytes; device nodes, FIFOs, and sockets are skipped.
 */
export class CpioArtifactReader implements ArtifactReader {
  readonly format = "file" as const;
  #source: ByteSource | undefined;
  #current:
    | {
        readonly key: string;
        readonly path: string;
        readonly header: CpioHeader;
      }
    | undefined;
  #consumed = false;
  readonly #links = new Map<string, Buffer>();
  readonly #pending = new Map<string, PendingLink[]>();
  readonly #aliases = new Map<string, Buffer>();
  #buffered = 0;

  constructor(
    private readonly openCompressed: (
      signal?: AbortSignal,
    ) => Promise<Readable>,
    /**
     * Integrity mode for iteration-time CRC failures. Streamed data CRCs are
     * always checked; under record-and-continue a zero-size hard-link header
     * whose CRC disagrees is yielded as an unavailable occurrence so later
     * siblings are still inventoried, instead of aborting the archive.
     */
    private readonly integrity: "fail" | "record-and-continue" = "fail",
  ) {}

  async *entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry> {
    const compressed = await this.openCompressed(signal);
    const gunzip = createGunzip();
    // `pipe()` does not forward source errors (cancellation, truncation);
    // propagate them so the MCP process fails as a tagged Artifact failure.
    compressed.on("error", (cause: unknown) => {
      gunzip.destroy(
        cause instanceof ArtifactReaderFailure
          ? cause
          : new ArtifactReaderFailure("format", "cpio stream failed", {
              cause,
            }),
      );
    });
    gunzip.on("error", () => {
      // Prevent unhandled source errors after the decoder fails first.
      compressed.destroy();
    });
    const budget = new DecodedBudget();
    gunzip.on("error", (cause: unknown) => {
      budget.destroy(
        cause instanceof ArtifactReaderFailure
          ? cause
          : new ArtifactReaderFailure("format", "cpio stream failed", {
              cause,
            }),
      );
    });
    budget.on("error", () => {
      compressed.destroy();
    });
    const source = new ByteSource(compressed.pipe(gunzip).pipe(budget));
    this.#source = source;
    for (let index = 0; ; index++) {
      if (signal?.aborted === true)
        throw new ArtifactReaderFailure(
          "cancelled",
          "cpio expansion was cancelled",
        );
      yield* this.#finishCurrent(source);
      const header = await readHeader(source);
      if (header.nameSize < 1 || header.nameSize > MAX_NAME_BYTES)
        throw new ArtifactReaderFailure(
          "format",
          "cpio member name size is invalid",
        );
      const nameBytes = await source.read(header.nameSize, "member name");
      await drain(
        source.take(
          padding(header.format, 110 + header.nameSize),
          "name padding",
        ),
      );
      // cpio names require exactly one terminal NUL: a missing terminator or
      // an embedded NUL with trailing bytes is malformed. Decode without
      // replacement so distinct byte names cannot collapse to one path.
      if (
        nameBytes.length === 0 ||
        nameBytes[nameBytes.length - 1] !== 0 ||
        nameBytes.indexOf(0) !== nameBytes.length - 1
      )
        throw new ArtifactReaderFailure(
          "format",
          "cpio member name is not NUL-terminated",
        );
      let raw: string;
      try {
        raw = new TextDecoder("utf-8", { fatal: true }).decode(
          nameBytes.subarray(0, nameBytes.length - 1),
        );
      } catch {
        throw new ArtifactReaderFailure(
          "format",
          "cpio member name is not valid UTF-8",
        );
      }
      if (raw === TRAILER) {
        yield* this.#unresolvedLinks();
        return;
      }
      yield* this.#member(source, header, raw, `${index}:${raw}`);
    }
  }

  async *#member(
    source: ByteSource,
    header: CpioHeader,
    raw: string,
    key: string,
  ): AsyncGenerator<ArtifactEntry> {
    const type = header.mode & S_IFMT;
    const path = memberPath(raw);
    if (type === S_IFLNK) {
      yield* this.#symlink(source, { header, raw, key }, path);
      return;
    }
    if (
      path !== undefined &&
      type === S_IFREG &&
      header.links > 1 &&
      header.fileSize === 0
    ) {
      // Zero-size headers carry no bytes, so a CRC archive must declare zero.
      // Under record-and-continue this is the occurrence's own forgotten
      // bytes: yield it unavailable so later siblings still inventory.
      if (header.format === "crc" && header.check !== 0) {
        if (this.integrity !== "record-and-continue")
          throw new ArtifactReaderFailure(
            "integrity",
            `cpio CRC disagrees with content: ${raw}`,
          );
        yield entryOf({
          path,
          kind: "file",
          key,
          header,
          size: null,
          limitations: [`cpio CRC disagrees with content: ${raw}`],
          contentUnavailable: true,
        });
        return;
      }
      const stored = this.#links.get(header.identity);
      if (stored !== undefined) {
        yield this.#alias(path, key, header, stored);
        return;
      }
      // newc stores a hard link's bytes on its last member; wait for them.
      // An all-empty group is resolved to empty files at TRAILER!!!.
      const waiting = this.#pending.get(header.identity) ?? [];
      waiting.push({ path, key, header });
      this.#pending.set(header.identity, waiting);
      return;
    }
    this.#current = { key, path: raw, header };
    this.#consumed = false;
    if (path === undefined) return;
    if (type !== S_IFREG && type !== S_IFDIR) {
      // FIFOs, device nodes, sockets and other types are not expanded; keep
      // an explicit unavailable occurrence instead of dropping the path.
      yield entryOf({
        path,
        kind: "file",
        key,
        header,
        size: null,
        limitations: [
          `Unsupported cpio member type ${type.toString(8)}; content not expanded.`,
        ],
        contentUnavailable: true,
      });
      // Consume its data (if any) so the next header aligns.
      await drain(this.#verified(source, header, raw));
      this.#current = undefined;
      return;
    }
    yield entryOf({
      path,
      kind: type === S_IFDIR ? "directory" : "file",
      key,
      header,
      limitations: [],
    });
  }

  /**
   * One symlink member. A hostile header can declare a multi-gigabyte target,
   * so oversized targets stream past. CRC failures surface before the entry
   * is yielded, outside the scanner's per-entry recovery: under
   * record-and-continue the symlink becomes an unavailable occurrence so
   * later siblings still inventory.
   */
  async *#symlink(
    source: ByteSource,
    member: {
      readonly header: CpioHeader;
      readonly raw: string;
      readonly key: string;
    },
    path: string | undefined,
  ): AsyncGenerator<ArtifactEntry> {
    const { header, raw, key } = member;
    let target: Buffer | undefined;
    let crcLimitation: string | undefined;
    try {
      if (header.fileSize > MAX_SYMLINK_TARGET_BYTES)
        await drain(this.#verified(source, header, raw));
      else target = await this.#collect(source, header, raw);
    } catch (cause: unknown) {
      if (
        this.integrity !== "record-and-continue" ||
        !(cause instanceof ArtifactReaderFailure) ||
        cause.reason !== "integrity"
      )
        throw cause;
      crcLimitation = cause.message;
    }
    if (path === undefined) return;
    if (crcLimitation !== undefined) {
      yield entryOf({
        path,
        kind: "symlink",
        key,
        header,
        limitations: [crcLimitation],
        contentUnavailable: true,
      });
      return;
    }
    yield entryOf({
      path,
      kind: "symlink",
      key,
      header,
      limitations: [symlinkTargetLimitation(header, target)],
    });
  }

  #alias(
    path: string,
    key: string,
    header: CpioHeader,
    bytes: Buffer,
  ): ArtifactEntry {
    this.#aliases.set(key, bytes);
    return entryOf({
      path,
      kind: "file",
      key,
      header,
      size: bytes.length,
      limitations: [
        "Hard link: bytes are stored with another member of this archive.",
      ],
    });
  }

  *#unresolvedLinks(): Generator<ArtifactEntry> {
    for (const links of this.#pending.values())
      for (const { path, key, header } of links) {
        // A complete zero-length group establishes empty content. An orphan
        // that claims more links than appear is missing its bytes.
        const complete =
          links.length >= header.links &&
          links.every((m) => m.header.fileSize === 0);
        if (header.fileSize === 0 && complete) {
          const empty = Buffer.alloc(0);
          this.#aliases.set(key, empty);
          yield entryOf({
            path,
            kind: "file",
            key,
            header,
            size: 0,
            limitations: [
              "Hard link: every member of this link group is empty.",
            ],
          });
          continue;
        }
        yield entryOf({
          path,
          kind: "file",
          key,
          header,
          size: null,
          limitations: [UNRESOLVED_LINK],
          contentUnavailable: true,
        });
      }
    this.#pending.clear();
  }

  /** Finish the current member, then serve hard links that were waiting for it. */
  async *#finishCurrent(source: ByteSource): AsyncGenerator<ArtifactEntry> {
    const current = this.#current;
    if (current === undefined) return;
    this.#current = undefined;
    if (!this.#consumed) {
      if (this.#shouldKeep(current.header))
        this.#remember(
          current.header,
          await this.#collect(source, current.header, current.path),
        );
      else await drain(this.#verified(source, current.header, current.path));
    }
    const waiting = this.#pending.get(current.header.identity);
    const stored = this.#links.get(current.header.identity);
    if (waiting === undefined || stored === undefined) return;
    this.#pending.delete(current.header.identity);
    for (const { path, key, header } of waiting)
      yield this.#alias(path, key, header, stored);
  }

  #shouldKeep(header: CpioHeader): boolean {
    return (
      (header.mode & S_IFMT) === S_IFREG &&
      header.links > 1 &&
      header.fileSize > 0 &&
      header.fileSize <= MAX_LINK_BUFFER_BYTES &&
      this.#buffered + header.fileSize <= MAX_LINK_BUFFER_TOTAL
    );
  }

  #remember(header: CpioHeader, bytes: Buffer): void {
    if (this.#links.has(header.identity)) return;
    this.#links.set(header.identity, bytes);
    this.#buffered += bytes.length;
  }

  /** Member data and its padding, checked against a `070702` CRC. */
  async *#verified(
    source: ByteSource,
    header: CpioHeader,
    path: string,
  ): AsyncGenerator<Buffer> {
    let sum = 0;
    for await (const chunk of source.take(header.fileSize, "member data")) {
      if (header.format === "crc")
        for (const byte of chunk) sum = (sum + byte) >>> 0;
      yield chunk;
    }
    // Consume padding before reporting a mismatch: under record-and-continue
    // iteration resumes after this error, and leftover padding would be read
    // as the next header's magic.
    await drain(
      source.take(padding(header.format, header.fileSize), "data padding"),
    );
    if (header.format === "crc" && sum !== header.check)
      throw new ArtifactReaderFailure(
        "integrity",
        `cpio CRC disagrees with content: ${path}`,
      );
  }

  async #collect(
    source: ByteSource,
    header: CpioHeader,
    path: string,
  ): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of this.#verified(source, header, path))
      chunks.push(chunk);
    return Buffer.concat(chunks);
  }

  open(entry: ArtifactEntry): Promise<Readable> {
    const alias = this.#aliases.get(entry.adapterKey);
    if (alias !== undefined) return Promise.resolve(Readable.from([alias]));
    const source = this.#source;
    const current = this.#current;
    if (
      source === undefined ||
      current === undefined ||
      current.key !== entry.adapterKey ||
      this.#consumed
    )
      return Promise.reject(
        new ArtifactReaderFailure(
          "unavailable",
          entry.contentUnavailable === true
            ? UNRESOLVED_LINK
            : "cpio members can be read only once, in archive order",
        ),
      );
    this.#consumed = true;
    const chunks = this.#verified(source, current.header, current.path);
    if (!this.#shouldKeep(current.header))
      return Promise.resolve(Readable.from(chunks));
    // Keep a linked member's bytes for paths that share them.
    const kept: Buffer[] = [];
    const remember = (): void => {
      this.#remember(current.header, Buffer.concat(kept));
    };
    return Promise.resolve(
      Readable.from(
        (async function* () {
          for await (const chunk of chunks) {
            kept.push(chunk);
            yield chunk;
          }
          remember();
        })(),
      ),
    );
  }

  provenance(): readonly ArtifactCommand[] {
    return [];
  }

  async close(): Promise<void> {
    await this.#source?.close();
    this.#source = undefined;
  }
}
