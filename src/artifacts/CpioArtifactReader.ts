import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";

import type { ArtifactCommand } from "../domain/artifactGraph.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
  type ArtifactReader,
} from "./ArtifactReader.js";

/** Longest member name accepted, including its terminating NUL. */
const MAX_NAME_BYTES = 64 * 1024;
const TRAILER = "TRAILER!!!";
const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;
const S_IFLNK = 0o120000;

/** Pull exactly the requested bytes from a stream, holding at most one chunk. */
class ByteSource {
  readonly #iterator: AsyncIterator<Buffer>;
  #buffer: Buffer = Buffer.alloc(0);

  constructor(stream: Readable) {
    this.#iterator = stream[Symbol.asyncIterator]();
  }

  async #fill(): Promise<boolean> {
    const next = await this.#iterator.next();
    if (next.done === true) return false;
    const chunk: unknown = next.value;
    if (!Buffer.isBuffer(chunk))
      throw new ArtifactReaderFailure(
        "format",
        "cpio stream yielded non-binary data",
      );
    this.#buffer =
      this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
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

  async skip(length: number, label: string): Promise<void> {
    for await (const chunk of this.take(length, label)) void chunk;
  }

  async close(): Promise<void> {
    await this.#iterator.return?.();
  }
}

interface CpioHeader {
  readonly format: "odc" | "newc";
  readonly mode: number;
  readonly fileSize: number;
  readonly nameSize: number;
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
      mode: field(rest, 12, 6, 8),
      nameSize: field(rest, 53, 6, 8),
      fileSize: field(rest, 59, 11, 8),
    };
  }
  if (magic === "070701" || magic === "070702") {
    const rest = await source.read(104, "header");
    return {
      format: "newc",
      mode: field(rest, 8, 8, 16),
      fileSize: field(rest, 48, 8, 16),
      nameSize: field(rest, 88, 8, 16),
    };
  }
  throw new ArtifactReaderFailure(
    "format",
    "cpio member has an unsupported header; only odc and newc archives are expanded",
  );
};

const padding = (format: CpioHeader["format"], length: number): number =>
  format === "newc" ? (4 - (length % 4)) % 4 : 0;

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

/** Project one cpio header as an archive-neutral entry. */
const entryOf = (member: {
  readonly path: string;
  readonly kind: ArtifactEntry["kind"];
  readonly key: string;
  readonly header: CpioHeader;
  readonly limitations: readonly string[];
}): ArtifactEntry => ({
  path: member.path,
  kind: member.kind,
  declaredSize: member.kind === "file" ? member.header.fileSize : null,
  compressedSize: null,
  executable: (member.header.mode & 0o111) !== 0,
  encrypted: false,
  byteOffset: null,
  declaredSha256: null,
  unpacked: false,
  limitations: member.limitations,
  adapterKey: member.key,
});

/**
 * Sequential reader for a gzip-compressed cpio archive, such as an installer
 * package's Scripts or Payload. Members are decompressed once, in order: open
 * an entry before advancing to the next one. Device nodes, FIFOs, and sockets
 * are skipped; hard links appear as separate entries.
 */
export class CpioArtifactReader implements ArtifactReader {
  readonly format = "file" as const;
  #source: ByteSource | undefined;
  #current:
    | {
        readonly key: string;
        readonly size: number;
        readonly header: CpioHeader;
      }
    | undefined;
  #consumed = false;

  constructor(
    private readonly openCompressed: (
      signal?: AbortSignal,
    ) => Promise<Readable>,
  ) {}

  async *entries(signal?: AbortSignal): AsyncIterable<ArtifactEntry> {
    const source = new ByteSource(
      (await this.openCompressed(signal)).pipe(createGunzip()),
    );
    this.#source = source;
    for (let index = 0; ; index++) {
      signal?.throwIfAborted();
      await this.#finishCurrent(source);
      const header = await readHeader(source);
      if (header.nameSize < 1 || header.nameSize > MAX_NAME_BYTES)
        throw new ArtifactReaderFailure(
          "format",
          "cpio member name size is invalid",
        );
      const nameBytes = await source.read(header.nameSize, "member name");
      await source.skip(
        padding(header.format, 110 + header.nameSize),
        "name padding",
      );
      const raw = nameBytes.toString(
        "utf8",
        0,
        nameBytes.indexOf(0) >= 0 ? nameBytes.indexOf(0) : nameBytes.length,
      );
      if (raw === TRAILER) return;
      const type = header.mode & S_IFMT;
      const path = memberPath(raw);
      const key = `${index}:${raw}`;
      if (type === S_IFLNK) {
        const target = (
          await source.read(header.fileSize, "symlink target")
        ).toString("utf8");
        await source.skip(
          padding(header.format, header.fileSize),
          "data padding",
        );
        if (path !== undefined)
          yield entryOf({
            path,
            kind: "symlink",
            key,
            header,
            limitations: [`Symlink target: ${target}`],
          });
        continue;
      }
      this.#current = { key, size: header.fileSize, header };
      this.#consumed = false;
      if (path === undefined || (type !== S_IFREG && type !== S_IFDIR))
        continue;
      yield entryOf({
        path,
        kind: type === S_IFDIR ? "directory" : "file",
        key,
        header,
        limitations: [],
      });
    }
  }

  /** Skip whatever the caller did not read of the current member. */
  async #finishCurrent(source: ByteSource): Promise<void> {
    const current = this.#current;
    if (current === undefined) return;
    this.#current = undefined;
    if (!this.#consumed) await source.skip(current.size, "member data");
    await source.skip(
      padding(current.header.format, current.size),
      "data padding",
    );
  }

  open(entry: ArtifactEntry): Promise<Readable> {
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
          "cpio members can be read only once, in archive order",
        ),
      );
    this.#consumed = true;
    return Promise.resolve(
      Readable.from(source.take(current.size, "member data")),
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
