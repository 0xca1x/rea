import { open, type FileHandle } from "node:fs/promises";

import type { MachoImageFacts } from "../domain/dylibResolution.js";
import type {
  DyldCacheMapping,
  DyldCacheSubcache,
  DyldSharedCacheHeader,
} from "../domain/dyldSharedCache.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import { readMachoImage } from "./MachoLoadCommandReader.js";

const MAGIC_PREFIX = "dyld_v1";
/** Header fields are valid only below `mappingOffset`; real headers are under 1 KiB. */
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_IMAGES = 200_000;
const MAX_MAPPINGS = 64;
const MAX_SUBCACHES = 256;
const MAX_PATH_BYTES = 4096;
const BLOCK_BYTES = 64 * 1024;

/** Byte offsets of `dyld_cache_header` fields in Apple's open-source dyld. */
const FIELD = {
  mappingOffset: 0x10,
  mappingCount: 0x14,
  imagesOffsetOld: 0x18,
  imagesCountOld: 0x1c,
  uuid: 0x58,
  cacheType: 0x68,
  platform: 0xd8,
  formatBits: 0xdc,
  sharedRegionStart: 0xe0,
  sharedRegionSize: 0xe8,
  maxSlide: 0xf0,
  osVersion: 0x16c,
  altPlatform: 0x170,
  altOsVersion: 0x174,
  subCacheArrayOffset: 0x188,
  subCacheArrayCount: 0x18c,
  symbolFileUuid: 0x190,
  imagesOffset: 0x1c0,
  imagesCount: 0x1c4,
  cacheSubType: 0x1c8,
} as const;

const hex = (value: bigint | number): string => `0x${value.toString(16)}`;

const uuidText = (bytes: Buffer): string => {
  const text = bytes.toString("hex").toUpperCase();
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
};

const safeNumber = (value: bigint, label: string): number => {
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new ArtifactReaderFailure(
      "format",
      `dyld cache ${label} exceeds the safe range`,
    );
  return Number(value);
};

/** Block-cached positional reads over one cache file. */
class CacheFile {
  readonly #blocks = new Map<number, Buffer>();

  private constructor(
    readonly suffix: string,
    readonly handle: FileHandle,
    readonly size: number,
  ) {}

  static async open(path: string, suffix: string): Promise<CacheFile> {
    const handle = await open(path, "r");
    try {
      return new CacheFile(suffix, handle, (await handle.stat()).size);
    } catch (cause: unknown) {
      await handle.close();
      throw cause;
    }
  }

  async read(offset: number, length: number): Promise<Buffer> {
    if (offset < 0 || offset + length > this.size)
      throw new ArtifactReaderFailure(
        "format",
        `dyld cache read at ${hex(offset)} extends beyond ${this.suffix === "" ? "the main file" : `subcache ${this.suffix}`}`,
      );
    if (length > BLOCK_BYTES) {
      const bytes = Buffer.alloc(length);
      await this.handle.read(bytes, 0, length, offset);
      return bytes;
    }
    const chunks: Buffer[] = [];
    for (let position = offset; position < offset + length;) {
      const index = Math.floor(position / BLOCK_BYTES);
      let block = this.#blocks.get(index);
      if (block === undefined) {
        const start = index * BLOCK_BYTES;
        block = Buffer.alloc(Math.min(BLOCK_BYTES, this.size - start));
        await this.handle.read(block, 0, block.length, start);
        this.#blocks.set(index, block);
      }
      const from = position - index * BLOCK_BYTES;
      const take = Math.min(block.length - from, offset + length - position);
      chunks.push(block.subarray(from, from + take));
      position += take;
    }
    return chunks.length === 1
      ? (chunks[0] ?? Buffer.alloc(0))
      : Buffer.concat(chunks);
  }

  async cString(offset: number): Promise<string> {
    const bytes = await this.read(
      offset,
      Math.min(MAX_PATH_BYTES, this.size - offset),
    );
    const end = bytes.indexOf(0);
    if (end < 0)
      throw new ArtifactReaderFailure(
        "format",
        `dyld cache string at ${hex(offset)} is unterminated`,
      );
    return bytes.toString("utf8", 0, end);
  }
}

interface ParsedHeader {
  readonly magic: string;
  readonly uuid: string;
  readonly mappings: readonly {
    readonly address: bigint;
    readonly size: bigint;
    readonly fileOffset: bigint;
    readonly maxProt: number;
    readonly initProt: number;
  }[];
  readonly header: Buffer;
  readonly length: number;
}

const has = (parsed: ParsedHeader, offset: number, width: number): boolean =>
  parsed.length >= offset + width;

const readHeader = async (file: CacheFile): Promise<ParsedHeader> => {
  if (file.size < 0x20)
    throw new ArtifactReaderFailure(
      "format",
      "File is too short to be a dyld shared cache",
    );
  const prefix = await file.read(0, 0x20);
  const magic = prefix.toString("latin1", 0, 16).replace(/\0+$/u, "");
  if (!magic.startsWith(MAGIC_PREFIX))
    throw new ArtifactReaderFailure(
      "format",
      "File is not a dyld shared cache",
    );
  const mappingOffset = prefix.readUInt32LE(FIELD.mappingOffset);
  const mappingCount = prefix.readUInt32LE(FIELD.mappingCount);
  if (
    mappingOffset < 0x20 ||
    mappingOffset > MAX_HEADER_BYTES ||
    mappingCount > MAX_MAPPINGS
  )
    throw new ArtifactReaderFailure(
      "format",
      "dyld cache header has an invalid mapping table",
    );
  const header = await file.read(0, mappingOffset);
  const table = await file.read(mappingOffset, mappingCount * 32);
  const mappings = Array.from({ length: mappingCount }, (_, index) => ({
    address: table.readBigUInt64LE(index * 32),
    size: table.readBigUInt64LE(index * 32 + 8),
    fileOffset: table.readBigUInt64LE(index * 32 + 16),
    maxProt: table.readUInt32LE(index * 32 + 24),
    initProt: table.readUInt32LE(index * 32 + 28),
  }));
  const parsed = { magic, uuid: "", mappings, header, length: mappingOffset };
  return {
    ...parsed,
    uuid: has(parsed, FIELD.uuid, 16)
      ? uuidText(header.subarray(FIELD.uuid, FIELD.uuid + 16))
      : "",
  };
};

const PLATFORMS: Readonly<Record<number, string>> = {
  1: "macos",
  2: "ios",
  3: "tvos",
  4: "watchos",
  5: "bridgeos",
  6: "maccatalyst",
  7: "ios-simulator",
  8: "tvos-simulator",
  9: "watchos-simulator",
  10: "driverkit",
  11: "visionos",
  12: "visionos-simulator",
};

const version = (value: number): string | null =>
  value === 0
    ? null
    : `${value >>> 16}.${(value >>> 8) & 0xff}.${value & 0xff}`;

/** A main dyld shared cache file and the subcaches it names. */
export class DyldSharedCache {
  readonly #byPath: ReadonlyMap<
    string,
    { readonly path: string; readonly address: number }
  >;

  private constructor(
    readonly header: DyldSharedCacheHeader,
    readonly images: readonly {
      readonly path: string;
      readonly address: number;
    }[],
    private readonly files: readonly CacheFile[],
    private readonly regions: readonly {
      readonly file: CacheFile;
      readonly address: number;
      readonly size: number;
      readonly fileOffset: number;
    }[],
  ) {
    this.#byPath = new Map(images.map((image) => [image.path, image]));
  }

  /** Open the main cache file and every subcache beside it. */
  static async open(
    path: string,
    signal?: AbortSignal,
  ): Promise<DyldSharedCache> {
    const main = await CacheFile.open(path, "");
    const files = [main];
    try {
      const parsed = await readHeader(main);
      const subcaches = await DyldSharedCache.#subcacheEntries(main, parsed);
      const statuses: DyldCacheSubcache[] = [];
      const parsedFiles = [{ file: main, parsed }];
      for (const entry of subcaches) {
        signal?.throwIfAborted();
        let file: CacheFile;
        try {
          file = await CacheFile.open(`${path}${entry.suffix}`, entry.suffix);
        } catch (cause: unknown) {
          if (
            cause instanceof Error &&
            "code" in cause &&
            cause.code === "ENOENT"
          ) {
            statuses.push({ ...entry, status: "missing", observed_uuid: null });
            continue;
          }
          throw cause;
        }
        files.push(file);
        const subParsed = await readHeader(file);
        const matches = subParsed.uuid === entry.uuid;
        statuses.push({
          ...entry,
          status: matches ? "present" : "uuid-mismatch",
          observed_uuid: subParsed.uuid,
        });
        if (matches) parsedFiles.push({ file, parsed: subParsed });
      }
      const header = DyldSharedCache.#summary(parsed, parsedFiles, statuses);
      const images = await DyldSharedCache.#images(main, parsed, signal);
      const regions = parsedFiles.flatMap(({ file, parsed: item }) =>
        item.mappings.map((mapping) => ({
          file,
          address: safeNumber(mapping.address, "mapping address"),
          size: safeNumber(mapping.size, "mapping size"),
          fileOffset: safeNumber(mapping.fileOffset, "mapping file offset"),
        })),
      );
      return new DyldSharedCache(header, images, files, regions);
    } catch (cause: unknown) {
      await Promise.allSettled(files.map(({ handle }) => handle.close()));
      throw cause;
    }
  }

  static async #subcacheEntries(
    main: CacheFile,
    parsed: ParsedHeader,
  ): Promise<
    {
      readonly suffix: string;
      readonly uuid: string;
      readonly vm_offset: string;
    }[]
  > {
    if (!has(parsed, FIELD.subCacheArrayCount, 4)) return [];
    const offset = parsed.header.readUInt32LE(FIELD.subCacheArrayOffset);
    const count = parsed.header.readUInt32LE(FIELD.subCacheArrayCount);
    if (count === 0) return [];
    if (count > MAX_SUBCACHES)
      throw new ArtifactReaderFailure(
        "format",
        "dyld cache lists too many subcaches",
      );
    // Headers that include cacheSubType use entries with an explicit file suffix.
    const named = has(parsed, FIELD.cacheSubType, 4);
    const size = named ? 56 : 24;
    const table = await main.read(offset, count * size);
    return Array.from({ length: count }, (_, index) => {
      const base = index * size;
      const suffix = named
        ? table.toString("latin1", base + 24, base + 56).replace(/\0.*$/su, "")
        : `.${index + 1}`;
      if (!/^\.[A-Za-z0-9.]+$/u.test(suffix))
        throw new ArtifactReaderFailure(
          "format",
          "dyld subcache has an unsafe file suffix",
        );
      return {
        suffix,
        uuid: uuidText(table.subarray(base, base + 16)),
        vm_offset: hex(table.readBigUInt64LE(base + 16)),
      };
    });
  }

  static #summary(
    parsed: ParsedHeader,
    files: readonly {
      readonly file: CacheFile;
      readonly parsed: ParsedHeader;
    }[],
    subcaches: readonly DyldCacheSubcache[],
  ): DyldSharedCacheHeader {
    const header = parsed.header;
    const u32 = (offset: number): number | null =>
      has(parsed, offset, 4) ? header.readUInt32LE(offset) : null;
    const u64 = (offset: number): string | null =>
      has(parsed, offset, 8) ? hex(header.readBigUInt64LE(offset)) : null;
    const platform = u32(FIELD.platform);
    const altPlatform = u32(FIELD.altPlatform);
    const cacheType = has(parsed, FIELD.cacheType, 8)
      ? Number(header.readBigUInt64LE(FIELD.cacheType))
      : null;
    const symbols = has(parsed, FIELD.symbolFileUuid, 16)
      ? header.subarray(FIELD.symbolFileUuid, FIELD.symbolFileUuid + 16)
      : undefined;
    const mappings: DyldCacheMapping[] = files.flatMap(
      ({ file, parsed: item }) =>
        item.mappings.map((mapping) => ({
          file: file.suffix,
          address: hex(mapping.address),
          size: hex(mapping.size),
          file_offset: hex(mapping.fileOffset),
          max_protection: mapping.maxProt,
          initial_protection: mapping.initProt,
        })),
    );
    return {
      magic: parsed.magic,
      architecture: parsed.magic.slice(MAGIC_PREFIX.length).trim(),
      uuid: parsed.uuid,
      platform:
        platform === null
          ? null
          : { id: platform, name: PLATFORMS[platform] ?? null },
      os_version: version(u32(FIELD.osVersion) ?? 0),
      alt_platform:
        altPlatform === null || altPlatform === 0
          ? null
          : { id: altPlatform, name: PLATFORMS[altPlatform] ?? null },
      alt_os_version: version(u32(FIELD.altOsVersion) ?? 0),
      cache_type:
        cacheType === 0
          ? "development"
          : cacheType === 1
            ? "production"
            : cacheType === 2
              ? "multi-cache"
              : null,
      shared_region:
        u64(FIELD.sharedRegionStart) === null
          ? null
          : {
              start: u64(FIELD.sharedRegionStart) ?? "0x0",
              size: u64(FIELD.sharedRegionSize) ?? "0x0",
            },
      max_slide: u64(FIELD.maxSlide),
      mappings,
      subcaches: [...subcaches],
      symbols_file_uuid:
        symbols === undefined || symbols.every((byte) => byte === 0)
          ? null
          : uuidText(symbols),
    };
  }

  static async #images(
    main: CacheFile,
    parsed: ParsedHeader,
    signal?: AbortSignal,
  ): Promise<{ readonly path: string; readonly address: number }[]> {
    const modern = has(parsed, FIELD.imagesCount, 4);
    const offset = parsed.header.readUInt32LE(
      modern ? FIELD.imagesOffset : FIELD.imagesOffsetOld,
    );
    const count = parsed.header.readUInt32LE(
      modern ? FIELD.imagesCount : FIELD.imagesCountOld,
    );
    if (count > MAX_IMAGES)
      throw new ArtifactReaderFailure(
        "limit",
        `dyld cache lists more than ${MAX_IMAGES} images`,
      );
    const table = await main.read(offset, count * 32);
    const images: { path: string; address: number }[] = [];
    for (let index = 0; index < count; index++) {
      if (index % 512 === 0) signal?.throwIfAborted();
      images.push({
        address: safeNumber(table.readBigUInt64LE(index * 32), "image address"),
        path: await main.cString(table.readUInt32LE(index * 32 + 24)),
      });
    }
    return images;
  }

  /** Locate an image by its exact install path. */
  find(
    path: string,
  ): { readonly path: string; readonly address: number } | undefined {
    return this.#byPath.get(path);
  }

  /** Parse one cached image's load commands through the cache's VM mappings. */
  async imageFacts(
    path: string,
  ): Promise<
    { readonly file: string; readonly facts: MachoImageFacts } | undefined
  > {
    const image = this.find(path);
    if (image === undefined) return undefined;
    const region = this.regions.find(
      ({ address, size }) =>
        image.address >= address && image.address < address + size,
    );
    if (region === undefined) return undefined;
    const base = region.fileOffset + (image.address - region.address);
    const available = region.size - (image.address - region.address);
    const facts = await readMachoImage(
      async (offset, length) =>
        region.file.read(
          base + offset,
          Math.max(0, Math.min(length, available - offset)),
        ),
      available,
    );
    return { file: region.file.suffix, facts };
  }

  async close(): Promise<void> {
    await Promise.allSettled(this.files.map(({ handle }) => handle.close()));
  }
}
