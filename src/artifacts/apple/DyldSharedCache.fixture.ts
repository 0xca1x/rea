/** Synthetic dyld shared caches laid out field by field for tests. */

export interface CacheFixtureImage {
  readonly path: string;
  readonly bytes: Uint8Array;
  /** Place the image in the `.01` subcache instead of the main file. */
  readonly inSubcache?: boolean;
}

export interface CacheFixture {
  readonly main: Uint8Array;
  readonly subcaches: readonly {
    readonly suffix: string;
    readonly bytes: Uint8Array;
  }[];
}

const MAIN_BASE = 0x180000000n;
const SUB_BASE = 0x190000000n;
const MODERN_HEADER = 0x228;
const LEGACY_HEADER = 0x98;

const uuid = (seed: number): Buffer =>
  Buffer.from(
    Array.from({ length: 16 }, (_, index) => (seed * 31 + index) & 0xff),
  );

const align = (value: number): number => Math.ceil(value / 0x1000) * 0x1000;

const writeHeader = (
  buffer: Buffer,
  options: {
    readonly headerSize: number;
    readonly uuidSeed: number;
    readonly architecture: string;
  },
): void => {
  buffer.write(`dyld_v1  ${options.architecture}`.padEnd(15, " "), 0, "latin1");
  buffer.writeUInt32LE(options.headerSize, 0x10);
  buffer.writeUInt32LE(1, 0x14);
  uuid(options.uuidSeed).copy(buffer, 0x58);
};

const writeMapping = (
  buffer: Buffer,
  at: number,
  address: bigint,
  size: number,
): void => {
  buffer.writeBigUInt64LE(address, at);
  buffer.writeBigUInt64LE(BigInt(size), at + 8);
  buffer.writeBigUInt64LE(0n, at + 16);
  buffer.writeUInt32LE(5, at + 24);
  buffer.writeUInt32LE(5, at + 28);
};

/** Build a main cache (modern or legacy header) plus an optional `.01` subcache. */
export const dyldCacheFixture = (
  images: readonly CacheFixtureImage[],
  options: {
    readonly legacy?: boolean;
    readonly architecture?: string;
    readonly subcacheUuidSeed?: number;
  } = {},
): CacheFixture => {
  const architecture = options.architecture ?? "arm64e";
  const legacy = options.legacy === true;
  const headerSize = legacy ? LEGACY_HEADER : MODERN_HEADER;
  const sub = images.filter(({ inSubcache }) => inSubcache === true);
  const main = images.filter(({ inSubcache }) => inSubcache !== true);
  const mappingTable = headerSize;
  const imageTable = mappingTable + 32;
  const subTable = imageTable + images.length * 32;
  const pathsAt = subTable + (sub.length > 0 && !legacy ? 56 : 0);
  const paths = images.map(({ path }) => Buffer.from(`${path}\0`));
  let cursor = align(
    pathsAt + paths.reduce((total, path) => total + path.length, 0),
  );
  const mainOffsets = main.map((image) => {
    const offset = cursor;
    cursor = align(cursor + image.bytes.length);
    return offset;
  });
  const mainFile = Buffer.alloc(cursor);
  writeHeader(mainFile, { headerSize, uuidSeed: 1, architecture });
  writeMapping(mainFile, mappingTable, MAIN_BASE, mainFile.length);
  if (legacy) {
    mainFile.writeUInt32LE(imageTable, 0x18);
    mainFile.writeUInt32LE(images.length, 0x1c);
  } else {
    mainFile.writeUInt32LE(1, 0xd8);
    mainFile.writeBigUInt64LE(MAIN_BASE, 0xe0);
    mainFile.writeBigUInt64LE(0x20000000n, 0xe8);
    mainFile.writeBigUInt64LE(0x10000000n, 0xf0);
    mainFile.writeUInt32LE(0x001a0600, 0x16c);
    mainFile.writeUInt32LE(imageTable, 0x1c0);
    mainFile.writeUInt32LE(images.length, 0x1c4);
  }
  let pathCursor = pathsAt;
  let subCursor = MODERN_HEADER + 32;
  const subOffsets = new Map<string, number>();
  for (const image of sub) {
    subCursor = align(subCursor);
    subOffsets.set(image.path, subCursor);
    subCursor += image.bytes.length;
  }
  images.forEach((image, index) => {
    const row = imageTable + index * 32;
    const mainIndex = main.indexOf(image);
    const address =
      mainIndex >= 0
        ? MAIN_BASE + BigInt(mainOffsets[mainIndex] ?? 0)
        : SUB_BASE + BigInt(subOffsets.get(image.path) ?? 0);
    mainFile.writeBigUInt64LE(address, row);
    mainFile.writeUInt32LE(pathCursor, row + 24);
    const path = paths[index] ?? Buffer.alloc(1);
    path.copy(mainFile, pathCursor);
    pathCursor += path.length;
    if (mainIndex >= 0)
      Buffer.from(image.bytes).copy(mainFile, mainOffsets[mainIndex] ?? 0);
  });
  if (sub.length === 0 || legacy) return { main: mainFile, subcaches: [] };
  mainFile.writeUInt32LE(subTable, 0x188);
  mainFile.writeUInt32LE(1, 0x18c);
  uuid(2).copy(mainFile, subTable);
  mainFile.writeBigUInt64LE(SUB_BASE - MAIN_BASE, subTable + 16);
  mainFile.write(".01", subTable + 24, "latin1");
  const subFile = Buffer.alloc(align(subCursor));
  writeHeader(subFile, {
    headerSize: MODERN_HEADER,
    uuidSeed: options.subcacheUuidSeed ?? 2,
    architecture,
  });
  writeMapping(subFile, MODERN_HEADER, SUB_BASE, subFile.length);
  for (const image of sub)
    Buffer.from(image.bytes).copy(subFile, subOffsets.get(image.path) ?? 0);
  return { main: mainFile, subcaches: [{ suffix: ".01", bytes: subFile }] };
};
