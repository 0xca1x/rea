import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  dyldCacheFixture,
  type CacheFixture,
} from "../../../src/artifacts/DyldSharedCache.fixture.js";
import {
  FILE_TYPE,
  LC,
  dylibCommand,
  dylibUseCommand,
  machoImage,
} from "../../../src/artifacts/MachoImage.fixture.js";
import {
  inspectDyldSharedCache,
  inspectDyldSharedCacheEvidence,
} from "../../../src/application/DyldSharedCacheService.js";
import { dyldSharedCacheResultSchema } from "../../../src/domain/dyldSharedCache.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const dylib = (installName: string, dependencies: readonly Uint8Array[] = []) =>
  machoImage({
    fileType: FILE_TYPE.dylib,
    commands: [dylibCommand(LC.ID_DYLIB, installName), ...dependencies],
  });

const writeCache = async (fixture: CacheFixture): Promise<string> => {
  const directory = await createTestTempDirectory("rea-dyld-cache-");
  const path = join(directory, "dyld_shared_cache_arm64e");
  await writeFile(path, fixture.main);
  for (const { suffix, bytes } of fixture.subcaches)
    await writeFile(`${path}${suffix}`, bytes);
  return path;
};

const IMAGES = [
  {
    path: "/usr/lib/libSystem.B.dylib",
    bytes: dylib("/usr/lib/libSystem.B.dylib", [
      dylibCommand(LC.REEXPORT_DYLIB, "/usr/lib/system/libcache.dylib"),
    ]),
  },
  {
    path: "/usr/lib/swift/libswiftCore.dylib",
    bytes: dylib("/usr/lib/swift/libswiftCore.dylib", [
      dylibUseCommand(LC.LOAD_DYLIB, "/usr/lib/libSystem.B.dylib", 0x4 | 0x8),
    ]),
    inSubcache: true,
  },
];

describe("dyld shared cache inspection", () => {
  it("reads the header, subcaches, image list and cached load commands", async () => {
    const path = await writeCache(dyldCacheFixture(IMAGES));
    const result = await inspectDyldSharedCache({
      cache_path: path,
      images: ["/usr/lib/swift/libswiftCore.dylib", "/usr/lib/missing.dylib"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const cache = dyldSharedCacheResultSchema.parse(result.value);
    expect(cache).toMatchObject({
      architecture: "arm64e",
      platform: { id: 1, name: "macos" },
      os_version: "26.6.0",
      shared_region: { start: "0x180000000", size: "0x20000000" },
      images_total: 2,
      coverage: { status: "complete", unreadable_subcaches: [] },
    });
    expect(cache.subcaches).toEqual([
      expect.objectContaining({
        suffix: ".01",
        status: "present",
        vm_offset: "0x10000000",
      }),
    ]);
    expect(cache.images.map(({ path: image }) => image)).toEqual(
      IMAGES.map(({ path: image }) => image),
    );
    const [swift, missing] = cache.inspected_images;
    expect(swift).toMatchObject({ status: "parsed", file: ".01" });
    expect(swift?.slices[0]?.dependencies).toEqual([
      expect.objectContaining({
        install_name: "/usr/lib/libSystem.B.dylib",
        encoding: "dylib_use_command",
        upward: true,
        delayed_init: true,
      }),
    ]);
    expect(missing).toEqual({
      path: "/usr/lib/missing.dylib",
      status: "absent",
      address: null,
      file: null,
      reason: null,
      slices: [],
    });
  });

  it("reports missing and mismatched subcaches as partial coverage", async () => {
    const mismatched = await writeCache(
      dyldCacheFixture(IMAGES, { subcacheUuidSeed: 9 }),
    );
    const result = await inspectDyldSharedCache({
      cache_path: mismatched,
      images: ["/usr/lib/swift/libswiftCore.dylib"],
    });
    expect(result.ok && result.value).toMatchObject({
      subcaches: [{ suffix: ".01", status: "uuid-mismatch" }],
      inspected_images: [{ status: "unmapped" }],
      coverage: { status: "partial", unreadable_subcaches: [".01"] },
    });
    const missing = await writeCache(dyldCacheFixture(IMAGES));
    await rm(`${missing}.01`);
    const without = await inspectDyldSharedCache({ cache_path: missing });
    expect(without.ok && without.value.subcaches[0]).toMatchObject({
      status: "missing",
      observed_uuid: null,
    });
  });

  it("reads legacy single-file headers without later fields", async () => {
    const path = await writeCache(
      dyldCacheFixture(IMAGES.slice(0, 1), { legacy: true }),
    );
    const result = await inspectDyldSharedCache({
      cache_path: path,
      images: ["/usr/lib/libSystem.B.dylib"],
    });
    expect(result.ok && result.value).toMatchObject({
      platform: null,
      os_version: null,
      subcaches: [],
      images_total: 1,
      inspected_images: [{ status: "parsed" }],
    });
  });

  it("separates malformed input, missing files and non-cache files", async () => {
    expect(await inspectDyldSharedCache({ images: [] })).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    const directory = await createTestTempDirectory("rea-dyld-cache-bad-");
    expect(
      await inspectDyldSharedCache({ cache_path: join(directory, "absent") }),
    ).toMatchObject({ ok: false, error: { reason: "path" } });
    const notCache = join(directory, "not-a-cache");
    await writeFile(notCache, Buffer.alloc(64, 0x41));
    expect(
      await inspectDyldSharedCache({ cache_path: notCache }),
    ).toMatchObject({
      ok: false,
      error: { reason: "format" },
    });
  });

  it("wraps the observation as Evidence about the main cache file", async () => {
    const path = await writeCache(dyldCacheFixture(IMAGES));
    const evidence = await inspectDyldSharedCacheEvidence({ cache_path: path });
    expect(evidence.ok && evidence.value).toMatchObject({
      operation: "inspect_dyld_shared_cache",
      subject: { local_path: path, format: "file" },
      confidence: "observed",
    });
  });
});
