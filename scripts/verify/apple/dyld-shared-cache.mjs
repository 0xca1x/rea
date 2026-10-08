import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdtemp, open, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { DyldSharedCache } from "../../../dist/artifacts/apple/DyldSharedCacheReader.js";
import {
  artifactCli,
  artifactMcpResult,
  withArtifactMcp,
} from "../../lib/artifact-e2e.mjs";
import {
  buildMacosBundleFixture,
  preflightMacosBundleFixture,
} from "../../fixtures/apple/macos-bundle.mjs";

const exec = promisify(execFile);

await preflightMacosBundleFixture();
try {
  await exec("/usr/bin/xcrun", ["--find", "dyld_info"]);
} catch (cause) {
  throw new Error(
    "dyld shared cache verification requires dyld_info from Command Line Tools (xcrun --find dyld_info failed)",
    { cause },
  );
}

/** The cache this host's dyld uses for native processes. */
const hostCache = async () => {
  const names =
    process.arch === "arm64"
      ? ["dyld_shared_cache_arm64e"]
      : ["dyld_shared_cache_x86_64h", "dyld_shared_cache_x86_64"];
  for (const directory of [
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    "/System/Library/dyld",
  ])
    for (const name of names)
      try {
        await access(join(directory, name));
        return join(directory, name);
      } catch {
        // Try the next documented location.
      }
  throw new Error("No dyld shared cache was found in the documented locations");
};

/** `dyld_info -all_dyld_cache -linked_dylibs`: path -> "attributes|load path" lines. */
const dyldInfoImages = async () => {
  const { stdout } = await exec(
    "/usr/bin/xcrun",
    ["dyld_info", "-all_dyld_cache", "-linked_dylibs"],
    { maxBuffer: 256 * 1024 * 1024 },
  );
  const images = new Map();
  let current;
  for (const line of stdout.split("\n")) {
    const head = /^(\/.+) \[(\S+)\]:$/u.exec(line);
    if (head !== null) {
      current = [];
      images.set(head[1], current);
      continue;
    }
    const dependency = /^\s{8}(.*?)\s*(\/\S.*)$/u.exec(line);
    if (dependency !== null && current !== undefined)
      current.push(
        `${dependency[1].split(/\s+/u).filter(Boolean).sort().join(",")}|${dependency[2]}`,
      );
  }
  return images;
};

const attributes = (dependency) =>
  [
    dependency.reexport ? "re-export" : null,
    dependency.weak ? "weak-link" : null,
    dependency.upward ? "upward" : null,
    dependency.delayed_init ? "delay-init" : null,
  ]
    .filter((value) => value !== null)
    .sort()
    .join(",");

const cachePath = await hostCache();
const root = await mkdtemp(join(tmpdir(), "rea-dyld-cache-"));
try {
  const expected = await dyldInfoImages();
  const cache = await DyldSharedCache.open(cachePath);
  let compared = 0;
  try {
    assert.deepEqual(
      cache.images.map(({ path }) => path).sort(),
      [...expected.keys()].sort(),
      "image list differs from dyld_info",
    );
    for (const [path, dependencies] of expected) {
      const read = await cache.imageFacts(path);
      assert.equal(read?.facts.status, "parsed", path);
      assert.deepEqual(
        read.facts.slices[0].dependencies.map(
          (dependency) =>
            `${attributes(dependency)}|${dependency.install_name}`,
        ),
        dependencies,
        `${path} dependencies differ from dyld_info`,
      );
      compared += 1;
    }
  } finally {
    await cache.close();
  }

  const inspected = await artifactCli("inspect-dyld-shared-cache", cachePath, [
    "--image",
    "/usr/lib/libSystem.B.dylib",
  ]);
  assert.equal(inspected.images_total, expected.size);
  assert.equal(inspected.coverage.status, "complete");
  assert.equal(inspected.inspected_images[0].status, "parsed");
  // Check the producer header directly, independently of REA's header projection.
  const handle = await open(cachePath, "r");
  try {
    const header = Buffer.alloc(0x1cc);
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    const multi = header.readBigUInt64LE(0x68) === 2n;
    const hasSubtype =
      bytesRead === header.length && header.readUInt32LE(0x10) >= header.length;
    const subtype = multi && hasSubtype ? header.readUInt32LE(0x1c8) : null;
    assert.deepEqual(
      inspected.cache_subtype,
      subtype === null
        ? null
        : {
            id: subtype,
            name:
              subtype === 0
                ? "development"
                : subtype === 1
                  ? "production"
                  : null,
          },
      "multi-cache subtype differs from the producer header",
    );
  } finally {
    await handle.close();
  }
  await withArtifactMcp(null, async (client) => {
    const viaMcp = await artifactMcpResult(
      client,
      "inspect_dyld_shared_cache",
      {
        cache_path: cachePath,
        images: ["/usr/lib/libSystem.B.dylib"],
      },
    );
    assert.deepEqual(viaMcp, inspected);
  });

  const { app } = await buildMacosBundleFixture(root);
  const trace = await artifactCli("trace-dylib-resolution", app, [
    "--shared-cache",
    cachePath,
  ]);
  assert.equal(trace.shared_cache.uuid, inspected.uuid);
  const main = "Contents/MacOS/MacFixture";
  const cached = trace.edges.filter(
    ({ root: edgeRoot, resolution }) =>
      edgeRoot === main && resolution.status === "shared-cache",
  );
  assert.ok(
    cached.some(
      ({ install_name: name }) => name === "/usr/lib/libSystem.B.dylib",
    ),
  );
  assert.ok(
    trace.edges.every(({ install_name: name, resolution }) =>
      name.startsWith("/usr/lib/") || name.startsWith("/System/")
        ? resolution.status === "shared-cache"
        : true,
    ),
    "a system install path was not found in the host cache",
  );
  const { stderr } = await exec(join(app, main), [], {
    env: { PATH: "/usr/bin:/bin", DYLD_PRINT_LIBRARIES: "1" },
  });
  const loaded = new Set(
    stderr
      .split("\n")
      .map((line) => /^dyld\[\d+\]: <[0-9A-F-]+> (.+)$/u.exec(line)?.[1])
      .filter((path) => path !== undefined),
  );
  for (const { resolution } of cached)
    assert.ok(
      loaded.has(resolution.image),
      `${resolution.image} was not loaded by dyld`,
    );

  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      mocked: false,
      cli: true,
      stdio_mcp: true,
      cache: {
        architecture: inspected.architecture,
        os_version: inspected.os_version,
        images: inspected.images_total,
        type: inspected.cache_type,
        subtype: inspected.cache_subtype,
      },
      images_matching_dyld_info: compared,
      trace_shared_cache_edges: cached.length,
      dyld_loaded_every_cached_edge: true,
      host: await realpath(cachePath),
    })}\n`,
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
