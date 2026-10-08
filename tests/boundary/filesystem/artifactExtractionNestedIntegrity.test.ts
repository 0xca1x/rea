import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createPackage, createPackageWithOptions } from "@electron/asar";
import { expect, it } from "vitest";

import { extractArtifact } from "../../../src/artifacts/extraction/ArtifactExtraction.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("does not claim unmaterialized nested integrity contradictions were extracted", async () => {
  const root = await createTestTempDirectory("rea-nested-integrity-extract-");
  const source = join(root, "source");
  const original = "console.log('ok');\n";
  const changed = "console.log('no');\n";
  await mkdir(source);
  await writeFile(join(source, "main.js"), original);
  const app = join(root, "app");
  await mkdir(app);
  const archive = join(app, "app.asar");
  await createPackage(source, archive);
  const bytes = await readFile(archive);
  const contentOffset = bytes.indexOf(original);
  expect(contentOffset).toBeGreaterThanOrEqual(0);
  bytes.write(changed, contentOffset, "utf8");
  await writeFile(archive, bytes);

  const result = await extractArtifact({
    inputPath: app,
    // A directory path is read as a directory before this format is consulted.
    inputFormat: "zip",
    outputRoot: join(root, "out"),
    integrity: { mode: "record-and-continue" },
  });

  expect(result.artifacts.map(({ relative_path }) => relative_path)).toEqual([
    "app.asar",
  ]);
  expect(result.integrity_contradictions).toEqual([
    expect.objectContaining({
      logical_path: "app.asar/main.js",
      declared_sha256: createHash("sha256").update(original).digest("hex"),
      observed_sha256: createHash("sha256").update(changed).digest("hex"),
      trust: "observed-untrusted",
    }),
  ]);
  expect(result.limitations.join("\n")).toContain(
    "were not written as their own files",
  );
  expect(result.limitations.join("\n")).toContain("main.js");
  expect(result.limitations.join("\n")).not.toContain(
    "extracted file(s) contradict",
  );
});

it.each(["addon.node", "lib/addon.node"])(
  "recognizes unpacked companion %s materialized under its filesystem path",
  async (member) => {
    const root = await createTestTempDirectory(
      "rea-unpacked-integrity-extract-",
    );
    const source = join(root, "source");
    const app = join(root, "app");
    await mkdir(source);
    await mkdir(app);
    const original = "unsigned addon bytes";
    const observed = "signed addon bytes";
    await mkdir(join(source, "lib"));
    await writeFile(join(source, member), original);
    const archive = join(app, "app.asar");
    await createPackageWithOptions(source, archive, { unpack: "**/*.node" });
    await writeFile(join(`${archive}.unpacked`, member), observed);
    const output = join(root, "out");
    const result = await extractArtifact({
      inputPath: app,
      inputFormat: "zip",
      outputRoot: output,
      integrity: { mode: "record-and-continue" },
    });
    expect(
      await readFile(join(output, `app.asar.unpacked/${member}`), "utf8"),
    ).toBe(observed);
    expect(result.integrity_contradictions).toEqual([
      expect.objectContaining({
        logical_path: `app.asar/${member}`,
        unpacked: true,
      }),
    ]);
    expect(result.limitations.join("\n")).toContain(
      "1 extracted file(s) contradict declared integrity",
    );
    expect(result.limitations.join("\n")).not.toContain(
      "were not written as their own files",
    );
  },
);
