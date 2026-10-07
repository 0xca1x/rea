import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  MODE,
  gzipCpio,
  xarArchive,
} from "../../../src/artifacts/InstallerPackage.fixture.js";
import { runProviderAnalysis } from "../../../src/application/DirectAnalysis.js";
import { artifactInventoryResultSchema } from "../../../src/domain/artifactGraph.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const sha256 = (text: string): string =>
  createHash("sha256").update(text).digest("hex");

const productPackage = (payloadText: string, extractedSha1?: string) =>
  xarArchive([
    {
      name: "Distribution",
      data: Buffer.from("<installer-gui-script/>"),
      encoding: "zlib",
    },
    {
      name: "App.pkg",
      type: "directory",
      children: [
        {
          name: "PackageInfo",
          data: Buffer.from('<pkg-info identifier="com.example.app"/>'),
          encoding: "zlib",
          ...(extractedSha1 === undefined ? {} : { extractedSha1 }),
        },
        {
          name: "Scripts",
          data: gzipCpio([
            { name: ".", mode: MODE.directory },
            {
              name: "./postinstall",
              mode: MODE.executable,
              data: "#!/bin/sh\n",
            },
          ]),
        },
        {
          name: "Payload",
          data: gzipCpio([
            { name: ".", mode: MODE.directory },
            { name: "./Applications", mode: MODE.directory },
            {
              name: "./Applications/App.app/Contents/Info.plist",
              mode: MODE.file,
              data: payloadText,
            },
          ]),
        },
      ],
    },
  ]);

describe("installer package inventory", () => {
  it("inventories xar members and expands gzip-cpio scripts and payloads", async () => {
    const directory = await createTestTempDirectory("rea-pkg-inventory-");
    const path = join(directory, "Installer.pkg");
    await writeFile(path, productPackage("<plist/>"));
    const evidence = parseEvidence(
      await runProviderAnalysis(path, "inventory_artifact", {}),
    );
    const inventory = artifactInventoryResultSchema.parse(
      evidence.normalized_result,
    );
    expect(inventory.manifest.root_format).toBe("pkg");
    expect(inventory.limitations).toEqual([]);
    const occurrences = new Map(
      inventory.occurrences.map((occurrence) => [
        occurrence.logical_path,
        occurrence,
      ]),
    );
    expect([...occurrences.keys()]).toEqual(
      expect.arrayContaining([
        "Distribution",
        "App.pkg/PackageInfo",
        "App.pkg/Scripts",
        "App.pkg/Scripts/postinstall",
        "App.pkg/Payload",
        "App.pkg/Payload/Applications/App.app/Contents/Info.plist",
      ]),
    );
    const plist = occurrences.get(
      "App.pkg/Payload/Applications/App.app/Contents/Info.plist",
    );
    const node = inventory.nodes.find(
      ({ artifact_id: id }) => id === plist?.artifact_id,
    );
    expect(node?.sha256).toBe(sha256("<plist/>"));
    expect(occurrences.get("App.pkg/Scripts/postinstall")?.executable).toBe(
      true,
    );
    const scripts = occurrences.get("App.pkg/Scripts");
    expect(
      occurrences.get("App.pkg/Scripts/postinstall")?.parent_occurrence_id,
    ).toBe(scripts?.occurrence_id);
  });

  it("fails on a member whose xar checksum disagrees with its bytes", async () => {
    const directory = await createTestTempDirectory("rea-pkg-tampered-");
    const path = join(directory, "Installer.pkg");
    await writeFile(path, productPackage("<plist/>", "0".repeat(40)));
    expect(
      await runProviderAnalysis(path, "inventory_artifact", {}),
    ).toMatchObject({
      error: "Analysis failed",
      details: { reason: "integrity" },
    });
  });

  it("records an unresolved hard link as unavailable instead of empty", async () => {
    const directory = await createTestTempDirectory("rea-pkg-hardlink-");
    const path = join(directory, "Installer.pkg");
    await writeFile(
      path,
      xarArchive([
        {
          name: "Payload",
          data: gzipCpio(
            [{ name: "./orphan", mode: MODE.file, ino: 3, links: 2 }],
            "newc",
          ),
        },
      ]),
    );
    const inventory = artifactInventoryResultSchema.parse(
      parseEvidence(await runProviderAnalysis(path, "inventory_artifact", {}))
        .normalized_result,
    );
    expect(
      inventory.occurrences.find(
        ({ logical_path: logical }) => logical === "Payload/orphan",
      ),
    ).toMatchObject({
      artifact_id: null,
      hash_status: "unavailable",
      limitations: [expect.stringContaining("Hard-link bytes")],
    });
  });
});
