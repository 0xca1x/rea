import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  MODE,
  gzipCpio,
  xarArchive,
  rewriteXarToc,
} from "../../../src/artifacts/InstallerPackage.fixture.js";
import { runProviderAnalysis } from "../../../src/composition/directAnalysis.js";
import {
  artifactInventoryResultSchema,
  artifactExtractionResultSchema,
} from "../../../src/domain/artifactGraph.js";
import { analysisErrorProjectionSchema } from "../../../src/contracts/errorSchemas.js";
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

describe("installer package checksum evidence", () => {
  it("reports a stored SHA-1 mismatch independently of a valid decoded MD5", async () => {
    const directory = await createTestTempDirectory("rea-pkg-checksum-reason-");
    const path = join(directory, "Installer.pkg");
    const data = Buffer.from("readable content");
    const declared = "0".repeat(40);
    await writeFile(
      path,
      rewriteXarToc(
        xarArchive([{ name: "member", data, archivedSha1: declared }]),
        (xml) =>
          xml.replace(
            /<extracted-checksum style="sha1">[^<]+<\/extracted-checksum>/u,
            `<extracted-checksum style="md5">${createHash("md5").update(data).digest("hex")}</extracted-checksum>`,
          ),
      ),
    );
    const { error, ...projection } = z
      .object({ error: z.string() })
      .passthrough()
      .parse(await runProviderAnalysis(path, "inventory_artifact", {}));
    expect(error).toBe("Analysis failed");
    const failed = analysisErrorProjectionSchema.parse(projection);
    expect(failed).toMatchObject({
      code: "artifact_integrity_mismatch",
      details: {
        logical_path: "member",
        checksum_mismatches: [
          {
            representation: "stored",
            algorithm: "sha1",
            declared,
            observed: createHash("sha1").update(data).digest("hex"),
          },
        ],
      },
    });
  });

  it.each(["raw", "zlib"] as const)(
    "hashes and extracts %s content with unsupported stored and decoded checksum algorithms",
    async (encoding) => {
      const directory = await createTestTempDirectory(
        "rea-pkg-unknown-checksum-",
      );
      const path = join(directory, "Installer.pkg");
      const data = Buffer.from("readable content");
      await writeFile(
        path,
        rewriteXarToc(xarArchive([{ name: "member", data, encoding }]), (xml) =>
          xml
            .replaceAll(
              '<archived-checksum style="sha1">',
              '<archived-checksum style="unknown-stored">',
            )
            .replaceAll(
              '<extracted-checksum style="sha1">',
              '<extracted-checksum style="unknown-decoded">',
            ),
        ),
      );
      const inventory = artifactInventoryResultSchema.parse(
        parseEvidence(await runProviderAnalysis(path, "inventory_artifact", {}))
          .normalized_result,
      );
      const member = inventory.occurrences.find(
        ({ logical_path }) => logical_path === "member",
      );
      expect(member).toMatchObject({
        hash_status: "verified",
        limitations: [
          expect.stringContaining("unsupported checksum unknown-decoded"),
          expect.stringContaining(
            "unsupported archived checksum unknown-stored",
          ),
        ],
      });
      expect(
        inventory.nodes.find(
          ({ artifact_id }) => artifact_id === member?.artifact_id,
        ),
      ).toMatchObject({ sha256: sha256(data.toString()), size: data.length });
      const output = join(directory, "extracted");
      const extraction = artifactExtractionResultSchema.parse(
        parseEvidence(
          await runProviderAnalysis(path, "extract_artifact", {
            output_root: output,
          }),
        ).normalized_result,
      );
      expect(extraction.artifacts).toHaveLength(1);
      expect(await readFile(join(output, "member"))).toEqual(data);
    },
  );
});

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
      code: "artifact_integrity_mismatch",
      details: { logical_path: "App.pkg/PackageInfo", declared_sha256: null },
    });
  });

  it("records a xar checksum mismatch under record-and-continue", async () => {
    const directory = await createTestTempDirectory("rea-pkg-recorded-");
    const path = join(directory, "Installer.pkg");
    await writeFile(path, productPackage("<plist/>", "0".repeat(40)));
    const inventory = artifactInventoryResultSchema.parse(
      parseEvidence(
        await runProviderAnalysis(path, "inventory_artifact", {
          integrity_policy: "record-and-continue",
        }),
      ).normalized_result,
    );
    const info = inventory.occurrences.find(
      ({ logical_path: logical }) => logical === "App.pkg/PackageInfo",
    );
    const observedSha1 = createHash("sha1")
      .update('<pkg-info identifier="com.example.app"/>')
      .digest("hex");
    expect(info).toMatchObject({ hash_status: "mismatched" });
    expect(info?.limitations).toContain(
      `Declared decoded sha1 ${"0".repeat(40)} disagrees with observed ${observedSha1}.`,
    );
    expect(inventory.limitations).toContainEqual(
      expect.stringContaining(
        "1 member(s) disagree with a declared non-SHA-256 checksum",
      ),
    );
    // Untampered members are still inventoried and expanded.
    expect(
      inventory.occurrences.some(
        ({ logical_path: logical }) =>
          logical === "App.pkg/Scripts/postinstall",
      ),
    ).toBe(true);
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

describe("installer package CRC recovery", () => {
  it("recovers later siblings after a misaligned CRC mismatch", async () => {
    const directory = await createTestTempDirectory("rea-pkg-crc-align-");
    const path = join(directory, "Installer.pkg");
    await writeFile(
      path,
      xarArchive([
        {
          name: "Payload",
          // "abc" is 3 bytes (1 padding byte): a CRC failure here must not
          // desynchronize the following member.
          data: gzipCpio(
            [
              { name: "./bad", mode: MODE.file, data: "abc", check: 1 },
              { name: "./good", mode: MODE.file, data: "ok" },
            ],
            "crc",
          ),
        },
      ]),
    );
    const inventory = artifactInventoryResultSchema.parse(
      parseEvidence(
        await runProviderAnalysis(path, "inventory_artifact", {
          integrity_policy: "record-and-continue",
        }),
      ).normalized_result,
    );
    const bad = inventory.occurrences.find(
      ({ logical_path: logical }) => logical === "Payload/bad",
    );
    expect(bad).toMatchObject({ hash_status: "mismatched" });
    expect(
      inventory.nodes.find(
        ({ artifact_id }) => artifact_id === bad?.artifact_id,
      ),
    ).toMatchObject({ sha256: sha256("abc"), size: 3 });
    expect(bad?.limitations).toContain(
      "Declared decoded cpio-byte-sum 00000001 disagrees with observed 00000126.",
    );
    expect(
      inventory.occurrences.find(
        ({ logical_path: logical }) => logical === "Payload/good",
      ),
    ).toMatchObject({ hash_status: "verified" });
  });

  it("keeps later siblings after a zero-size hard-link CRC mismatch", async () => {
    const directory = await createTestTempDirectory("rea-pkg-link-crc-");
    const path = join(directory, "Installer.pkg");
    await writeFile(
      path,
      xarArchive([
        {
          name: "Payload",
          data: gzipCpio(
            [
              { name: "./bad", mode: MODE.file, ino: 4, links: 2, check: 1 },
              { name: "./good", mode: MODE.file, data: "ok" },
            ],
            "crc",
          ),
        },
      ]),
    );
    const inventory = artifactInventoryResultSchema.parse(
      parseEvidence(
        await runProviderAnalysis(path, "inventory_artifact", {
          integrity_policy: "record-and-continue",
        }),
      ).normalized_result,
    );
    expect(
      inventory.occurrences.find(
        ({ logical_path: logical }) => logical === "Payload/bad",
      ),
    ).toMatchObject({ hash_status: "unavailable" });
    expect(
      inventory.occurrences.find(
        ({ logical_path: logical }) => logical === "Payload/good",
      ),
    ).toMatchObject({ hash_status: "verified" });
  });
});
