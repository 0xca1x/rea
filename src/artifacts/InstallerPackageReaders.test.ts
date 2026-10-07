import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { buffer } from "node:stream/consumers";

import { afterEach, describe, expect, it } from "vitest";

import type { ArtifactEntry } from "./ArtifactReader.js";
import { CpioArtifactReader } from "./CpioArtifactReader.js";
import { MODE, gzipCpio, xarArchive } from "./InstallerPackage.fixture.js";
import { XarArtifactReader } from "./XarArtifactReader.js";

let directory: string | undefined;
afterEach(async () => {
  if (directory !== undefined)
    await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

const writePackage = async (bytes: Uint8Array): Promise<string> => {
  directory = await mkdtemp(join(tmpdir(), "rea-pkg-reader-"));
  const path = join(directory, "fixture.pkg");
  await writeFile(path, bytes);
  return path;
};

const collect = async (reader: {
  entries(): AsyncIterable<ArtifactEntry>;
}): Promise<ArtifactEntry[]> => {
  const entries: ArtifactEntry[] = [];
  for await (const entry of reader.entries()) entries.push(entry);
  return entries;
};

describe("xar installer package reader", () => {
  it("lists nested members and marks gzip-cpio scripts and payloads", async () => {
    const scripts = gzipCpio([
      { name: "./postinstall", mode: MODE.executable, data: "#!/bin/sh\n" },
    ]);
    const reader = new XarArtifactReader(
      await writePackage(
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
                data: Buffer.from("<pkg-info/>"),
                encoding: "zlib",
              },
              { name: "Scripts", data: scripts },
              { name: "Payload", data: Buffer.from("pbzx\0\0\0\0\x01\0\0\0") },
              { name: "Current", type: "symlink", link: "App.pkg" },
            ],
          },
        ]),
      ),
    );
    try {
      const entries = await collect(reader);
      expect(entries.map(({ path, kind }) => `${kind}:${path}`)).toEqual([
        "file:Distribution",
        "directory:App.pkg",
        "file:App.pkg/PackageInfo",
        "file:App.pkg/Scripts",
        "file:App.pkg/Payload",
        "symlink:App.pkg/Current",
      ]);
      const scriptsEntry = entries.find(
        ({ path }) => path === "App.pkg/Scripts",
      );
      expect(scriptsEntry?.nestedArchive).toBe("gzip-cpio");
      expect(
        entries.find(({ path }) => path === "App.pkg/Payload")?.limitations,
      ).toEqual([expect.stringContaining("pbzx")]);
      const distribution = entries[0];
      if (distribution === undefined) throw new Error("missing entry");
      expect((await buffer(await reader.open(distribution))).toString()).toBe(
        "<installer-gui-script/>",
      );
      if (scriptsEntry === undefined) throw new Error("missing scripts");
      const nested = new CpioArtifactReader(() => reader.open(scriptsEntry));
      try {
        const members: string[] = [];
        for await (const entry of nested.entries()) {
          members.push(entry.path);
          expect((await buffer(await nested.open(entry))).toString()).toBe(
            "#!/bin/sh\n",
          );
          expect(entry.executable).toBe(true);
        }
        expect(members).toEqual(["postinstall"]);
      } finally {
        await nested.close();
      }
    } finally {
      await reader.close();
    }
  });

  it("rejects tampered members, TOCs and unsupported encodings", async () => {
    const tampered = new XarArtifactReader(
      await writePackage(
        xarArchive([
          {
            name: "Bom",
            data: Buffer.from("bom"),
            extractedSha1: "0".repeat(40),
          },
        ]),
      ),
    );
    try {
      const [entry] = await collect(tampered);
      if (entry === undefined) throw new Error("missing entry");
      await expect(buffer(await tampered.open(entry))).rejects.toMatchObject({
        reason: "integrity",
      });
    } finally {
      await tampered.close();
    }
    const corrupt = new XarArtifactReader(
      await writePackage(
        xarArchive([{ name: "Bom", data: Buffer.from("bom") }], {
          corruptTocChecksum: true,
        }),
      ),
    );
    await expect(collect(corrupt)).rejects.toMatchObject({
      reason: "integrity",
    });
    await corrupt.close();
    const bzip = new XarArtifactReader(
      await writePackage(
        xarArchive([
          { name: "Bom", data: Buffer.from("bom"), encoding: "bzip2" },
        ]),
      ),
    );
    const [entry] = await collect(bzip);
    if (entry === undefined) throw new Error("missing entry");
    await expect(bzip.open(entry)).rejects.toMatchObject({ reason: "format" });
    await bzip.close();
    const notXar = new XarArtifactReader(
      await writePackage(Buffer.from("not an archive at all")),
    );
    await expect(collect(notXar)).rejects.toMatchObject({ reason: "format" });
    await notXar.close();
  });
});

describe("gzip cpio reader", () => {
  for (const format of ["odc", "newc"] as const)
    it(`reads ${format} members in order and skips unopened data`, async () => {
      const archive = gzipCpio(
        [
          { name: ".", mode: MODE.directory },
          { name: "./usr", mode: MODE.directory },
          {
            name: "./usr/bin/tool",
            mode: MODE.executable,
            data: "skipped bytes",
          },
          { name: "./usr/lib/link", mode: MODE.symlink, data: "../bin/tool" },
          { name: "./usr/fifo", mode: MODE.fifo },
          { name: "./usr/share/readme.txt", mode: MODE.file, data: "read me" },
        ],
        format,
      );
      const reader = new CpioArtifactReader(() =>
        Promise.resolve(Readable.from([archive])),
      );
      const seen: string[] = [];
      try {
        for await (const entry of reader.entries()) {
          seen.push(`${entry.kind}:${entry.path}`);
          if (entry.path === "usr/share/readme.txt") {
            expect((await buffer(await reader.open(entry))).toString()).toBe(
              "read me",
            );
            await expect(reader.open(entry)).rejects.toMatchObject({
              reason: "unavailable",
            });
          }
          if (entry.kind === "symlink")
            expect(entry.limitations).toEqual(["Symlink target: ../bin/tool"]);
        }
      } finally {
        await reader.close();
      }
      expect(seen).toEqual([
        "directory:usr",
        "file:usr/bin/tool",
        "symlink:usr/lib/link",
        "file:usr/share/readme.txt",
      ]);
    });

  it("rejects traversal and truncated archives", async () => {
    for (const name of ["../escape", "/absolute"]) {
      const reader = new CpioArtifactReader(() =>
        Promise.resolve(
          Readable.from([gzipCpio([{ name, mode: MODE.file, data: "x" }])]),
        ),
      );
      await expect(collect(reader)).rejects.toMatchObject({ reason: "path" });
      await reader.close();
    }
    const whole = gzipCpio([{ name: "a", mode: MODE.file, data: "abc" }]);
    const { gunzipSync, gzipSync } = await import("node:zlib");
    const truncated = gzipSync(gunzipSync(whole).subarray(0, 60));
    const reader = new CpioArtifactReader(() =>
      Promise.resolve(Readable.from([truncated])),
    );
    await expect(collect(reader)).rejects.toMatchObject({ reason: "format" });
    await reader.close();
  });
});
