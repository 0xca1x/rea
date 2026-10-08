import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { buffer } from "node:stream/consumers";

import { describe, expect, it } from "vitest";

import type { ArtifactEntry } from "./ArtifactReader.js";
import { CpioArtifactReader } from "./CpioArtifactReader.js";
import { MODE, gzipCpio, xarArchive } from "./InstallerPackage.fixture.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { XarArtifactReader } from "./XarArtifactReader.js";

const writePackage = async (bytes: Uint8Array): Promise<string> => {
  const directory = await createTestTempDirectory("rea-pkg-reader-");
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
    expect(entry.contentUnavailable).toBe(true);
    await expect(bzip.open(entry)).rejects.toMatchObject({
      reason: "unavailable",
    });
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
        "file:usr/fifo",
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

describe("installer package reader hardening", () => {
  it("refuses a TOC checksum whose declared size is not one digest", async () => {
    const reader = new XarArtifactReader(
      await writePackage(
        xarArchive([{ name: "Bom", data: Buffer.from("bom") }], {
          tocChecksumSize: 0x7fffffff,
        }),
      ),
    );
    await expect(collect(reader)).rejects.toMatchObject({
      reason: "format",
      message: "xar TOC declares a 2147483647-byte sha1 checksum",
    });
    await reader.close();
  });

  it("reports corrupt zlib members as malformed and keeps cancellation tagged", async () => {
    const reader = new XarArtifactReader(
      await writePackage(
        xarArchive([
          {
            name: "PackageInfo",
            data: Buffer.from("<pkg-info/>"),
            encoding: "zlib",
            archived: Buffer.from("not zlib at all"),
          },
        ]),
      ),
    );
    try {
      const [entry] = await collect(reader);
      if (entry === undefined) throw new Error("missing entry");
      await expect(buffer(await reader.open(entry))).rejects.toMatchObject({
        reason: "format",
      });
      const controller = new AbortController();
      controller.abort();
      await expect(reader.open(entry, controller.signal)).rejects.toMatchObject(
        {
          reason: "cancelled",
        },
      );
    } finally {
      await reader.close();
    }
  });
});

describe("cpio symlink targets", () => {
  it("streams past an oversized symlink target and keeps reading", async () => {
    const reader = new CpioArtifactReader(() =>
      Promise.resolve(
        Readable.from([
          gzipCpio(
            [
              { name: "./huge", mode: MODE.symlink, data: "x".repeat(4097) },
              { name: "./after", mode: MODE.file, data: "after" },
            ],
            "crc",
          ),
        ]),
      ),
    );
    try {
      const entries = await collect(reader);
      expect(
        entries.map(({ kind, path, limitations }) => [kind, path, limitations]),
      ).toEqual([
        [
          "symlink",
          "huge",
          ["Symlink target of 4097 bytes exceeds 4096 bytes and was not read."],
        ],
        ["file", "after", []],
      ]);
    } finally {
      await reader.close();
    }
  });
});

describe("cpio hard links and CRC archives", () => {
  const readAll = async (archive: Uint8Array) => {
    const reader = new CpioArtifactReader(() =>
      Promise.resolve(Readable.from([archive])),
    );
    const files: Record<string, string | undefined> = {};
    try {
      for await (const entry of reader.entries())
        if (entry.kind === "file")
          files[entry.path] =
            entry.contentUnavailable === true
              ? undefined
              : (await buffer(await reader.open(entry))).toString();
    } finally {
      await reader.close();
    }
    return files;
  };

  it("serves newc hard links stored on the last member to every path", async () => {
    expect(
      await readAll(
        gzipCpio(
          [
            { name: "./first", mode: MODE.file, ino: 7, links: 2 },
            {
              name: "./second",
              mode: MODE.file,
              ino: 7,
              links: 2,
              data: "shared",
            },
            {
              name: "./third",
              mode: MODE.file,
              ino: 9,
              links: 2,
              data: "kept",
            },
            { name: "./fourth", mode: MODE.file, ino: 9, links: 2 },
          ],
          "newc",
        ),
      ),
    ).toEqual({
      first: "shared",
      second: "shared",
      third: "kept",
      fourth: "kept",
    });
  });

  it("reports a hard link whose bytes never appear as unavailable", async () => {
    const reader = new CpioArtifactReader(() =>
      Promise.resolve(
        Readable.from([
          gzipCpio(
            [{ name: "./orphan", mode: MODE.file, ino: 4, links: 2 }],
            "newc",
          ),
        ]),
      ),
    );
    const entries = await collect(reader);
    expect(entries).toEqual([
      expect.objectContaining({
        path: "orphan",
        contentUnavailable: true,
        declaredSize: null,
      }),
    ]);
    const orphan = entries[0];
    if (orphan === undefined) throw new Error("missing entry");
    await expect(reader.open(orphan)).rejects.toMatchObject({
      reason: "unavailable",
    });
    await reader.close();
  });

  it("verifies 070702 member checksums whether or not members are opened", async () => {
    expect(
      await readAll(
        gzipCpio([{ name: "./ok", mode: MODE.file, data: "abc" }], "crc"),
      ),
    ).toEqual({ ok: "abc" });
    await expect(
      readAll(
        gzipCpio(
          [{ name: "./bad", mode: MODE.file, data: "abc", check: 1 }],
          "crc",
        ),
      ),
    ).rejects.toMatchObject({ reason: "integrity" });
    const reader = new CpioArtifactReader(() =>
      Promise.resolve(
        Readable.from([
          gzipCpio(
            [{ name: "./bad", mode: MODE.file, data: "abc", check: 1 }],
            "crc",
          ),
        ]),
      ),
    );
    await expect(collect(reader)).rejects.toMatchObject({
      reason: "integrity",
    });
    await reader.close();
  });
});
