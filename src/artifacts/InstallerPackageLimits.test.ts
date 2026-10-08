import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buffer } from "node:stream/consumers";
import { Readable } from "node:stream";
import { expect, it } from "vitest";
import { ArtifactDecodedBudget } from "./ArtifactDecodedBudget.js";
import { CpioArtifactReader } from "./CpioArtifactReader.js";
import {
  MODE,
  gzipCpio,
  xarArchive,
  rewriteXarToc,
  type XarFixtureMember,
} from "./InstallerPackage.fixture.js";
import { XarArtifactReader } from "./XarArtifactReader.js";

const withReader = async (
  bytes: Uint8Array,
  run: (reader: XarArtifactReader) => Promise<void>,
  decodedBudget?: ArtifactDecodedBudget,
) => {
  const root = await mkdtemp(join(tmpdir(), "rea-pkg-limits-"));
  const path = join(root, "fixture.pkg");
  await writeFile(path, bytes);
  const reader = new XarArtifactReader(
    path,
    decodedBudget === undefined ? {} : { decodedBudget },
  );
  try {
    await run(reader);
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
};

it("shares an inflation budget across separate zlib members", async () => {
  const bytes = xarArchive([
    { name: "a", data: Buffer.alloc(40, 65), encoding: "zlib" },
    { name: "b", data: Buffer.alloc(40, 66), encoding: "zlib" },
  ]);
  await withReader(
    bytes,
    async (reader) => {
      let read = 0;
      await expect(
        (async () => {
          for await (const entry of reader.entries()) {
            await buffer(await reader.open(entry));
            read++;
          }
        })(),
      ).rejects.toMatchObject({
        reason: "limit",
        message: expect.stringContaining("Decoded archive budget"),
      });
      expect(read).toBe(1);
    },
    new ArtifactDecodedBudget(64),
  );
});

it.each(["", " ", "1e2", "0x10"])(
  "rejects nondecimal/empty numeric TOC data: %j",
  async (value) => {
    const bytes = rewriteXarToc(
      xarArchive([{ name: "a", data: Buffer.from("bytes") }]),
      (xml) =>
        xml.replace(/<length>\d+<\/length>/u, `<length>${value}</length>`),
    );
    await withReader(bytes, async (reader) => {
      await expect(
        (async () => {
          for await (const entry of reader.entries()) void entry;
        })(),
      ).rejects.toMatchObject({
        reason: "format",
        message: "xar TOC has an invalid data length",
      });
    });
  },
);

it("rejects unsafe absolute heap ranges with a tagged format failure", async () => {
  const bytes = rewriteXarToc(
    xarArchive([{ name: "Payload", data: Buffer.from("gzip") }]),
    (xml) =>
      xml.replace(
        /<offset>20<\/offset>/u,
        `<offset>${Number.MAX_SAFE_INTEGER}</offset>`,
      ),
  );
  await withReader(bytes, async (reader) => {
    await expect(
      (async () => {
        for await (const entry of reader.entries()) void entry;
      })(),
    ).rejects.toMatchObject({
      reason: "format",
      message: expect.stringContaining("heap extent"),
    });
  });
});

it("bounds retained full paths from deeply nested TOCs", async () => {
  let member: XarFixtureMember = { name: "leaf", data: Buffer.from("x") };
  for (let depth = 0; depth < 300; depth++)
    member = {
      name: "directory-segment",
      type: "directory",
      children: [member],
    };
  await withReader(xarArchive([member]), async (reader) => {
    await expect(
      (async () => {
        for await (const entry of reader.entries()) void entry;
      })(),
    ).rejects.toMatchObject({
      reason: "limit",
      message: expect.stringContaining("path text"),
    });
  });
});

it("observes cancellation during internal symlink drains", async () => {
  const controller = new AbortController();
  const archive = gzipCpio([
    {
      name: "huge-link",
      mode: MODE.symlink,
      data: "x".repeat(4 * 1024 * 1024),
    },
  ]);
  let decoded = 0;
  const budget = new (class extends ArtifactDecodedBudget {
    override consume(bytes: number, path: string): void {
      super.consume(bytes, path);
      decoded += bytes;
      if (decoded >= 64 * 1024) controller.abort();
    }
  })();
  const reader = new CpioArtifactReader(
    async () => Readable.from([archive]),
    "fail",
    budget,
  );
  try {
    await expect(
      (async () => {
        for await (const entry of reader.entries(controller.signal)) void entry;
      })(),
    ).rejects.toMatchObject({ reason: "cancelled" });
  } finally {
    await reader.close();
  }
});
