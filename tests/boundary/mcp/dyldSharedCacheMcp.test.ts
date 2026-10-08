import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, expect, it } from "vitest";
import { z } from "zod";

import { dyldCacheFixture } from "../../../src/artifacts/apple/DyldSharedCache.fixture.js";
import {
  FILE_TYPE,
  LC,
  dylibCommand,
  machoImage,
} from "../../../src/artifacts/apple/MachoImage.fixture.js";
import { dyldSharedCacheResultSchema } from "../../../src/domain/apple/dyldSharedCache.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const resources: Array<{ close(): Promise<unknown> }> = [];
afterEach(async () => {
  for (const resource of resources.splice(0)) await resource.close();
});

it("inspects a dyld shared cache through MCP without a target", async () => {
  const session = createTestBinarySession(() => {
    throw new Error("shared cache inspection must not launch a provider");
  });
  const server = createServer(session, session);
  const client = new Client({ name: "dyld-shared-cache-test", version: "1" });
  resources.push(client, server, session);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);

  const directory = await createTestTempDirectory("rea-dyld-cache-mcp-");
  const path = join(directory, "dyld_shared_cache_arm64e");
  const fixture = dyldCacheFixture([
    {
      path: "/usr/lib/libSystem.B.dylib",
      bytes: machoImage({
        fileType: FILE_TYPE.dylib,
        commands: [dylibCommand(LC.ID_DYLIB, "/usr/lib/libSystem.B.dylib")],
      }),
    },
  ]);
  const main = Buffer.from(fixture.main);
  main.writeBigUInt64LE(2n, 0x68);
  main.writeUInt32LE(1, 0x1c8);
  await writeFile(path, main);

  const tools = await client.listTools();
  expect(tools.tools.map(({ name }) => name)).toContain(
    "inspect_dyld_shared_cache",
  );
  const called = await client.callTool({
    name: "inspect_dyld_shared_cache",
    arguments: { cache_path: path, images: ["/usr/lib/libSystem.B.dylib"] },
  });
  expect(called.isError, JSON.stringify(called.structuredContent)).not.toBe(
    true,
  );
  const result = dyldSharedCacheResultSchema.parse(
    z.object({ result: z.unknown() }).parse(called.structuredContent).result,
  );
  expect(result).toMatchObject({
    architecture: "arm64e",
    cache_type: "multi-cache",
    cache_subtype: { id: 1, name: "production" },
    images_total: 1,
    inspected_images: [
      { path: "/usr/lib/libSystem.B.dylib", status: "parsed" },
    ],
  });
  const missing = await client.callTool({
    name: "inspect_dyld_shared_cache",
    arguments: { cache_path: join(directory, "absent") },
  });
  expect(missing.isError).toBe(true);
});
