import { Readable, Transform } from "node:stream";
import { buffer } from "node:stream/consumers";
import { expect, it } from "vitest";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import { artifactStreamPipeline } from "./ArtifactStreamPipeline.js";

it("preserves tagged failures from intermediate verification stages", async () => {
  const failure = new ArtifactReaderFailure(
    "integrity",
    "stored checksum disagrees",
  );
  const verifier = new Transform({
    transform(_chunk, _encoding, done) {
      done(failure);
    },
  });
  const output = artifactStreamPipeline(
    Readable.from([Buffer.from("encoded")]),
    [verifier],
    { path: "member" },
  );
  await expect(buffer(output)).rejects.toBe(failure);
});

it("closes the source when the consumer stops before exhausting member data", async () => {
  const source = Readable.from(
    (function* () {
      for (let index = 0; index < 1000; index++) yield Buffer.alloc(64 * 1024);
    })(),
  );
  const closed = new Promise<void>((resolve) =>
    source.once("close", () => resolve()),
  );
  const output = artifactStreamPipeline(source, [], { path: "member" });
  for await (const chunk of output) {
    expect(Buffer.isBuffer(chunk)).toBe(true);
    break;
  }
  await closed;
  expect(source.destroyed).toBe(true);
});

it("observes abort before a consumer starts reading", async () => {
  const controller = new AbortController();
  const source = Readable.from([Buffer.from("data")]);
  const output = artifactStreamPipeline(source, [], {
    path: "member",
    signal: controller.signal,
  });
  controller.abort();
  await expect(buffer(output)).rejects.toMatchObject({ reason: "cancelled" });
});
