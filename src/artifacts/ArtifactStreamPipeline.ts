import { PassThrough, Readable, pipeline, type Transform } from "node:stream";
import { ArtifactReaderFailure } from "./ArtifactReader.js";

/**
 * Connect a decoder chain as one lifecycle: failures propagate in both
 * directions, cancellation destroys every stage, and consumer early-return
 * cannot leave the archive source reading after its handle is closed.
 */
export const artifactStreamPipeline = (
  source: Readable,
  stages: readonly Transform[],
  context: {
    readonly path: string;
    readonly signal?: AbortSignal | undefined;
  },
): Readable => {
  const output = new PassThrough();
  const aborted = () =>
    output.destroy(
      new ArtifactReaderFailure(
        "cancelled",
        `Archive read cancelled: ${context.path}`,
      ),
    );
  pipeline([source, ...stages, output], () => {
    // The readable destination retains any failure for its consumer. Keep
    // cancellation active until buffered output has also been consumed.
  });
  context.signal?.addEventListener("abort", aborted, { once: true });
  if (context.signal?.aborted) aborted();
  const dispose = () => {
    context.signal?.removeEventListener("abort", aborted);
    output.destroy();
  };
  const consumer = Readable.from(
    (async function* () {
      try {
        for await (const chunk of output) yield chunk;
      } catch (cause: unknown) {
        if (cause instanceof ArtifactReaderFailure) throw cause;
        if (context.signal?.aborted)
          throw new ArtifactReaderFailure(
            "cancelled",
            `Archive read cancelled: ${context.path}`,
            { cause },
          );
        throw new ArtifactReaderFailure(
          "format",
          `Archive member could not be decoded: ${context.path}`,
          { cause },
        );
      } finally {
        dispose();
      }
    })(),
  );
  // Also covers destroy() before the async generator is first advanced.
  consumer.once("close", dispose);
  return consumer;
};
