import { Transform, type TransformCallback } from "node:stream";
import { ArtifactReaderFailure } from "./ArtifactReader.js";

/** One decoded-byte ceiling shared by an archive and all nested readers. */
export class ArtifactDecodedBudget {
  #used = 0;

  constructor(private readonly maximum = 512 * 1024 * 1024) {}

  /** Charge decoding work, including repeated reads, before exposing a chunk. */
  consume(bytes: number, path: string): void {
    if (
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      bytes > this.maximum - this.#used
    )
      throw new ArtifactReaderFailure(
        "limit",
        `Decoded archive budget of ${this.maximum} bytes exhausted at ${path}`,
      );
    this.#used += bytes;
  }
}

/** Decoder-stage budget/cancellation guard, independent of member metadata. */
export class ArtifactBudgetTransform extends Transform {
  constructor(
    private readonly budget: ArtifactDecodedBudget,
    private readonly path: string,
    private readonly signal?: AbortSignal,
  ) {
    super();
  }

  override _transform(
    chunk: Buffer,
    _encoding: BufferEncoding,
    done: TransformCallback,
  ): void {
    if (this.signal?.aborted) {
      done(
        new ArtifactReaderFailure(
          "cancelled",
          `Archive decoding cancelled at ${this.path}`,
        ),
      );
      return;
    }
    try {
      this.budget.consume(chunk.length, this.path);
    } catch (cause: unknown) {
      done(cause instanceof Error ? cause : new Error(String(cause)));
      return;
    }
    done(null, chunk);
  }
}
