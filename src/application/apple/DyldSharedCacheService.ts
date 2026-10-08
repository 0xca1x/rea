import { resolve } from "node:path";

import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { DyldSharedCache } from "../../artifacts/apple/DyldSharedCacheReader.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import {
  DYLD_SHARED_CACHE_LIMITATIONS,
  dyldSharedCacheResultSchema,
  inspectDyldSharedCacheInputSchema,
  type DyldSharedCacheResult,
  type InspectedCacheImage,
} from "../../domain/apple/dyldSharedCache.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import { APPLE_APPLICATION_PROVIDER } from "../InvestigationProviders.js";

const OPERATION = "inspect_dyld_shared_cache" as const;

/** Read one requested image through the cache, keeping absence explicit. */
const inspectImage = async (
  cache: DyldSharedCache,
  path: string,
): Promise<InspectedCacheImage> => {
  const image = cache.find(path);
  const base = { path, reason: null, slices: [] };
  if (image === undefined)
    return { ...base, status: "absent", address: null, file: null };
  const address = `0x${image.address.toString(16)}`;
  const read = await cache.imageFacts(path);
  if (read === undefined)
    return {
      ...base,
      status: "unmapped",
      address,
      file: null,
      reason: "The image address lies in no readable cache mapping.",
    };
  const { facts, file } = read;
  if (facts.status === "parsed")
    return {
      ...base,
      status: "parsed",
      address,
      file,
      slices: [...facts.slices],
    };
  return {
    ...base,
    status: facts.status === "not-mach-o" ? "malformed" : facts.status,
    address,
    file,
    reason:
      facts.status === "not-mach-o"
        ? "The cached image is not a Mach-O image."
        : facts.reason,
  };
};

const failure = (cause: unknown): AnalysisError => {
  if (cause instanceof ArtifactReaderFailure)
    return new ArtifactOperationError(
      OPERATION,
      cause.reason,
      undefined,
      cause.message,
    );
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "ENOENT" || cause.code === "ENOTDIR")
      return new ArtifactOperationError(
        OPERATION,
        "path",
        undefined,
        "The cache file does not exist.",
      );
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new ArtifactOperationError(
        OPERATION,
        "unavailable",
        undefined,
        "The cache file is not readable.",
      );
  }
  if (cause instanceof Error && cause.name === "AbortError")
    return new ArtifactOperationError(OPERATION, "cancelled");
  return new ArtifactOperationError(OPERATION, "io");
};

/** Inspect a dyld shared cache file set selected by path. */
export const inspectDyldSharedCache = async (
  rawInput: unknown,
  signal?: AbortSignal,
): Promise<Result<DyldSharedCacheResult, AnalysisError>> => {
  const parsed = inspectDyldSharedCacheInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(new AnalysisInputError(OPERATION, { cause: parsed.error }));
  // Keep the caller-selected spelling for result and Evidence metadata; only
  // filesystem access uses the resolved path.
  const selectedPath = parsed.data.cache_path;
  const cachePath = resolve(selectedPath);
  let cache: DyldSharedCache | undefined;
  try {
    cache = await DyldSharedCache.open(cachePath, signal);
    const inspected: InspectedCacheImage[] = [];
    for (const path of parsed.data.images ?? []) {
      signal?.throwIfAborted();
      inspected.push(await inspectImage(cache, path));
    }
    const unreadable = cache.header.subcaches
      .filter(({ status }) => status !== "present")
      .map(({ suffix }) => suffix);
    // Hash through the open handles the header was parsed from, so a path
    // replacement mid-inspection cannot attribute new bytes to old facts.
    const mainSha = await cache.mainSha256(signal);
    const subcacheSha = await cache.subcacheSha256(signal);
    return ok(
      dyldSharedCacheResultSchema.parse({
        cache_path: selectedPath,
        // The header and image list were read through this same handle.
        main_file_sha256: mainSha,
        ...cache.header,
        subcache_sha256: subcacheSha,
        images_total: cache.images.length,
        images: cache.images.map(({ path, address }) => ({
          path,
          address: `0x${address.toString(16)}`,
        })),
        inspected_images: inspected,
        coverage: {
          status: unreadable.length === 0 ? "complete" : "partial",
          unreadable_subcaches: unreadable,
        },
        limitations: [
          ...DYLD_SHARED_CACHE_LIMITATIONS,
          ...(unreadable.length === 0
            ? []
            : [
                `Subcaches ${unreadable.join(", ")} are missing or do not match the main cache UUID; images mapped there are unmapped.`,
              ]),
        ],
      }),
    );
  } catch (cause: unknown) {
    return err(failure(cause));
  } finally {
    await cache?.close();
  }
};

/** Inspect a dyld shared cache and wrap the observation as Evidence. */
export const inspectDyldSharedCacheEvidence = async (
  rawInput: unknown,
  signal?: AbortSignal,
): Promise<Result<Evidence, AnalysisError>> => {
  const inspected = await inspectDyldSharedCache(rawInput, signal);
  if (!inspected.ok) return inspected;
  const result = inspected.value;
  return ok(
    createEvidence(
      {
        path: result.cache_path,
        sha256: result.main_file_sha256,
        format: "file",
      },
      APPLE_APPLICATION_PROVIDER,
      {
        operation: OPERATION,
        parameters: {
          cache_path: result.cache_path,
          images: result.inspected_images.map(({ path }) => path),
        },
        result: jsonValueSchema.parse(result),
        rawResult: null,
        confidence: "observed",
        authority: "shipped-artifact",
        environment: null,
        limitations: result.limitations,
      },
    ),
  );
};
