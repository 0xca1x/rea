import { z } from "zod";

import { applePlatformSchema } from "./applePlatforms.js";
import { digestSchema } from "../digests.js";
import { machoSliceSchema } from "./dylibResolution.js";

const hexSchema = z.string().regex(/^0x[0-9a-f]+$/u);
const uuidSchema = z
  .string()
  .regex(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u);

/** One cached image selected by its exact install path. */
export const inspectDyldSharedCacheInputSchema = z.strictObject({
  cache_path: z.string().min(1),
  images: z.array(z.string().min(1)).min(1).optional(),
});

const mappingSchema = z.object({
  file: z.string(),
  address: hexSchema,
  size: hexSchema,
  file_offset: hexSchema,
  max_protection: z.number().int(),
  initial_protection: z.number().int(),
});

const subcacheSchema = z.object({
  suffix: z.string(),
  uuid: uuidSchema,
  vm_offset: hexSchema,
  status: z.enum(["present", "missing", "uuid-mismatch"]),
  observed_uuid: uuidSchema.nullable(),
});

const headerSchema = z.object({
  magic: z.string(),
  architecture: z.string(),
  uuid: z.string(),
  platform: applePlatformSchema.nullable(),
  /** Producer platform fields before simulator-family normalization. */
  header_platform: applePlatformSchema.nullable().default(null),
  header_alt_platform: applePlatformSchema.nullable().default(null),
  simulator: z.boolean().nullable().default(null),
  os_version: z.string().nullable(),
  alt_platform: applePlatformSchema.nullable(),
  alt_os_version: z.string().nullable(),
  cache_type: z.enum(["development", "production", "multi-cache"]).nullable(),
  cache_subtype: z
    .object({
      id: z.number().int().nonnegative(),
      name: z.enum(["development", "production"]).nullable(),
    })
    .nullable()
    .default(null)
    .describe(
      "Multi-cache subtype from the producer header: 0 is development, 1 is production; unknown values retain their ID with a null name. Null when absent or not applicable.",
    ),
  shared_region: z.object({ start: hexSchema, size: hexSchema }).nullable(),
  max_slide: hexSchema.nullable(),
  mappings: z.array(mappingSchema),
  subcaches: z.array(subcacheSchema),
  symbols_file_uuid: uuidSchema.nullable(),
});

const inspectedImageSchema = z.object({
  path: z.string(),
  status: z.enum(["parsed", "malformed", "unsupported", "absent", "unmapped"]),
  address: hexSchema.nullable(),
  file: z.string().nullable(),
  reason: z.string().nullable(),
  slices: z.array(machoSliceSchema),
});

/** Header, mappings, subcaches, and the complete image list of one cache. */
export const dyldSharedCacheResultSchema = z.object({
  cache_path: z.string(),
  main_file_sha256: digestSchema,
  ...headerSchema.shape,
  images_total: z.number().int().nonnegative(),
  images: z.array(z.object({ path: z.string(), address: hexSchema })),
  inspected_images: z.array(inspectedImageSchema),
  /** SHA-256 of every readable subcache backing inspected images, keyed by suffix. */
  subcache_sha256: z.record(z.string(), digestSchema).default({}),
  coverage: z.object({
    status: z.enum(["complete", "partial"]),
    unreadable_subcaches: z.array(z.string()),
  }),
  limitations: z.array(z.string()),
});

export type DyldCacheMapping = z.infer<typeof mappingSchema>;
export type DyldCacheSubcache = z.infer<typeof subcacheSchema>;
export type DyldSharedCacheHeader = z.infer<typeof headerSchema>;
export type DyldSharedCacheResult = z.infer<typeof dyldSharedCacheResultSchema>;
export type InspectedCacheImage = z.infer<typeof inspectedImageSchema>;

/** Limitations that bound claims made from one cache file set. */
export const DYLD_SHARED_CACHE_LIMITATIONS = [
  "The cache describes the operating system it was built for; it is evidence about this cache file set, not about another host.",
  "Image headers are read through the cache's VM mappings; slide info, local symbols, and code signatures are not parsed, and images are not extracted.",
  "Install paths are matched exactly against the cache image table; dyld alias canonicalization is not modeled, so an alias may report absent or undetermined though dyld would load it from the cache.",
];
