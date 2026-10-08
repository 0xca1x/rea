import { z } from "zod";

/** Observed signing-directory metadata; policy interpretation belongs to the adapter. */
export const codeDirectorySchema = z.object({
  version: z.string().nullable(),
  flags: z
    .object({
      value: z.number().int().nonnegative(),
      names: z.array(z.string()),
    })
    .nullable(),
  code_slots: z.number().int().nonnegative().nullable(),
  special_slots: z.number().int().nonnegative().nullable(),
  location: z.string().nullable(),
  hash_type: z.string().nullable(),
  platform_identifier: z.number().int().nonnegative().nullable(),
  runtime_version: z.string().nullable(),
  executable_segment_flags: z.number().int().nonnegative().nullable(),
});

/** Observed sealed-resource summary. */
export const sealedResourcesSchema = z.object({
  status: z.enum(["sealed", "none", "unknown"]),
  version: z.number().int().nullable(),
  rules: z.number().int().nullable(),
  files: z.number().int().nullable(),
});

/** Local verification observation; unknown is distinct from a proven invalid signature. */
export const signatureVerificationSchema = z.object({
  path: z.string(),
  status: z.enum(["valid", "invalid", "unsigned", "unknown"]),
  exit_code: z.number().int().nullable(),
  diagnostics: z.array(z.string()),
  validated_nested_code: z.array(z.string()),
});

/** Local ticket presence and content identity, without a remote notarization claim. */
export const stapledTicketSchema = z.object({
  status: z.enum(["present", "absent", "unreadable", "not-applicable"]),
  path: z.string().nullable(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .nullable(),
  size: z.number().int().nonnegative().nullable(),
  reason: z.string().nullable(),
});

const facetSchema = z.discriminatedUnion("facet", [
  z.object({
    facet: z.literal("library-validation"),
    state: z.enum(["enforced", "disabled", "not-enforced", "unknown"]),
    basis: z.literal("derived"),
    evidence: z.array(z.string()),
    explanation: z.string(),
  }),
  z.object({
    facet: z.literal("dyld-environment-variables"),
    state: z.enum(["ignored", "honored", "unknown"]),
    basis: z.literal("derived"),
    evidence: z.array(z.string()),
    explanation: z.string(),
  }),
  z.object({
    facet: z.literal("debugger-attach"),
    state: z.enum(["allowed", "blocked", "unknown"]),
    basis: z.literal("derived"),
    evidence: z.array(z.string()),
    explanation: z.string(),
  }),
  z.object({
    facet: z.literal("executable-memory"),
    state: z.enum([
      "restricted",
      "jit-allowed",
      "unsigned-allowed",
      "protection-disabled",
      "unrestricted",
      "unknown",
    ]),
    basis: z.literal("derived"),
    evidence: z.array(z.string()),
    explanation: z.string(),
  }),
  z.object({
    facet: z.literal("app-sandbox"),
    state: z.enum(["sandboxed", "not-sandboxed", "unknown"]),
    basis: z.literal("derived"),
    evidence: z.array(z.string()),
    explanation: z.string(),
  }),
]);

/** Shared result semantics; adapters determine each facet's policy and evidence. */
export const securityFacetsSchema = z.array(facetSchema);
export type CodeDirectory = z.infer<typeof codeDirectorySchema>;
export type SecurityFacet = z.infer<typeof facetSchema>;
