import type { BinaryTarget } from "../domain/binaryTarget.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { canonicalJson } from "../domain/comparisonSemantics.js";
import { ok, type Result } from "../domain/result.js";
import type { NativeCommandCapture } from "./CommandRunner.js";
import { codesignReason } from "./CodesignVerification.js";
import { parseCodeSignature } from "./parsers/codesign.js";
import { parseSignatureEntitlements } from "./NativeSignatureEntitlements.js";
import {
  signatureArchitectures,
  summarizeSignatureSlices,
} from "./NativeSignatureSlices.js";

/** The provider owns process execution and typed failure translation. */
export type SignatureCapture = (
  argv: readonly string[],
  signal?: AbortSignal,
) => Promise<Result<NativeCommandCapture, AnalysisError>>;

/** Detect explicit unsigned display reasons, not words embedded in echoed pathnames. */
export const unsignedSignatureCapture = (
  capture: NativeCommandCapture,
  path: string,
): boolean =>
  capture.exitCode !== null &&
  capture.exitCode !== 0 &&
  `${capture.stderr}\n${capture.stdout}`
    .split("\n")
    .some((line) =>
      /^(?:code object is not signed at all|code object is not signed|not signed at all)/iu.test(
        codesignReason(line, path),
      ),
    );

/** Slice observations and aggregate knowledge, with every contributing capture retained. */
export interface SignatureSliceObservation {
  readonly mixed: boolean;
  readonly captures: readonly NativeCommandCapture[];
  readonly limitations: readonly string[];
  readonly signed: boolean | undefined;
  readonly classificationUnknown: boolean;
}

/** Proactively inspect independent signatures of universal Mach-O architectures. */
export const inspectSignatureSlices = async (
  target: BinaryTarget,
  input: {
    readonly format: string | null;
    readonly requirements: NativeCommandCapture;
    readonly entitlements: NativeCommandCapture;
    readonly unsigned: boolean;
  },
  capture: SignatureCapture,
  signal?: AbortSignal,
): Promise<Result<SignatureSliceObservation, AnalysisError>> => {
  const architectures = signatureArchitectures(input.format, target);
  const gate =
    !input.unsigned &&
    (unsignedSignatureCapture(input.requirements, target.path) ||
      unsignedSignatureCapture(input.entitlements, target.path));
  if (!gate && architectures.length <= 1)
    return ok({
      mixed: false,
      captures: [],
      limitations: [],
      signed: undefined,
      classificationUnknown: false,
    });
  const captures: NativeCommandCapture[] = [];
  const signed: string[] = [];
  const unsigned: string[] = [];
  const unclassified: string[] = [];
  const postures = new Map<string, string>();
  for (const architecture of architectures) {
    const display = await capture(
      ["-d", "-a", architecture, "--verbose=4", target.path],
      signal,
    );
    if (!display.ok) return display;
    captures.push(display.value);
    if (display.value.exitCode !== 0) {
      (unsignedSignatureCapture(display.value, target.path)
        ? unsigned
        : unclassified
      ).push(architecture);
      continue;
    }
    signed.push(architecture);
    const entitlements = await capture(
      ["-d", "--entitlements", ":-", "-a", architecture, target.path],
      signal,
    );
    if (!entitlements.ok) return entitlements;
    captures.push(entitlements.value);
    const directory = parseCodeSignature(display.value.stderr, false, [
      target.path,
    ]).code_directory;
    if (
      directory?.flags === null ||
      directory === null ||
      entitlements.value.exitCode !== 0
    ) {
      unclassified.push(architecture);
      continue;
    }
    postures.set(
      architecture,
      canonicalJson(
        {
          flags: directory.flags.value,
          platform: directory.platform_identifier,
          entitlements: parseSignatureEntitlements(entitlements.value.stdout)
            .value,
        },
        "Signature slice posture",
      ),
    );
  }
  const summary = summarizeSignatureSlices({
    signed,
    unsigned,
    unclassified,
    postures,
  });
  const limitations: string[] = [];
  if (unsigned.length > 0)
    limitations.push(`Unsigned Mach-O slices: ${unsigned.join(", ")}.`);
  if (summary.postureDiffers)
    limitations.push(
      "Signed Mach-O slices differ in CodeDirectory flags or entitlements; aggregate facets are unknown.",
    );
  if (unclassified.length > 0)
    limitations.push(
      `Signature state could not be classified for Mach-O slices: ${unclassified.join(", ")}.`,
    );
  if (gate && input.requirements.exitCode !== 0)
    limitations.push(
      "The aggregate designated requirement is unavailable because Mach-O slices have mixed signing states.",
    );
  if (gate && input.entitlements.exitCode !== 0)
    limitations.push(
      "The aggregate entitlements are unavailable because Mach-O slices have mixed signing states.",
    );
  return ok({
    ...summary,
    mixed: gate || summary.mixed,
    captures,
    limitations,
  });
};
