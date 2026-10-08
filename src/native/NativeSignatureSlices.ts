import type { BinaryTarget } from "../domain/binaryTarget.js";

/** Architectures to probe, retaining subtypes from codesign and target inventory. */
export const signatureArchitectures = (
  format: string | null,
  target: BinaryTarget,
): string[] => {
  const universal = /^Mach-O universal \(([^)\r\n]+)\)$/u.exec(
    format ?? "",
  )?.[1];
  const declared =
    universal?.split(/\s+/u).filter((name) => name.length > 0) ?? [];
  const available =
    target.kind === "executable" && target.format === "mach-o"
      ? target.availableArchitectures.map((name) =>
          name === "x86" ? "i386" : name,
        )
      : [];
  return [...new Set([...declared, ...available])];
};

/** Aggregate signing knowledge, keeping inconclusive probes distinct from unsigned. */
export const summarizeSignatureSlices = (input: {
  readonly signed: readonly string[];
  readonly unsigned: readonly string[];
  readonly unclassified: readonly string[];
  readonly postures: ReadonlyMap<string, string>;
}): {
  readonly signed: boolean | undefined;
  readonly mixed: boolean;
  readonly postureDiffers: boolean;
  readonly classificationUnknown: boolean;
} => {
  const classificationUnknown = input.unclassified.length > 0;
  const postureDiffers = new Set(input.postures.values()).size > 1;
  const signed =
    input.signed.length > 0
      ? true
      : classificationUnknown || input.unsigned.length === 0
        ? undefined
        : false;
  return {
    signed,
    classificationUnknown,
    postureDiffers,
    mixed:
      classificationUnknown ||
      (input.signed.length > 0 && input.unsigned.length > 0) ||
      postureDiffers,
  };
};
