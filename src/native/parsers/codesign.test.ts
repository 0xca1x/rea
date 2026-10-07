import { describe, expect, it } from "vitest";

import { parseCodeSignature } from "./codesign.js";

const display = (lines: readonly string[]): string =>
  [
    "Identifier=com.example.fixture",
    "Format=app bundle with Mach-O thin (arm64)",
    ...lines,
    "TeamIdentifier=TEAM12345",
    "",
  ].join("\n");

describe("codesign CodeDirectory parsing", () => {
  it("decodes CodeDirectory fields and flags from the numeric value", () => {
    const parsed = parseCodeSignature(
      display([
        "CodeDirectory v=20500 size=443 flags=0x12a00(kill,restrict,library-validation,runtime) hashes=3209+7 location=embedded",
        "Platform identifier=26",
        "Hash type=sha256 size=32",
        "Executable Segment flags=0x1",
        "Runtime Version=26.4.0",
        "Sealed Resources version=2 rules=13 files=290",
      ]),
      false,
    );
    expect(parsed.code_directory).toEqual({
      version: "20500",
      flags: {
        value: 0x12a00,
        names: ["kill", "restrict", "library-validation", "runtime"],
      },
      code_slots: 3209,
      special_slots: 7,
      location: "embedded",
      hash_type: "sha256",
      platform_identifier: 26,
      runtime_version: "26.4.0",
      executable_segment_flags: 1,
    });
    expect(parsed.hardened_runtime).toBe(true);
    expect(parsed.sealed_resources).toEqual({
      status: "sealed",
      version: 2,
      rules: 13,
      files: 290,
    });
  });

  it("reports unsealed, unsigned and incomplete output without guessing", () => {
    const bare = parseCodeSignature(
      display([
        "CodeDirectory v=20400 size=336 location=embedded",
        "Sealed Resources=none",
      ]),
      false,
    );
    expect(bare.code_directory).toMatchObject({
      flags: null,
      code_slots: null,
      platform_identifier: null,
    });
    expect(bare.sealed_resources.status).toBe("none");
    expect(parseCodeSignature(display([]), false)).toMatchObject({
      code_directory: null,
      sealed_resources: { status: "unknown" },
    });
    expect(
      parseCodeSignature("fixture: code object is not signed at all\n", true),
    ).toMatchObject({
      signed: false,
      code_directory: null,
      sealed_resources: { status: "none" },
      stapled_ticket: { status: "not-applicable" },
    });
  });
});
