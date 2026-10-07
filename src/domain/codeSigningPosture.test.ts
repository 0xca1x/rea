import { describe, expect, it } from "vitest";

import {
  codeDirectoryFlagNames,
  deriveSecurityFacets,
  type CodeDirectory,
} from "./codeSigningPosture.js";

const directory = (
  flags: number | null,
  platform: number | null = null,
): CodeDirectory => ({
  version: "20500",
  flags:
    flags === null
      ? null
      : { value: flags, names: codeDirectoryFlagNames(flags) },
  code_slots: 1,
  special_slots: 7,
  location: "embedded",
  hash_type: "sha256",
  platform_identifier: platform,
  runtime_version: null,
  executable_segment_flags: 1,
});

type PostureInput = Parameters<typeof deriveSecurityFacets>[0];

const derive = (
  input: Omit<PostureInput, "mixedSlices" | "appleOrigin"> &
    Partial<PostureInput>,
) => deriveSecurityFacets({ mixedSlices: false, appleOrigin: false, ...input });

const states = (facets: ReturnType<typeof deriveSecurityFacets>) =>
  Object.fromEntries(facets.map(({ facet, state }) => [facet, state]));

const RUNTIME = 0x10000;

describe("CodeDirectory flags", () => {
  it("names known bits and keeps unknown bits numeric", () => {
    expect(codeDirectoryFlagNames(0x12a02)).toEqual([
      "adhoc",
      "kill",
      "restrict",
      "library-validation",
      "runtime",
    ]);
    expect(codeDirectoryFlagNames(0x40000 | 0x2)).toEqual(["adhoc", "0x40000"]);
  });
});

describe("derived security facets", () => {
  it("treats unsigned and plain ad hoc code as unrestricted", () => {
    for (const signed of [false, true])
      expect(
        states(
          derive({
            signed,
            codeDirectory: signed ? directory(0x2) : null,
            entitlements: null,
            entitlementsKnown: true,
          }),
        ),
      ).toEqual({
        "library-validation": "not-enforced",
        "dyld-environment-variables": "honored",
        "debugger-attach": "allowed",
        "executable-memory": "unrestricted",
        "app-sandbox": "not-sandboxed",
      });
  });

  it("restricts hardened-runtime code unless entitlements relax it", () => {
    expect(
      states(
        derive({
          signed: true,
          codeDirectory: directory(RUNTIME),
          entitlements: { "com.apple.security.app-sandbox": true },
          entitlementsKnown: true,
        }),
      ),
    ).toEqual({
      "library-validation": "enforced",
      "dyld-environment-variables": "ignored",
      "debugger-attach": "blocked",
      "executable-memory": "restricted",
      "app-sandbox": "sandboxed",
    });
    const relaxed = derive({
      signed: true,
      codeDirectory: directory(RUNTIME),
      entitlements: {
        "com.apple.security.cs.disable-library-validation": true,
        "com.apple.security.cs.allow-dyld-environment-variables": true,
        "com.apple.security.get-task-allow": true,
        "com.apple.security.cs.allow-jit": true,
      },
      entitlementsKnown: true,
    });
    expect(states(relaxed)).toMatchObject({
      "library-validation": "disabled",
      "dyld-environment-variables": "honored",
      "debugger-attach": "allowed",
      "executable-memory": "jit-allowed",
    });
    expect(relaxed[0]?.evidence).toEqual([
      "hardened runtime",
      "com.apple.security.cs.disable-library-validation",
    ]);
  });

  it("lets explicit flags and platform identity override entitlements", () => {
    const flagged = derive({
      signed: true,
      codeDirectory: directory(0x2000 | 0x800 | RUNTIME),
      entitlements: {
        "com.apple.security.cs.disable-library-validation": true,
      },
      entitlementsKnown: true,
    });
    expect(states(flagged)).toMatchObject({
      "library-validation": "enforced",
      "dyld-environment-variables": "ignored",
    });
    expect(
      states(
        derive({
          signed: true,
          codeDirectory: directory(RUNTIME, 26),
          entitlements: null,
          entitlementsKnown: true,
          appleOrigin: true,
        }),
      ),
    ).toMatchObject({
      "library-validation": "enforced",
      "dyld-environment-variables": "ignored",
      "debugger-attach": "blocked",
    });
  });
});

describe("security facets that need more than one CodeDirectory", () => {
  it("applies platform policy only to Apple-signed platform identifiers", () => {
    const crafted = derive({
      signed: true,
      codeDirectory: directory(0, 26),
      entitlements: null,
      entitlementsKnown: true,
    });
    expect(states(crafted)).toMatchObject({
      "library-validation": "unknown",
      "dyld-environment-variables": "unknown",
      "debugger-attach": "unknown",
    });
    expect(crafted[0]?.evidence).toEqual([
      "platform identifier",
      "Apple origin not verified",
    ]);
  });

  it("leaves every facet unknown when slices differ in signing state", () => {
    const mixed = derive({
      signed: true,
      codeDirectory: directory(0x2000 | RUNTIME, 26),
      entitlements: null,
      entitlementsKnown: false,
      appleOrigin: true,
      mixedSlices: true,
    });
    expect(new Set(mixed.map(({ state }) => state))).toEqual(
      new Set(["unknown"]),
    );
    expect(mixed[0]?.evidence).toEqual([
      "architecture slices differ in signing state",
    ]);
  });

  it("keeps facets unknown when flags or entitlements are unavailable", () => {
    expect(
      states(
        derive({
          signed: true,
          codeDirectory: directory(RUNTIME),
          entitlements: null,
          entitlementsKnown: false,
        }),
      ),
    ).toEqual({
      "library-validation": "unknown",
      "dyld-environment-variables": "unknown",
      "debugger-attach": "unknown",
      "executable-memory": "unknown",
      "app-sandbox": "unknown",
    });
    expect(
      states(
        derive({
          signed: true,
          codeDirectory: directory(null),
          entitlements: null,
          entitlementsKnown: true,
        }),
      ),
    ).toMatchObject({
      "library-validation": "unknown",
      "dyld-environment-variables": "unknown",
      "debugger-attach": "unknown",
      "executable-memory": "unknown",
    });
  });
});
