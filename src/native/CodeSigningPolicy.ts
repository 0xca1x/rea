import type { JsonValue } from "../domain/jsonValue.js";
import type {
  CodeDirectory,
  SecurityFacet,
} from "../domain/native/codeSigningPosture.js";

/** `SecCodeSignatureFlags` bits that codesign reports in a CodeDirectory. */
const CODE_DIRECTORY_FLAGS: readonly (readonly [number, string])[] = [
  [0x1, "host"],
  [0x2, "adhoc"],
  [0x100, "hard"],
  [0x200, "kill"],
  [0x400, "expires"],
  [0x800, "restrict"],
  [0x1000, "enforcement"],
  [0x2000, "library-validation"],
  [0x10000, "runtime"],
  [0x20000, "linker-signed"],
];

/** Decode CodeDirectory flag bits; unknown bits keep their hexadecimal value. */
export const codeDirectoryFlagNames = (value: number): string[] => {
  const flags = value >>> 0;
  const names = CODE_DIRECTORY_FLAGS.flatMap(([bit, name]) =>
    (flags & bit) === 0 ? [] : [name],
  );
  const known = CODE_DIRECTORY_FLAGS.reduce((total, [bit]) => total | bit, 0);
  for (let index = 0; index < 32; index++)
    if (((flags >>> index) & 1) === 1 && ((known >>> index) & 1) === 0)
      names.push(`0x${(2 ** index).toString(16)}`);
  return names;
};

const entitlement = (
  entitlements: JsonValue | null,
  key: string,
): boolean | undefined => {
  if (
    entitlements === null ||
    typeof entitlements !== "object" ||
    Array.isArray(entitlements)
  )
    return undefined;
  const value = entitlements[key];
  return typeof value === "boolean" ? value : undefined;
};

interface PostureInput {
  readonly signed: boolean;
  readonly codeDirectory: CodeDirectory | null;
  readonly entitlements: JsonValue | null;
  /** False when mixed or unreadable signing states hide the aggregate entitlements. */
  readonly entitlementsKnown: boolean;
  /** Architecture slices differ in signing state, so no one CodeDirectory describes the process. */
  readonly mixedSlices: boolean;
  /**
   * The signature satisfies `anchor apple`. Only then does a CodeDirectory
   * platform identifier mean an Apple platform binary.
   */
  readonly appleOrigin: boolean;
  /**
   * The local `--deep --strict` verification failed for the opened code.
   * Flag bits from an unauthenticated CodeDirectory must not decide facets.
   */
  readonly signatureInvalid?: boolean;
}

/** Whether the CodeDirectory claims a platform binary, and whether Apple signed it. */
const platformBinary = (
  input: PostureInput,
): "apple" | "unverified" | "none" =>
  (input.codeDirectory?.platform_identifier ?? null) === null
    ? "none"
    : input.appleOrigin
      ? "apple"
      : "unverified";

const UNVERIFIED_PLATFORM = [
  "platform identifier",
  "Apple origin not verified",
] as const;

const has = (input: PostureInput, flag: string): boolean =>
  input.codeDirectory?.flags?.names.includes(flag) === true;

const libraryValidation = (input: PostureInput): SecurityFacet => {
  const base = { facet: "library-validation", basis: "derived" } as const;
  const explanation =
    "With library validation, the process loads only libraries signed by Apple or by the same team; without it, any library dyld finds can load.";
  if (!input.signed)
    return {
      ...base,
      state: "not-enforced",
      evidence: ["unsigned"],
      explanation,
    };
  if (input.codeDirectory === null || input.codeDirectory.flags === null)
    return {
      ...base,
      state: "unknown",
      evidence: ["CodeDirectory flags unavailable"],
      explanation,
    };
  const platform = platformBinary(input);
  if (platform !== "none")
    return platform === "apple"
      ? {
          ...base,
          state: "enforced",
          evidence: ["platform binary"],
          explanation,
        }
      : {
          ...base,
          state: "unknown",
          evidence: [...UNVERIFIED_PLATFORM],
          explanation,
        };
  if (has(input, "library-validation"))
    return {
      ...base,
      state: "enforced",
      evidence: ["CodeDirectory flag library-validation"],
      explanation,
    };
  if (!has(input, "runtime"))
    return {
      ...base,
      state: "not-enforced",
      evidence: ["no hardened runtime or library-validation flag"],
      explanation,
    };
  if (!input.entitlementsKnown)
    return {
      ...base,
      state: "unknown",
      evidence: ["hardened runtime", "entitlements unavailable"],
      explanation,
    };
  return entitlement(
    input.entitlements,
    "com.apple.security.cs.disable-library-validation",
  ) === true
    ? {
        ...base,
        state: "disabled",
        evidence: [
          "hardened runtime",
          "com.apple.security.cs.disable-library-validation",
        ],
        explanation,
      }
    : {
        ...base,
        state: "enforced",
        evidence: ["hardened runtime"],
        explanation,
      };
};

const dyldEnvironment = (input: PostureInput): SecurityFacet => {
  const base = {
    facet: "dyld-environment-variables",
    basis: "derived",
  } as const;
  const explanation =
    "Whether dyld honors DYLD_* variables such as DYLD_INSERT_LIBRARIES at launch. setuid/setgid bits, a __RESTRICT segment, and system integrity policy can also restrict them and are not evaluated here.";
  if (has(input, "restrict"))
    return {
      ...base,
      state: "ignored",
      evidence: ["CodeDirectory flag restrict"],
      explanation,
    };
  const platform = platformBinary(input);
  if (platform !== "none")
    return platform === "apple"
      ? {
          ...base,
          state: "ignored",
          evidence: ["platform binary"],
          explanation,
        }
      : {
          ...base,
          state: "unknown",
          evidence: [...UNVERIFIED_PLATFORM],
          explanation,
        };
  if (!has(input, "runtime"))
    return input.signed && (input.codeDirectory?.flags ?? null) === null
      ? {
          ...base,
          state: "unknown",
          evidence: ["CodeDirectory flags unavailable"],
          explanation,
        }
      : {
          ...base,
          state: "honored",
          evidence: ["no hardened runtime"],
          explanation,
        };
  if (!input.entitlementsKnown)
    return {
      ...base,
      state: "unknown",
      evidence: ["hardened runtime", "entitlements unavailable"],
      explanation,
    };
  return entitlement(
    input.entitlements,
    "com.apple.security.cs.allow-dyld-environment-variables",
  ) === true
    ? {
        ...base,
        state: "honored",
        evidence: [
          "hardened runtime",
          "com.apple.security.cs.allow-dyld-environment-variables",
        ],
        explanation,
      }
    : {
        ...base,
        state: "ignored",
        evidence: ["hardened runtime"],
        explanation,
      };
};

const debuggerAttach = (input: PostureInput): SecurityFacet => {
  const base = { facet: "debugger-attach", basis: "derived" } as const;
  const explanation =
    "Whether a debugger running as the same user can obtain the task port. Developer Tools authorization and system integrity policy still apply.";
  if (
    input.entitlementsKnown &&
    entitlement(input.entitlements, "com.apple.security.get-task-allow") ===
      true
  )
    return {
      ...base,
      state: "allowed",
      evidence: ["com.apple.security.get-task-allow"],
      explanation,
    };
  const platform = platformBinary(input);
  if (platform !== "none")
    return platform === "apple"
      ? {
          ...base,
          state: "blocked",
          evidence: ["platform binary"],
          explanation,
        }
      : {
          ...base,
          state: "unknown",
          evidence: [...UNVERIFIED_PLATFORM],
          explanation,
        };
  if (has(input, "runtime"))
    return input.entitlementsKnown
      ? {
          ...base,
          state: "blocked",
          evidence: ["hardened runtime without get-task-allow"],
          explanation,
        }
      : {
          ...base,
          state: "unknown",
          evidence: ["hardened runtime", "entitlements unavailable"],
          explanation,
        };
  if (input.signed && (input.codeDirectory?.flags ?? null) === null)
    return {
      ...base,
      state: "unknown",
      evidence: ["CodeDirectory flags unavailable"],
      explanation,
    };
  return {
    ...base,
    state: "allowed",
    evidence: ["no hardened runtime"],
    explanation,
  };
};

const executableMemory = (input: PostureInput): SecurityFacet => {
  const base = { facet: "executable-memory", basis: "derived" } as const;
  const explanation =
    "Hardened-runtime limits on writable or unsigned executable memory, relaxed by code-signing entitlements.";
  if (!has(input, "runtime"))
    return input.signed && (input.codeDirectory?.flags ?? null) === null
      ? {
          ...base,
          state: "unknown",
          evidence: ["CodeDirectory flags unavailable"],
          explanation,
        }
      : {
          ...base,
          state: "unrestricted",
          evidence: ["no hardened runtime"],
          explanation,
        };
  if (!input.entitlementsKnown)
    return {
      ...base,
      state: "unknown",
      evidence: ["hardened runtime", "entitlements unavailable"],
      explanation,
    };
  for (const [key, state] of [
    [
      "com.apple.security.cs.disable-executable-page-protection",
      "protection-disabled",
    ],
    [
      "com.apple.security.cs.allow-unsigned-executable-memory",
      "unsigned-allowed",
    ],
    ["com.apple.security.cs.allow-jit", "jit-allowed"],
  ] as const)
    if (entitlement(input.entitlements, key) === true)
      return {
        ...base,
        state,
        evidence: ["hardened runtime", key],
        explanation,
      };
  return {
    ...base,
    state: "restricted",
    evidence: ["hardened runtime"],
    explanation,
  };
};

const appSandbox = (input: PostureInput): SecurityFacet => {
  const base = { facet: "app-sandbox", basis: "derived" } as const;
  const explanation =
    "Whether the App Sandbox entitlement confines the process.";
  if (!input.entitlementsKnown)
    return {
      ...base,
      state: "unknown",
      evidence: ["entitlements unavailable"],
      explanation,
    };
  return entitlement(input.entitlements, "com.apple.security.app-sandbox") ===
    true
    ? {
        ...base,
        state: "sandboxed",
        evidence: ["com.apple.security.app-sandbox"],
        explanation,
      }
    : {
        ...base,
        state: "not-sandboxed",
        evidence: ["no com.apple.security.app-sandbox entitlement"],
        explanation,
      };
};

/** Derive launch-time security facets from observed flags and entitlements. */
export const deriveSecurityFacets = (input: PostureInput): SecurityFacet[] => {
  const facets = [
    libraryValidation(input),
    dyldEnvironment(input),
    debuggerAttach(input),
    executableMemory(input),
    appSandbox(input),
  ];
  // An invalid main signature leaves flag bits unauthenticated; keep the raw
  // CodeDirectory fields but report every facet as unknown.
  if (input.signatureInvalid === true)
    return facets.map((facet) => ({
      ...facet,
      state: "unknown" as const,
      evidence: ["signature verification failed"],
    }));
  // Each slice runs under its own signature; the inspected one does not
  // describe an unsigned slice of the same file.
  return input.mixedSlices
    ? facets.map((facet) => ({
        ...facet,
        state: "unknown" as const,
        evidence: ["architecture slices differ in signing state"],
      }))
    : facets;
};
