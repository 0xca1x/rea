import { type CodeDirectory } from "../../domain/native/codeSigningPosture.js";
import { codeDirectoryFlagNames } from "../CodeSigningPolicy.js";
import {
  inspectSignatureSchema,
  type InspectSignature,
} from "../../domain/native/nativeInspection.js";

/**
 * Parse bounded `codesign -d --verbose=4` diagnostics, which Apple emits on
 * stderr. codesign echoes the executable path and signing identifier
 * verbatim, and an ad hoc identifier derives from the file name, so either
 * can contain line breaks and text that resembles other fields. The path is
 * removed by its exact value from `executablePaths`, and the identifier runs
 * to the `Format=` field that codesign prints after it.
 */
export const parseCodeSignature = (
  output: string,
  unsigned: boolean,
  executablePaths: readonly string[] = [],
): Omit<InspectSignature, "provenance"> => {
  const { identifier, fields } = splitEchoedValues(
    output.replaceAll("\r\n", "\n"),
    executablePaths,
  );
  const values = new Map<string, string>();
  const authorities: string[] = [];
  const cdhashes: string[] = [];
  let sealed: InspectSignature["sealed_resources"] = {
    status: "unknown",
    version: null,
    rules: null,
    files: null,
  };
  for (const line of fields.split("\n")) {
    if (line.startsWith("CodeDirectory ")) {
      values.set("CodeDirectory", line.slice("CodeDirectory ".length));
      continue;
    }
    if (line.startsWith("Sealed Resources")) {
      sealed = parseSealedResources(line);
      continue;
    }
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (key === "Authority") authorities.push(value);
    else if (key === "CDHash") cdhashes.push(value);
    else values.set(key, value);
  }
  const parsed = inspectSignatureSchema.omit({ provenance: true }).parse({
    signed: !unsigned,
    identifier: identifier ?? null,
    team_identifier: nullableCodeSignValue(values.get("TeamIdentifier")),
    format: values.get("Format") ?? null,
    cdhashes,
    hash_algorithms: splitAlgorithms(values.get("Hash choices")),
    authorities,
    designated_requirement: values.get("designated") ?? null,
    entitlements: null,
    timestamp: values.get("Timestamp") ?? null,
    hardened_runtime: parseRuntime(values.get("CodeDirectory")),
    code_directory: unsigned ? null : parseCodeDirectory(values),
    sealed_resources: unsigned
      ? { status: "none", version: null, rules: null, files: null }
      : sealed,
    verification: null,
    stapled_ticket: {
      status: "not-applicable",
      path: null,
      sha256: null,
      size: null,
      reason: null,
    },
    security_facets: [],
    limitations: unsigned
      ? ["Artifact is not signed."]
      : [
          "Entitlements and designated requirements require separate bounded commands.",
        ],
  });
  return parsed;
};

/**
 * Separate the echoed executable path and signing identifier, which codesign
 * prints first, from the fields that follow them.
 */
const splitEchoedValues = (
  text: string,
  executablePaths: readonly string[],
): { readonly identifier: string | undefined; readonly fields: string } => {
  const executable = executablePaths
    .map((path) => `Executable=${path}\n`)
    .find((line) => text.startsWith(line));
  let rest = text;
  if (executable !== undefined) rest = text.slice(executable.length);
  else if (text.startsWith("Executable=")) {
    const identifierLine = text.indexOf("\nIdentifier=");
    rest = identifierLine < 0 ? text : text.slice(identifierLine + 1);
  }
  if (!rest.startsWith("Identifier="))
    return { identifier: undefined, fields: rest };
  // Later fields come from the signature itself, so the last `Format=` line
  // is the one codesign printed after the identifier.
  const format = rest.lastIndexOf("\nFormat=");
  const lineEnd = rest.indexOf("\n");
  const end = format >= 0 ? format : lineEnd >= 0 ? lineEnd : rest.length;
  return {
    identifier: rest.slice("Identifier=".length, end),
    fields: rest.slice(end),
  };
};

const nullableCodeSignValue = (value: string | undefined): string | null =>
  value === undefined || value === "not set" ? null : value;

const splitAlgorithms = (value: string | undefined): string[] =>
  value === undefined
    ? []
    : value
        .split(/[,+\s]+/u)
        .map((part) => part.trim())
        .filter((part) => part.length > 0);

const parseRuntime = (value: string | undefined): boolean | null => {
  if (value === undefined) return null;
  const flags = /(?:^|\s)flags=[^(]*\(([^)]*)\)/u.exec(value)?.[1];
  if (flags === undefined) return null;
  return flags.split(",").some((flag) => flag.trim() === "runtime");
};

const integerField = (
  text: string | undefined,
  pattern: RegExp,
  radix = 10,
): number | null => {
  const match = text === undefined ? undefined : pattern.exec(text)?.[1];
  if (match === undefined) return null;
  const value = Number.parseInt(match, radix);
  return Number.isSafeInteger(value) ? value : null;
};

/**
 * `CodeDirectory v=20500 size=… flags=0x10000(runtime) hashes=3209+7
 * location=embedded`, plus the separate hash, platform, runtime-version and
 * executable-segment lines. Flag names are decoded from the numeric value.
 */
const parseCodeDirectory = (
  values: ReadonlyMap<string, string>,
): CodeDirectory | null => {
  const line = values.get("CodeDirectory");
  if (line === undefined) return null;
  const flags = integerField(line, /(?:^|\s)flags=0x([0-9a-f]+)/iu, 16);
  return {
    version: /(?:^|\s)v=(\S+)/u.exec(line)?.[1] ?? null,
    flags:
      flags === null
        ? null
        : { value: flags, names: codeDirectoryFlagNames(flags) },
    code_slots: integerField(line, /(?:^|\s)hashes=(\d+)\+/u),
    special_slots: integerField(line, /(?:^|\s)hashes=\d+\+(\d+)/u),
    location: /(?:^|\s)location=(\S+)/u.exec(line)?.[1] ?? null,
    hash_type: values.get("Hash type")?.split(/\s+/u)[0] ?? null,
    platform_identifier: integerField(
      values.get("Platform identifier"),
      /^(\d+)$/u,
    ),
    runtime_version: values.get("Runtime Version") ?? null,
    executable_segment_flags: integerField(
      values.get("Executable Segment flags"),
      /^0x([0-9a-f]+)$/iu,
      16,
    ),
  };
};

/** `Sealed Resources version=2 rules=13 files=290` or `Sealed Resources=none`. */
const parseSealedResources = (
  line: string,
): InspectSignature["sealed_resources"] => {
  if (/^Sealed Resources\s*=\s*none$/u.test(line.trim()))
    return { status: "none", version: null, rules: null, files: null };
  return {
    status: "sealed",
    version: integerField(line, /\sversion=(\d+)/u),
    rules: integerField(line, /\srules=(\d+)/u),
    files: integerField(line, /\sfiles=(\d+)/u),
  };
};
