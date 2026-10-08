import { applePlatformLabel } from "./applePlatforms.js";
import { cacheServes } from "./dyldPaths.js";
import type {
  DylibEdge as Edge,
  DylibFinding as Finding,
  DylibSharedCacheView,
  DylibTrace,
  MachoImageFacts,
  MachoSlice,
} from "./dylibResolution.js";

export const deriveFindings = (
  edges: readonly Edge[],
  roots: DylibTrace["roots"],
  images: ReadonlyMap<string, MachoImageFacts>,
): Finding[] => {
  const findings: Finding[] = [];
  edges.forEach((edge, index) => {
    if (edge.resolution.status === "unresolved")
      findings.push(unresolvedFinding(edge, index));
    if (edge.resolution.status === "unresolved" && edge.loader_conditional) {
      // loader_conditional already qualifies the unresolved explanation.
    }
    const resolvedAt = edge.candidates.findIndex(
      ({ outcome }) => outcome === "resolved" || outcome === "shared-cache",
    );
    const earlierAbsent = edge.candidates
      .slice(0, Math.max(resolvedAt, 0))
      .filter(
        ({ source, outcome }) => source === "rpath" && outcome === "absent",
      )
      .map(({ path }) => path);
    const earlierUnknown = edge.candidates
      .slice(0, Math.max(resolvedAt, 0))
      .some(({ outcome }) =>
        [
          "outside-target",
          "escapes-target",
          "unsupported",
          "undetermined",
        ].includes(outcome),
      );
    const loaderQualifies =
      edge.loader_conditional === true
        ? " This loader itself loads only conditionally; if it never loads, this search never occurs."
        : "";
    const unknownQualifies = earlierUnknown
      ? " An earlier candidate outside the analyzed root may still win at runtime, so this fallback loads only conditionally."
      : "";
    if (resolvedAt > 0 && earlierAbsent.length > 0)
      findings.push({
        kind: "earlier-rpath-candidate-absent",
        edge_index: index,
        image: edge.loader,
        basis: "derived",
        explanation: `dyld searches ${earlierAbsent.join(", ")} before ${edge.resolution.image ?? edge.install_name}. A Mach-O placed at an earlier path would load first unless code-signing library validation rejects it; library validation is not evaluated here (see inspect_signature).${loaderQualifies}${unknownQualifies}`,
      });
  });
  for (const { image, architecture } of roots) {
    const facts = images.get(image);
    const environment =
      facts?.status === "parsed"
        ? (facts.slices.find((slice) => slice.architecture === architecture)
            ?.dyld_environment ?? [])
        : [];
    if (environment.length > 0)
      findings.push({
        kind: "dyld-environment-present",
        edge_index: null,
        image,
        basis: "derived",
        explanation: `${image} (${architecture}) sets dyld environment variables through LC_DYLD_ENVIRONMENT (${environment.join(", ")}); any image-selection overrides they request are not modeled. Diagnostic settings alone do not alter resolution.`,
      });
  }
  return findings;
};

const unresolvedFinding = (edge: Edge, index: number): Finding => {
  const base = {
    edge_index: index,
    image: edge.loader,
    basis: "derived",
  } as const;
  const missing = `No candidate for ${edge.command === "LC_LAZY_LOAD_DYLIB" ? "lazily loaded " : edge.weak ? "weak dependency " : ""}${edge.install_name} exists in the analyzed root`;
  // Below a conditional fallback, every consequence applies only if it loads.
  const when = edge.loader_conditional
    ? `. ${edge.loader} loads only conditionally; if it loads, `
    : "; ";
  if (edge.command === "LC_LAZY_LOAD_DYLIB")
    return {
      ...base,
      kind: "lazy-load-unresolved",
      explanation: `${missing}${when}dyld loads it on first use, which would fail unless the image is supplied elsewhere.`,
    };
  return edge.weak
    ? {
        ...base,
        kind: "weak-load-unresolved",
        explanation: `${missing}${when}dyld continues without it.`,
      }
    : {
        ...base,
        kind: "required-load-unresolved",
        explanation: `${missing}${when}dyld would fail to launch ${edge.root} (${edge.architecture}) unless the image is supplied elsewhere.`,
      };
};

export const DYLIB_RESOLUTION_LIMITATIONS = [
  "LC_LAZY_LOAD_DYLIB dependencies are resolved but not traversed, because dyld loads them only on first use.",
  "Slices are matched by dyld's graded architectures (an x86_64h process also loads x86_64). arm64e processes that disable pointer authentication can also load arm64 slices; that fallback is not modeled.",
  "Leaf and relative install names depend on dyld fallback paths, DYLD_* variables, and the working directory; they are undetermined.",
  "Load order follows dyld's dependents-first traversal in load-command order. An image reached through several chains is resolved once per process, with the rpath stack and conditionality of the first chain; a later request whose install name matches an already loaded image reuses it.",
  "@loader_path uses each image's symlink-resolved path within the analyzed root.",
  "Code-signing checks that can reject a found image, such as library validation and the hardened runtime, are not evaluated.",
  "Dylib compatibility versions are not compared. Apple's linker documentation describes a load-time rejection when an image's compatibility version is older than the loader requires, but dyld on macOS 26 was observed to load such an image.",
];

/** A process root the supplied shared cache cannot answer for. */
export interface UnservedRoot {
  readonly image: string;
  readonly architecture: string;
  readonly reason: string;
}

/**
 * Why the cache cannot serve a process slice, or undefined when it can:
 * dyld maps only a cache built for the process's CPU family and platform.
 */
export const cacheMismatch = (
  cache: DylibSharedCacheView,
  slice: Pick<MachoSlice, "architecture" | "platforms">,
): string | undefined => {
  if (!cacheServes(cache.architecture, slice.architecture))
    return `the ${cache.architecture} cache does not serve ${slice.architecture} processes`;
  if (cache.platforms.length === 0)
    return "the cache header does not record its platform";
  if (slice.platforms.length === 0)
    return "the process records no LC_BUILD_VERSION or LC_VERSION_MIN platform";
  if (
    !slice.platforms.some(({ id }) =>
      cache.platforms.some((platform) => platform.id === id),
    )
  )
    return `the cache serves ${cache.platforms.map(applePlatformLabel).join(" and ")} processes, not ${slice.platforms.map(applePlatformLabel).join(" or ")}`;
  return undefined;
};

export const sharedCacheLimitations = (
  cache: DylibSharedCacheView | undefined,
  unserved: readonly UnservedRoot[],
): string[] => {
  if (cache === undefined)
    return [
      "Absolute install names and rpaths are outside the analyzed root and are not evaluated, including /System and /usr/lib libraries that the dyld shared cache usually provides. Pass shared_cache to look them up in a cache.",
    ];
  return [
    "Absolute install names and rpaths were looked up only in the supplied dyld shared cache; paths it does not list stay outside-target because the host filesystem outside the analyzed root is not read. Shared-cache hits assume no on-disk override (root or unzippered twin) though dyld checks the filesystem first; treat them as conditional when the external disk state is unknown. On another OS build the cache contents, and therefore these outcomes, can differ.",
    ...unserved.map(
      ({ image, architecture, reason }) =>
        `The supplied shared cache was not used for ${image} (${architecture}): ${reason}. Its absolute paths stay outside-target.`,
    ),
    ...(cache.unavailableSubcaches.length === 0
      ? []
      : [
          `Subcaches ${cache.unavailableSubcaches.join(", ")} of the supplied cache are unavailable; install paths listed there are undetermined and reported in coverage.unverified_shared_cache_images.`,
        ]),
  ];
};
