import { z } from "zod";

/** `PLATFORM_*` values from Apple's `mach-o/loader.h`. */
const APPLE_PLATFORM_NAMES: Readonly<Record<number, string>> = {
  1: "macos",
  2: "ios",
  3: "tvos",
  4: "watchos",
  5: "bridgeos",
  6: "maccatalyst",
  7: "ios-simulator",
  8: "tvos-simulator",
  9: "watchos-simulator",
  10: "driverkit",
  11: "visionos",
  12: "visionos-simulator",
};

/** A reported platform number and its `loader.h` name, when known. */
export const applePlatformSchema = z.strictObject({
  id: z.number().int(),
  name: z.string().nullable(),
});

export type ApplePlatform = z.infer<typeof applePlatformSchema>;

/** Name a reported platform number without discarding unknown values. */
export const applePlatform = (id: number): ApplePlatform => ({
  id,
  name: APPLE_PLATFORM_NAMES[id] ?? null,
});

/** Display one platform, falling back to its number. */
export const applePlatformLabel = ({ id, name }: ApplePlatform): string =>
  name ?? `platform ${id}`;
