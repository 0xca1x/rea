import { expect, it } from "vitest";
import { inspectNestedCodePaths } from "./NativeNestedCode.js";

it("observes cancellation between nested filesystem lookups", async () => {
  const controller = new AbortController();
  const paths: string[] = [];
  await expect(
    inspectNestedCodePaths(
      {
        validated_nested_code: ["/app/first", "/app/second"],
      },
      controller.signal,
      {
        lookup: async (path) => {
          paths.push(path);
          controller.abort();
        },
        names: async () => [],
      },
    ),
  ).rejects.toMatchObject({ name: "AbortError" });
  expect(paths).toEqual(["/app/first"]);
});

it("checks prepared-only fragments with the same completeness rules", async () => {
  const warnings = await inspectNestedCodePaths(
    { prepared_nested_code: ["/app/odd"], validated_nested_code: [] },
    undefined,
    {
      lookup: async () => {
        throw Object.assign(new Error("not found"), { code: "ENOENT" });
      },
      names: async () => [],
    },
  );
  expect(warnings.limitations).toContainEqual(
    expect.stringContaining(
      'prepared nested code at "/app/odd", which does not exist',
    ),
  );
});

it.each(["EACCES", "EPERM", "EIO", "ESTALE"])(
  "keeps observed records when path lookup fails with %s",
  async (code) => {
    const result = await inspectNestedCodePaths(
      {
        prepared_nested_code: ["/app/first"],
        validated_nested_code: ["/app/second"],
      },
      undefined,
      {
        lookup: async () => {
          throw Object.assign(new Error("lookup failed"), { code });
        },
        names: async () => [],
      },
    );
    expect(result.limitations).toHaveLength(2);
    expect(result.limitations.every((message) => message.includes(code))).toBe(
      true,
    );
    expect(result.progressAmbiguous).toBe(true);
  },
);
it("detects newline ambiguity even when the reported first fragment does not exist", async () => {
  const result = await inspectNestedCodePaths(
    { prepared_nested_code: ["/app/odd"], validated_nested_code: [] },
    undefined,
    {
      lookup: async () => {
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
      },
      names: async () => ["odd\n/app: invalid signature"],
    },
  );
  expect(result.progressAmbiguous).toBe(true);
});
