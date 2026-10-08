import { expect, it } from "vitest";
import { unconfirmedNestedCode } from "./NativeNestedCode.js";

it("observes cancellation between nested filesystem lookups", async () => {
  const controller = new AbortController();
  const paths: string[] = [];
  await expect(
    unconfirmedNestedCode(
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
  const warnings = await unconfirmedNestedCode(
    { prepared_nested_code: ["/app/odd"], validated_nested_code: [] },
    undefined,
    {
      lookup: async () => {
        throw Object.assign(new Error("not found"), { code: "ENOENT" });
      },
      names: async () => [],
    },
  );
  expect(warnings).toContainEqual(
    expect.stringContaining(
      'prepared nested code at "/app/odd", which does not exist',
    ),
  );
});
