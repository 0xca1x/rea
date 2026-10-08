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
