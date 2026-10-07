import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createPackageWithOptions } from "@electron/asar";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { analyzeJavaScriptApplication } from "./JavaScriptApplicationService.js";

describe("JavaScript application failure diagnostics", () => {
  it("identifies the rejected result field in caller-visible diagnostics", async () => {
    const inputPath = await createTestTempDirectory("rea-js-schema-failure-");
    await writeFile(join(inputPath, "main.js"), "export const value = 1;\n");
    const cause = new z.ZodError([
      {
        code: "custom",
        path: ["semantic_graph", "nodes", 42, "application_node_ids", 0],
        message: "Semantic node references an absent application node",
      },
    ]);
    const result = await analyzeJavaScriptApplication(
      { input_path: inputPath, format: "directory" },
      {
        progress: {
          report: async (event) => {
            if (event.terminal) throw cause;
          },
        },
      },
    );

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected analysis failure");
    expect(result.error.cause).toBe(cause);
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "unreadable_output",
      details: {
        operation: "analyze_javascript_application",
        reason:
          "Result schema rejected 1 issue at /semantic_graph/nodes/42/application_node_ids/0 (custom)",
      },
    });
  });

  it("retains unexpected failures and their input identity in caller-visible diagnostics", async () => {
    const inputPath = await createTestTempDirectory("rea-js-failure-");
    await writeFile(join(inputPath, "main.js"), "export const value = 1;\n");
    const cause = new RangeError("Invalid string length");
    const result = await analyzeJavaScriptApplication(
      { input_path: inputPath, format: "directory" },
      {
        progress: {
          report: async (event) => {
            if (event.terminal) throw cause;
          },
        },
      },
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected analysis failure");
    expect(result.error.cause).toBe(cause);
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "execution_failure",
      details: {
        provider_id: "rea-javascript-application",
        operation: "analyze_javascript_application",
        diagnostics: {
          input_path: inputPath,
          error_name: "RangeError",
          error_message: "Invalid string length",
        },
      },
    });
  });

  it("keeps filesystem failures distinct from engine failures", async () => {
    const root = await createTestTempDirectory("rea-js-missing-");
    const result = await analyzeJavaScriptApplication({
      input_path: join(root, "missing"),
      format: "directory",
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected missing artifact failure");
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "artifact_operation_failed",
      details: { operation: "analyze_javascript_application", reason: "io" },
    });
  });

  it.each(["reported failure", null])(
    "retains non-Error failures (%s)",
    async (cause) => {
      const inputPath = await createTestTempDirectory("rea-js-non-error-");
      await writeFile(join(inputPath, "main.js"), "export const value = 1;\n");
      const result = await analyzeJavaScriptApplication(
        { input_path: inputPath, format: "directory" },
        {
          progress: {
            report: async (event) => {
              if (event.terminal) throw cause;
            },
          },
        },
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected analysis failure");
      expect(projectAnalysisError(result.error)).toMatchObject({
        code: "execution_failure",
        details: {
          diagnostics: {
            error_name: "UnknownError",
            error_message:
              typeof cause === "string"
                ? cause
                : "JavaScript analysis failed with a non-Error value",
          },
        },
      });
    },
  );
});

describe("JavaScript application artifact integrity", () => {
  it("analyzes a signed-after-packaging native module only when the mismatch is recorded", async () => {
    const root = await createTestTempDirectory("rea-js-integrity-");
    const source = join(root, "source");
    await mkdir(source);
    await writeFile(
      join(source, "package.json"),
      '{"name":"signed","main":"main.js"}',
    );
    await writeFile(join(source, "main.js"), "require('./addon.node');\n");
    await writeFile(join(source, "addon.node"), "packed native bytes");
    const archive = join(root, "app.asar");
    await createPackageWithOptions(source, archive, { unpack: "*.node" });
    // macOS code signing rewrites unpacked binaries after the archive header
    // has recorded their integrity.
    await writeFile(
      join(`${archive}.unpacked`, "addon.node"),
      "signed native bytes",
    );

    const strict = await analyzeJavaScriptApplication({ input_path: archive });
    expect(strict.ok).toBe(false);
    if (strict.ok) throw new Error("Expected an integrity failure");
    expect(projectAnalysisError(strict.error)).toMatchObject({
      code: "artifact_integrity_mismatch",
      details: { logical_path: "addon.node", unpacked: true },
    });

    const recorded = await analyzeJavaScriptApplication({
      input_path: archive,
      integrity_policy: "record-and-continue",
    });
    expect(recorded.ok).toBe(true);
    if (!recorded.ok) throw new Error("Expected recorded analysis");
    expect(recorded.value.parameters).toEqual({
      format: "auto",
      integrity_policy: "record-and-continue",
    });
    expect(recorded.value.normalized_result).toMatchObject({
      format: "asar",
      integrity_contradictions: [
        {
          logical_path: "addon.node",
          unpacked: true,
          trust: "observed-untrusted",
        },
      ],
      limitations: expect.arrayContaining([
        "1 artifact file(s) contradict declared integrity; their observed bytes are untrusted, and contradicted nested archives were not expanded.",
      ]),
    });
  });
});
