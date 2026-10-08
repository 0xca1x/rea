import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createPackageWithOptions } from "@electron/asar";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { analyzeJavaScriptApplication } from "./JavaScriptApplicationService.js";
import {
  compareApplicationVersionsEvidence,
  compareJavaScriptExportShapesEvidence,
  traceApplicationFeatureEvidence,
} from "./JavaScriptApplicationWorkflowService.js";

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
    // Retain the original failure locally, but never serialize its object graph.
    cause.cause = cause;
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
    const projection = projectAnalysisError(result.error);
    expect(JSON.parse(JSON.stringify(projection))).toEqual(projection);
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

  it.each([new Error("x".repeat(10_000)), "y".repeat(10_000)])(
    "preserves long failure messages through JSON projection (%#)",
    async (cause) => {
      const inputPath = await createTestTempDirectory("rea-js-oversized-");
      await writeFile(join(inputPath, "main.js"), "export const value = 1;\n");
      const message = cause instanceof Error ? cause.message : cause;
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
            error_message: message,
          },
        },
      });
      const projection = projectAnalysisError(result.error);
      expect(JSON.parse(JSON.stringify(projection))).toEqual(projection);
    },
  );
});

const CONTRADICTION_LIMITATION =
  "Observed bytes of 1 artifact file(s) contradict declared integrity and are untrusted: addon.node.";

describe("JavaScript application artifact integrity", () => {
  it("analyzes a signed-after-packaging native module only when the mismatch is recorded", async () => {
    const root = await createTestTempDirectory("rea-js-integrity-");
    const source = join(root, "source");
    await mkdir(source);
    await writeFile(
      join(source, "package.json"),
      '{"name":"signed","main":"main.js"}',
    );
    await writeFile(
      join(source, "main.js"),
      "require('./addon.node'); export function value() { return {status: 'ready'}; }\n",
    );
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
      graph: { coverage: { status: "partial" } },
      limitations: expect.arrayContaining([CONTRADICTION_LIMITATION]),
      semantic_graph: {
        limitations: expect.arrayContaining([CONTRADICTION_LIMITATION]),
      },
    });

    // Workflows built on the recorded graph inherit its partial coverage.
    const clean = await analyzeJavaScriptApplication({
      input_path: source,
      format: "directory",
    });
    if (!clean.ok) throw new Error("Expected clean analysis");
    const comparison = compareApplicationVersionsEvidence({
      left: clean.value,
      right: recorded.value,
    });
    expect(comparison.ok).toBe(true);
    if (!comparison.ok) throw new Error("Expected comparison");
    expect(comparison.value.normalized_result).toMatchObject({
      coverage: { status: "partial", right_graph_status: "partial" },
      limitations: expect.arrayContaining([CONTRADICTION_LIMITATION]),
    });
    const shapes = compareJavaScriptExportShapesEvidence({
      left: clean.value,
      right: recorded.value,
      left_module_path: "main.js",
      left_export_name: "value",
      right_module_path: "main.js",
      right_export_name: "value",
    });
    expect(shapes.ok).toBe(true);
    if (!shapes.ok) throw shapes.error;
    expect(shapes.value.normalized_result).toMatchObject({
      coverage: { status: "partial" },
      limitations: expect.arrayContaining([CONTRADICTION_LIMITATION]),
    });
    const trace = traceApplicationFeatureEvidence({
      application: recorded.value,
      seed: { kind: "string", value: "nonexistent-feature" },
      direction: "outgoing",
    });
    expect(trace.ok).toBe(true);
    if (!trace.ok) throw trace.error;
    expect(trace.value.normalized_result).toMatchObject({
      graph: null,
      limitations: expect.arrayContaining([CONTRADICTION_LIMITATION]),
    });
  });
});
