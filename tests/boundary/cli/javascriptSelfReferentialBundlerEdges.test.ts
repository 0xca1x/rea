import { expect } from "vitest";

import { parseEvidence } from "../../../src/domain/evidence.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest, type TestCli } from "../../support/cli/cliFixture.js";
import { writeFixtureFiles } from "../../support/javascriptApplicationFixture.js";

const chunk = (ids: readonly number[], modules: string): string =>
  `"use strict";(self.webpackChunkdemo=self.webpackChunkdemo||[]).push([[${ids.join(",")}],{${modules}}]);\n`;

const analyze = async (
  cli: TestCli,
  files: Readonly<Record<string, string>>,
) => {
  const root = await createTestTempDirectory("rea-self-bundler-");
  await writeFixtureFiles(root, files);
  const output = await cli.run({
    arguments: ["analyze-javascript-application", root, "--json"],
  });
  expect(output.exitCode, JSON.stringify(output.json)).toBe(0);
  const result = javascriptApplicationAnalysisResultSchema.parse(
    parseEvidence(output.json).normalized_result,
  );
  expect(
    result.graph.edges.filter(
      (edge) => edge.source_node_id === edge.target_node_id,
    ),
  ).toEqual([]);
  expect(result.limitations).toEqual(
    expect.arrayContaining(result.graph.limitations),
  );
  return result.graph;
};

cliTest(
  "omits a chunk's request for its own id while keeping sibling chunk requests",
  async ({ cli }) => {
    const graph = await analyze(cli, {
      "1.js": chunk(
        [1],
        "10(e,t,r){r.e(1).then(r.bind(r,11));r.e(2)},11(e,t,r){r.r(t)}",
      ),
      "2.js": chunk([2], "20(e,t,r){r.r(t)}"),
      "3.js": chunk(
        [3, 4],
        "30(e,t,r){r.e(4).then(r.bind(r,31))},31(e,t,r){r.r(t)}",
      ),
    });
    expect(graph.limitations).toContainEqual(
      expect.stringMatching(
        /^2 bundler async-chunk requests resolved back to the requesting chunk itself and were omitted;/u,
      ),
    );
    expect(
      graph.edges
        .filter(({ properties }) => properties.kind === "bundler-async-chunk")
        .map(({ properties }) => properties.chunk_key),
    ).toEqual(["2"]);
  },
);

cliTest(
  "omits a bundled module's require of its own key while keeping sibling requires",
  async ({ cli }) => {
    const graph = await analyze(cli, {
      "5.js": chunk([5], "50(e,t,r){r(50);r(51)},51(e,t,r){r.r(t)}"),
    });
    expect(graph.limitations).toContainEqual(
      expect.stringMatching(
        /^1 static reference resolved back to the referencing module itself and was omitted;/u,
      ),
    );
    expect(
      graph.edges.some(
        ({ relation, properties }) =>
          relation === "imports" && properties.specifier === "51",
      ),
    ).toBe(true);
  },
);
