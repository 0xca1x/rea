import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

describe("Electron option evidence", () => {
  it("keeps the final explicit preload and service name with unrelated keys", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      new BrowserWindow({ webPreferences: { preload: "./kept.js", sandbox: true }, title: "App" });
      utilityProcess.fork("./worker.js", [], { serviceName: "kept", cwd: "/app" });
    `);

    expect(analysis.parse_status).toBe("complete");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: "./kept.js",
      preload_resolution_context: "module-specifier",
      web_preferences: [
        { name: "preload", value: { status: "literal", value: "./kept.js" } },
        { name: "sandbox", value: { status: "literal", value: true } },
      ],
    });
    expect(analysis.electron.utility_processes[0]).toMatchObject({
      module_path: "./worker.js",
      service_name: "kept",
    });
  });

  it("keeps values unknown when a later computed key can override them", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      new BrowserWindow({ webPreferences: { preload: "./maybe.js" }, [key]: null });
      utilityProcess.fork("./worker.js", [], { serviceName: "maybe", [key]: null });
    `);

    expect(analysis.parse_status).toBe("partial");
    expect(analysis.parse_error_count).toBe(0);
    expect(analysis.limitations.join(" ")).toContain("remain unknown");
    expect(analysis.electron.browser_windows[0]).toMatchObject({
      preload_path: null,
      preload_resolution_context: null,
      web_preferences_status: "dynamic",
      web_preferences: [],
    });
    expect(analysis.electron.utility_processes[0]).toMatchObject({
      module_path: "./worker.js",
      service_name: null,
    });
  });

  it("keeps recovered templates with invalid escapes dynamic", () => {
    const source = [
      "new BrowserWindow({ webPreferences: { sandbox: `",
      String.raw`\unicode`,
      "` } });",
    ].join("");
    const analysis = analyzeJavaScriptStaticSource(source);

    expect(analysis.parse_status).toBe("partial");
    expect(analysis.parse_error_count).toBe(1);
    expect(
      analysis.electron.browser_windows[0]?.web_preferences,
    ).toContainEqual(
      expect.objectContaining({
        name: "sandbox",
        value: expect.objectContaining({ status: "dynamic", value: null }),
      }),
    );
  });
});

describe("Electron effective preload", () => {
  const windowPreload = (webPreferences: string) =>
    analyzeJavaScriptStaticSource(
      `new BrowserWindow({ webPreferences: { ${webPreferences} } });`,
    ).electron.browser_windows[0];

  it.each([
    'preload: "./first.js", preload: runtimePath',
    'preload: "./first.js", ...runtimeOptions',
    'preload: "./first.js", [runtimeKey]: runtimeValue',
    'preload: "./first.js", get preload() { return runtimePath; }',
  ])("leaves the preload unknown after a later override in %s", (source) => {
    expect(windowPreload(source)).toMatchObject({
      preload_path: null,
      preload_resolution_context: null,
      web_preferences: expect.arrayContaining([
        {
          name: "preload",
          value: { status: "literal", value: "./first.js", expression: null },
        },
      ]),
    });
  });

  it.each([
    ['preload: runtimePath, preload: "./first.js"', "./first.js"],
    ['...runtimeOptions, preload: "./first.js"', "./first.js"],
    ['[runtimeKey]: runtimeValue, preload: "./first.js"', "./first.js"],
    ['preload: "./first.js", preload: "./last.js"', "./last.js"],
    ['preload: "./first.js", ["preload"]: "./last.js"', "./last.js"],
    ['preload: "./first.js", sandbox: true', "./first.js"],
  ])("resolves the final static preload in %s", (source, expected) => {
    expect(windowPreload(source)).toMatchObject({
      preload_path: expected,
      preload_resolution_context: "module-specifier",
    });
  });
});
