import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import {
  artifactCli,
  artifactMcpResult,
  withArtifactMcp,
} from "../../lib/artifact-e2e.mjs";

const exec = promisify(execFile);

if (process.platform !== "darwin")
  throw new Error(
    "Installer package verification requires macOS pkgbuild, productbuild and pkgutil",
  );
for (const tool of [
  "/usr/bin/pkgbuild",
  "/usr/bin/productbuild",
  "/usr/sbin/pkgutil",
])
  try {
    await exec(tool, ["--help"]);
  } catch (cause) {
    if (cause?.code === "ENOENT")
      throw new Error(`Installer package verification requires ${tool}`, {
        cause,
      });
  }

const root = await mkdtemp(join(tmpdir(), "rea-installer-package-"));
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** Inventory occurrences keyed by logical path, with each node's content digest. */
const inventoryOf = (inspection) => {
  const inventory = inspection.substeps[0].evidence.normalized_result;
  const nodes = new Map(
    inventory.nodes.map((node) => [node.artifact_id, node]),
  );
  return {
    inventory,
    entries: new Map(
      inventory.occurrences.map((occurrence) => [
        occurrence.logical_path,
        { ...occurrence, sha256: nodes.get(occurrence.artifact_id)?.sha256 },
      ]),
    ),
  };
};

/** Apple's Bom listing of a component package's payload, without the root. */
const bomPaths = async (path) =>
  (await exec("/usr/sbin/pkgutil", ["--payload-files", path])).stdout
    .split("\n")
    .filter((line) => line.length > 0 && line !== ".")
    .map((line) => line.replace(/^\.\//u, ""))
    .sort();

try {
  const payload = join(root, "payload");
  const scripts = join(root, "scripts");
  await mkdir(join(payload, "usr/local/rea"), { recursive: true });
  await mkdir(scripts);
  await writeFile(join(payload, "usr/local/rea/hello.txt"), "hello\n");
  for (const name of ["preinstall", "postinstall"]) {
    await writeFile(join(scripts, name), `#!/bin/sh\necho ${name}\n`);
    await chmod(join(scripts, name), 0o755);
  }
  const component = join(root, "Component.pkg");
  const build = (output, extra) =>
    exec("/usr/bin/pkgbuild", [
      "--quiet",
      "--root",
      payload,
      "--identifier",
      "com.example.rea.installer",
      "--version",
      "1.0",
      "--install-location",
      "/",
      ...extra,
      output,
    ]);
  await build(component, ["--scripts", scripts]);
  const product = join(root, "Product.pkg");
  await exec("/usr/bin/productbuild", [
    "--quiet",
    "--package",
    component,
    product,
  ]);
  const pbzx = join(root, "Latest.pkg");
  await build(pbzx, ["--compression", "latest", "--min-os-version", "13.0"]);

  const componentInventory = inventoryOf(
    await artifactCli("inspect-artifact", component),
  );
  assert.equal(componentInventory.inventory.manifest.root_format, "pkg");
  const payloadPaths = [...componentInventory.entries.keys()]
    .filter((path) => path.startsWith("Payload/"))
    .map((path) => path.slice("Payload/".length))
    .sort();
  assert.deepEqual(
    payloadPaths,
    await bomPaths(component),
    "Payload members differ from pkgutil",
  );
  assert.equal(
    componentInventory.entries.get("Payload/usr/local/rea/hello.txt")?.sha256,
    sha256("hello\n"),
  );
  for (const name of ["preinstall", "postinstall"]) {
    const script = componentInventory.entries.get(`Scripts/${name}`);
    assert.equal(script?.sha256, sha256(`#!/bin/sh\necho ${name}\n`));
    assert.equal(script?.executable, true);
  }
  assert.ok(componentInventory.entries.has("PackageInfo"));
  assert.ok(componentInventory.entries.has("Bom"));

  const productInventory = inventoryOf(
    await artifactCli("inspect-artifact", product),
  );
  assert.ok(productInventory.entries.has("Distribution"));
  assert.equal(
    productInventory.entries.get(
      "Component.pkg/Payload/usr/local/rea/hello.txt",
    )?.sha256,
    sha256("hello\n"),
  );
  assert.ok(productInventory.entries.has("Component.pkg/Scripts/postinstall"));

  const pbzxInventory = inventoryOf(
    await artifactCli("inspect-artifact", pbzx),
  );
  const pbzxPayload = pbzxInventory.entries.get("Payload");
  assert.ok(
    pbzxPayload?.limitations.some((line) => line.includes("pbzx")),
    JSON.stringify(pbzxPayload),
  );
  assert.ok(
    ![...pbzxInventory.entries.keys()].some((path) =>
      path.startsWith("Payload/"),
    ),
  );

  await withArtifactMcp(component, async (client) => {
    const viaMcp = inventoryOf(
      await artifactMcpResult(client, "inspect_artifact"),
    );
    assert.deepEqual(
      viaMcp.inventory.manifest,
      componentInventory.inventory.manifest,
    );
  });

  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      mocked: false,
      cli: true,
      stdio_mcp: true,
      payload_members: payloadPaths.length,
      matches_pkgutil_bom: true,
      product_nested: true,
      pbzx_payload: "recorded-not-expanded",
    })}\n`,
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
