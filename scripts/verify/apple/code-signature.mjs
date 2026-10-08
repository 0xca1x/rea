import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import {
  artifactCli,
  artifactMcpResult,
  withArtifactMcp,
} from "../../lib/artifact-e2e.mjs";
import {
  buildMacosBundleFixture,
  preflightMacosBundleFixture,
} from "../../fixtures/apple/macos-bundle.mjs";

const exec = promisify(execFile);

const args = process.argv.slice(2);
if (args.length !== 0 && (args.length !== 2 || args[0] !== "--stapled-app"))
  throw new Error("Usage: verify:code-signature [--stapled-app PATH]");
const stapledApp = args[1];
if (stapledApp !== undefined) {
  try {
    await exec("/usr/bin/xcrun", ["--find", "stapler"]);
  } catch (cause) {
    throw new Error("Real stapled-ticket verification requires xcrun stapler", {
      cause,
    });
  }
}

await preflightMacosBundleFixture();
const root = await mkdtemp(join(tmpdir(), "rea-code-signature-"));

const facets = (signature) =>
  Object.fromEntries(
    signature.security_facets.map(({ facet, state }) => [facet, state]),
  );

/** Re-sign a copy of one fixture executable ad hoc with the given options. */
const signedCopy = async (source, name, options) => {
  const path = join(root, name);
  await copyFile(source, path);
  await exec("/usr/bin/xcrun", [
    "codesign",
    "--force",
    "--sign",
    "-",
    ...options,
    path,
  ]);
  return path;
};

const ENTITLEMENTS = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.cs.disable-library-validation</key><true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<key>com.apple.security.get-task-allow</key><true/>
<key>com.apple.security.cs.allow-jit</key><true/>
</dict></plist>
`;

try {
  const { app } = await buildMacosBundleFixture(root);
  let realTicket = {
    status: "unverified",
    reason:
      "No known stapled app supplied; use --stapled-app PATH to exercise producer output.",
  };
  if (stapledApp !== undefined) {
    const appPath = await realpath(stapledApp);
    const oracle = await exec("/usr/bin/xcrun", [
      "stapler",
      "validate",
      appPath,
    ]);
    const observed = await artifactCli("inspect-signature", appPath);
    assert.equal(
      observed.stapled_ticket.status,
      "present",
      JSON.stringify(observed.stapled_ticket),
    );
    assert.equal(observed.stapled_ticket.reason, null);
    assert.match(observed.stapled_ticket.sha256, /^[a-f0-9]{64}$/u);
    await withArtifactMcp(appPath, async (client) => {
      const viaMcp = await artifactMcpResult(client, "inspect_signature");
      assert.deepEqual(viaMcp.stapled_ticket, observed.stapled_ticket);
    });
    realTicket = {
      status: "verified",
      selected_app: stapledApp,
      ticket_sha256: observed.stapled_ticket.sha256,
      size: observed.stapled_ticket.size,
      oracle: "xcrun stapler validate",
      stdout: oracle.stdout,
      stderr: oracle.stderr,
    };
  }
  const plain = await artifactCli("inspect-signature", app);
  assert.deepEqual(plain.code_directory.flags.names, ["adhoc"]);
  assert.equal(plain.verification.status, "valid");
  // The opened bundle is reported by its canonical path.
  assert.equal(plain.verification.path, await realpath(app));
  assert.equal(plain.stapled_ticket.status, "absent");
  assert.equal(plain.sealed_resources.status, "sealed");
  assert.deepEqual(facets(plain), {
    "library-validation": "not-enforced",
    "dyld-environment-variables": "honored",
    "debugger-attach": "allowed",
    "executable-memory": "unrestricted",
    "app-sandbox": "not-sandboxed",
  });
  // Deep verification reports the fixture's real nested code, all on disk.
  assert.ok(plain.verification.validated_nested_code.length > 0);
  assert.ok(
    !plain.limitations.some((limitation) =>
      limitation.includes("which does not exist"),
    ),
  );
  await withArtifactMcp(app, async (client) => {
    const viaMcp = await artifactMcpResult(client, "inspect_signature");
    const semantic = (value) => ({
      ...value,
      provenance: [],
      verification: {
        ...value.verification,
        raw_stdout: "",
        raw_stderr: "",
      },
    });
    assert.deepEqual(semantic(viaMcp), semantic(plain));
  });

  const tool = join(app, "Contents/Helpers/rea-tool");
  const hardened = await artifactCli(
    "inspect-signature",
    await signedCopy(tool, "hardened", ["--options", "runtime"]),
  );
  assert.deepEqual(hardened.code_directory.flags.names, ["adhoc", "runtime"]);
  assert.equal(hardened.stapled_ticket.status, "not-applicable");
  assert.deepEqual(facets(hardened), {
    "library-validation": "enforced",
    "dyld-environment-variables": "ignored",
    "debugger-attach": "blocked",
    "executable-memory": "restricted",
    "app-sandbox": "not-sandboxed",
  });

  const entitlements = join(root, "relaxed.entitlements");
  await writeFile(entitlements, ENTITLEMENTS);
  const relaxed = await artifactCli(
    "inspect-signature",
    await signedCopy(tool, "relaxed", [
      "--options",
      "runtime",
      "--entitlements",
      entitlements,
    ]),
  );
  assert.deepEqual(facets(relaxed), {
    "library-validation": "disabled",
    "dyld-environment-variables": "honored",
    "debugger-attach": "allowed",
    "executable-memory": "jit-allowed",
    "app-sandbox": "not-sandboxed",
  });

  const flagged = await artifactCli(
    "inspect-signature",
    await signedCopy(tool, "flagged", ["--options", "library,restrict"]),
  );
  assert.deepEqual(flagged.code_directory.flags.names, [
    "adhoc",
    "restrict",
    "library-validation",
  ]);
  assert.equal(facets(flagged)["library-validation"], "enforced");
  assert.equal(facets(flagged)["dyld-environment-variables"], "ignored");

  const platform = await artifactCli("inspect-signature", "/usr/bin/true");
  assert.notEqual(platform.code_directory.platform_identifier, null);
  assert.equal(platform.verification.status, "valid");
  assert.equal(facets(platform)["library-validation"], "enforced");
  // The platform rules rest on a real `anchor apple` requirement check.
  assert.ok(
    platform.provenance.some(({ command }) =>
      command.includes("-R=anchor apple"),
    ),
  );

  // Only deep verification sees a file added inside nested code.
  const nested = join(root, "Nested.app");
  await exec("/usr/bin/ditto", [app, nested]);
  await writeFile(
    join(nested, "Contents/XPCServices/Svc.xpc/Contents/added.txt"),
    "unsealed",
  );
  const nestedTamper = await artifactCli("inspect-signature", nested);
  assert.equal(nestedTamper.verification.status, "invalid");
  assert.ok(
    nestedTamper.verification.diagnostics.some((line) =>
      line.includes("Svc.xpc"),
    ),
    JSON.stringify(nestedTamper.verification),
  );

  await mkdir(join(app, "Contents/Resources"), { recursive: true });
  await writeFile(join(app, "Contents/Resources/added.txt"), "unsealed");
  const tampered = await artifactCli("inspect-signature", app);
  assert.equal(tampered.verification.status, "invalid");
  assert.ok(
    tampered.verification.diagnostics.some((line) => line.includes("added")),
    JSON.stringify(tampered.verification),
  );

  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      mocked: false,
      cli: true,
      stdio_mcp: true,
      variants: [
        "adhoc",
        "runtime",
        "runtime+entitlements",
        "library,restrict",
      ],
      platform_identifier: platform.code_directory.platform_identifier,
      tampered_verification: tampered.verification.status,
      nested_tamper_verification: nestedTamper.verification.status,
      real_stapled_ticket: realTicket,
    })}\n`,
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
