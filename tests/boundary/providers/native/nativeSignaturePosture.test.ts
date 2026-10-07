import { createHash } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { NativeMacOSProvider } from "../../../../src/native/NativeMacOSProvider.js";
import { ok } from "../../../../src/domain/result.js";
import { inspectSignatureSchema } from "../../../../src/domain/nativeInspection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  NativeFixtureRunner as FixtureRunner,
  nativeMachoTarget as machoTarget,
} from "../../../fixtures/nativeCommands.js";

/** Fail only strict verification, as a tampered bundle does. */
class TamperedRunner extends FixtureRunner {
  override async run(tool: string, arguments_: readonly string[]) {
    const result = await super.run(tool, arguments_);
    if (!result.ok || arguments_[0] !== "--verify") return result;
    const stderr =
      "--prepared:/Applications/Fixture.app/Contents/XPCServices/B.xpc\n--validated:/Applications/Fixture.app/Contents/XPCServices/B.xpc\n--validated:/Applications/Fixture.app/Contents/PlugIns/A.appex\n/Applications/Fixture.app: a sealed resource is missing or invalid\nfile modified: /Applications/Fixture.app/Contents/Resources/en.lproj/Main.nib\n";
    return ok({
      ...result.value,
      stdout: "",
      stderr,
      stdoutBytes: 0,
      stderrBytes: Buffer.byteLength(stderr),
      exitCode: 1,
    });
  }
}

const fixtureApp = async (ticket: string | undefined) => {
  const directory = await createTestTempDirectory("rea-signature-posture-");
  const app = join(directory, "Fixture.app");
  const executable = join(app, "Contents/MacOS/Fixture");
  await mkdir(join(app, "Contents/MacOS"), { recursive: true });
  await writeFile(executable, "fixture");
  if (ticket !== undefined)
    await writeFile(join(app, "Contents/CodeResources"), ticket);
  return { app, executable };
};

describe("native signature posture", () => {
  it("verifies the opened bundle and reports a stapled ticket", async () => {
    const ticket = "stapled ticket bytes";
    const { app, executable } = await fixtureApp(ticket);
    const signature = await new NativeMacOSProvider(
      new FixtureRunner(),
      "darwin",
    )
      .createClient(machoTarget(executable, app))
      .execute("inspect_signature", {});

    expect(signature.ok).toBe(true);
    if (!signature.ok) return;
    const result = inspectSignatureSchema.parse(signature.value.result);
    expect(result.code_directory).toMatchObject({
      version: "20500",
      flags: { value: 0x10000, names: ["runtime"] },
      code_slots: 10,
      special_slots: 7,
    });
    expect(result.verification).toMatchObject({
      path: app,
      status: "valid",
      exit_code: 0,
    });
    expect(result.stapled_ticket).toEqual({
      status: "present",
      path: "Contents/CodeResources",
      sha256: createHash("sha256").update(ticket).digest("hex"),
      size: ticket.length,
      reason: null,
    });
    expect(
      Object.fromEntries(
        result.security_facets.map(({ facet, state }) => [facet, state]),
      ),
    ).toEqual({
      "library-validation": "enforced",
      "dyld-environment-variables": "ignored",
      "debugger-attach": "blocked",
      "executable-memory": "restricted",
      "app-sandbox": "sandboxed",
    });
    expect(result.provenance.map(({ command }) => command[1])).toContain(
      "--verify",
    );
  });

  it("keeps a failed strict verification as an observation", async () => {
    const { app, executable } = await fixtureApp(undefined);
    const signature = await new NativeMacOSProvider(
      new TamperedRunner(),
      "darwin",
    )
      .createClient(machoTarget(executable, app))
      .execute("inspect_signature", {});

    expect(signature.ok).toBe(true);
    if (!signature.ok) return;
    const result = inspectSignatureSchema.parse(signature.value.result);
    expect(result.verification).toEqual({
      path: app,
      status: "invalid",
      exit_code: 1,
      diagnostics: [
        "/Applications/Fixture.app: a sealed resource is missing or invalid",
        "file modified: /Applications/Fixture.app/Contents/Resources/en.lproj/Main.nib",
      ],
      validated_nested_code: [
        "/Applications/Fixture.app/Contents/PlugIns/A.appex",
        "/Applications/Fixture.app/Contents/XPCServices/B.xpc",
      ],
    });
    expect(result.stapled_ticket.status).toBe("absent");
  });

  it("does not look for a stapled ticket beside a bare Mach-O", async () => {
    const directory = await createTestTempDirectory("rea-signature-bare-");
    const executable = join(directory, "tool");
    await writeFile(executable, "fixture");
    const signature = await new NativeMacOSProvider(
      new FixtureRunner(),
      "darwin",
    )
      .createClient(machoTarget(executable))
      .execute("inspect_signature", {});
    expect(signature.ok && signature.value.result).toMatchObject({
      verification: { path: executable },
      stapled_ticket: { status: "not-applicable" },
    });
  });

  it.skipIf(process.getuid?.() === 0)(
    "keeps inspecting when the stapled ticket cannot be read",
    async () => {
      const { app, executable } = await fixtureApp("ticket");
      const ticket = join(app, "Contents/CodeResources");
      await chmod(ticket, 0o000);
      try {
        const signature = await new NativeMacOSProvider(
          new FixtureRunner(),
          "darwin",
        )
          .createClient(machoTarget(executable, app))
          .execute("inspect_signature", {});
        expect(signature.ok && signature.value.result).toMatchObject({
          stapled_ticket: {
            status: "unreadable",
            path: "Contents/CodeResources",
            sha256: null,
            reason: "EACCES",
          },
          verification: { status: "valid" },
        });
      } finally {
        await chmod(ticket, 0o644);
      }
    },
  );

  it("reports unsigned nested code inside a signed bundle as invalid", async () => {
    const { app, executable } = await fixtureApp(undefined);
    const signature = await new NativeMacOSProvider(
      new UnsignedNestedRunner(),
      "darwin",
    )
      .createClient(machoTarget(executable, app))
      .execute("inspect_signature", {});
    expect(signature.ok && signature.value.result).toMatchObject({
      signed: true,
      verification: { status: "invalid", exit_code: 1 },
    });
  });
});

/** A signed bundle whose nested helper is unsigned. */
class UnsignedNestedRunner extends FixtureRunner {
  override async run(tool: string, arguments_: readonly string[]) {
    const result = await super.run(tool, arguments_);
    if (!result.ok || arguments_[0] !== "--verify") return result;
    const stderr =
      "/Applications/Fixture.app/Contents/Helpers/tool: code object is not signed at all\nIn subcomponent: /Applications/Fixture.app/Contents/Helpers/tool\n";
    return ok({
      ...result.value,
      stdout: "",
      stderr,
      stdoutBytes: 0,
      stderrBytes: Buffer.byteLength(stderr),
      exitCode: 1,
    });
  }
}
