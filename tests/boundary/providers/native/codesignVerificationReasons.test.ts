import { expect, it } from "vitest";
import { signatureVerification } from "../../../../src/native/CodesignVerification.js";
import { NativeFixtureRunner } from "../../../fixtures/nativeCommands.js";

it.each(["permission denied", "I/O error", "EACCES"])(
  "does not classify echoed pathname %s as an I/O failure",
  async (text) => {
    const path = `/Applications/${text}.app`;
    const capture = await new NativeFixtureRunner().run("codesign", [
      "--verify",
      path,
    ]);
    if (!capture.ok) throw capture.error;
    const observed = signatureVerification(
      {
        ...capture.value,
        exitCode: 1,
        stderr: `${path}: a sealed resource is missing or invalid\n`,
      },
      path,
      false,
    );
    expect(observed.status).toBe("invalid");
    expect(observed.diagnostics).toEqual([
      `${path}: a sealed resource is missing or invalid`,
    ]);
  },
);

it("keeps operational, unsigned, definite invalid and unrecognized failures distinct", async () => {
  const path = "/Applications/Fixture.app";
  const capture = await new NativeFixtureRunner().run("codesign", [
    "--verify",
    path,
  ]);
  if (!capture.ok) throw capture.error;
  const status = (reason: string, unsigned = false) =>
    signatureVerification(
      { ...capture.value, exitCode: 1, stderr: `${path}: ${reason}\n` },
      path,
      unsigned,
    ).status;
  expect(status("permission denied")).toBe("unknown");
  expect(status("I/O error")).toBe("unknown");
  expect(status("invalid signature")).toBe("invalid");
  expect(status("code object is not signed at all", true)).toBe("unsigned");
  expect(status("code object is not signed at all")).toBe("invalid");
  expect(status("unrecognized failure")).toBe("unknown");
});
