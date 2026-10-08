import { expect, it } from "vitest";
import { notarizationTicketFixture } from "../../tests/fixtures/notarizationTicket.js";
import { ticketStructureIssue } from "./NotarizationTicket.js";

const inspect = (bytes: Uint8Array) =>
  ticketStructureIssue(
    async (offset, length) => bytes.subarray(offset, offset + length),
    bytes.length,
  );

it("recognizes local ticket framing without claiming cryptographic validity", async () => {
  expect(await inspect(notarizationTicketFixture())).toBeNull();
});

it("rejects empty, arbitrary, truncated and contradictory ticket containers", async () => {
  expect(await inspect(new Uint8Array())).toContain("Not a recognized");
  expect(await inspect(Buffer.from("stapled ticket bytes"))).toContain(
    "Not a recognized",
  );
  const ticket = Buffer.from(notarizationTicketFixture());
  expect(await inspect(ticket.subarray(0, ticket.length - 1))).toContain(
    "signature",
  );
  ticket.writeUInt32LE(2, 16 + 4 + 8);
  expect(await inspect(ticket)).toContain("hash records disagree");
});
