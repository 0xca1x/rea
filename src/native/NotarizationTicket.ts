/** Bounded positional reader used to inspect local ticket framing. */
export type TicketReadAt = (
  offset: number,
  length: number,
) => Promise<Uint8Array>;

/**
 * Inspect the local s8ch/g8tk ticket framing. Observed in stapled app tickets;
 * see https://www.mothersruin.com/software/Archaeology/reverse/tickets.html.
 * This does not authenticate certificates, signatures, or notarized cdhashes.
 */
export const ticketStructureIssue = async (
  read: TicketReadAt,
  size: number,
): Promise<string | null> => {
  const header = Buffer.from(await read(0, 16));
  if (header.length !== 16 || header.toString("ascii", 0, 4) !== "s8ch")
    return "Not a recognized s8ch notarization ticket container";
  if (header.readUInt32LE(4) !== 1)
    return `Unsupported notarization ticket container version ${header.readUInt32LE(4)}`;
  const certificateSize = header.readUInt32LE(8);
  const contentSize = header.readUInt32LE(12);
  const contentOffset = 16 + certificateSize;
  const signatureOffset = contentOffset + contentSize;
  if (certificateSize < 4 || contentSize < 24 || signatureOffset >= size)
    return "Ticket certificate, content, or signature extent is missing or truncated";
  const content = Buffer.from(await read(contentOffset, 24));
  if (content.length !== 24 || content.toString("ascii", 0, 4) !== "g8tk")
    return "Ticket content has no complete g8tk header";
  const hashSize = content.readUInt16LE(6);
  const hashCount = content.readUInt32LE(8);
  if (
    hashSize === 0 ||
    hashCount === 0 ||
    24 + (hashSize + 1) * hashCount !== contentSize
  )
    return "Ticket hash records disagree with the declared content length";
  const certificates = await derSequenceExtent(read, 16, certificateSize);
  if (certificates !== certificateSize)
    return "Ticket certificate block has malformed DER framing";
  const signatureFieldSize = 72;
  if (size - signatureOffset !== signatureFieldSize)
    return "Ticket signature field is truncated or does not contain exactly 72 bytes";
  const signatureSize = await derSequenceExtent(
    read,
    signatureOffset,
    signatureFieldSize,
  );
  if (signatureSize === null || signatureSize < 8)
    return "Ticket signature has malformed DER framing";
  // The fixed signature field contains DER followed by zero padding.
  const paddingSize = size - signatureOffset - signatureSize;
  const padding = await read(signatureOffset + signatureSize, paddingSize);
  if (padding.byteLength !== paddingSize || padding.some((byte) => byte !== 0))
    return "Ticket has malformed signature padding";
  return null;
};

/** Read only a DER SEQUENCE tag/length and check its extent against its section. */
const derSequenceExtent = async (
  read: TicketReadAt,
  offset: number,
  available: number,
): Promise<number | null> => {
  const prefix = Buffer.from(await read(offset, Math.min(6, available)));
  if (prefix.length < 2 || prefix[0] !== 0x30) return null;
  const first = prefix[1] ?? 0;
  if (first < 128) return first + 2 <= available ? first + 2 : null;
  const width = first & 0x7f;
  if (width === 0 || width > 4 || prefix.length < width + 2 || prefix[2] === 0)
    return null;
  let length = 0;
  for (let index = 0; index < width; index++)
    length = length * 256 + (prefix[index + 2] ?? 0);
  return length >= 128 && length + width + 2 <= available
    ? length + width + 2
    : null;
};
