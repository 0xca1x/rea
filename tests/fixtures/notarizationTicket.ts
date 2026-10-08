/** Synthetic local ticket framing; it does not contain an authenticated certificate/signature. */
export const notarizationTicketFixture = (): Uint8Array => {
  const certificates = Buffer.from([0x30, 2, 0x30, 0]);
  const content = Buffer.alloc(45);
  content.write("g8tk", 0, "ascii");
  content.writeUInt16LE(2, 4);
  content.writeUInt16LE(20, 6);
  content.writeUInt32LE(1, 8);
  content[24] = 2;
  content.fill(0xab, 25);
  const signature = Buffer.alloc(72);
  signature.set([0x30, 6, 2, 1, 1, 2, 1, 1]);
  const header = Buffer.alloc(16);
  header.write("s8ch", 0, "ascii");
  header.writeUInt32LE(1, 4);
  header.writeUInt32LE(certificates.length, 8);
  header.writeUInt32LE(content.length, 12);
  return Buffer.concat([header, certificates, content, signature]);
};
