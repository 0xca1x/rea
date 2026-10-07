/** xar archives and cpio payloads built field by field for installer-package tests. */
import { createHash } from "node:crypto";
import { deflateSync, gzipSync } from "node:zlib";

export interface XarFixtureMember {
  readonly name: string;
  readonly type?: "file" | "directory" | "symlink";
  readonly data?: Uint8Array;
  readonly encoding?: "raw" | "zlib" | "bzip2";
  readonly link?: string;
  readonly mode?: string;
  /** Replace the declared extracted checksum, to model tampering. */
  readonly extractedSha1?: string;
  readonly children?: readonly XarFixtureMember[];
}

const sha1 = (bytes: Uint8Array): string =>
  createHash("sha1").update(bytes).digest("hex");

const escape = (text: string): string =>
  text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

/** Build a xar archive with a SHA-1 TOC checksum and per-member checksums. */
export const xarArchive = (
  members: readonly XarFixtureMember[],
  options: { readonly corruptTocChecksum?: boolean } = {},
): Uint8Array => {
  const heap: Uint8Array[] = [new Uint8Array(20)];
  let heapLength = 20;
  let nextId = 1;
  const fileXml = (member: XarFixtureMember): string => {
    const id = nextId++;
    const type = member.type ?? "file";
    let data = "";
    if (type === "file" && member.data !== undefined) {
      const archived =
        member.encoding === "zlib" ? deflateSync(member.data) : member.data;
      const offset = heapLength;
      heap.push(archived);
      heapLength += archived.length;
      const style =
        member.encoding === "zlib"
          ? "application/x-gzip"
          : member.encoding === "bzip2"
            ? "application/x-bzip2"
            : "application/octet-stream";
      data = `<data><archived-checksum style="sha1">${sha1(archived)}</archived-checksum><extracted-checksum style="sha1">${member.extractedSha1 ?? sha1(member.data)}</extracted-checksum><encoding style="${style}"/><size>${member.data.length}</size><offset>${offset}</offset><length>${archived.length}</length></data>`;
    }
    const link =
      type === "symlink"
        ? `<link type="file">${escape(member.link ?? "")}</link>`
        : "";
    const children = (member.children ?? []).map(fileXml).join("");
    return `<file id="${id}"><name>${escape(member.name)}</name><type>${type}</type><mode>${member.mode ?? (type === "directory" ? "0755" : "0644")}</mode>${data}${link}${children}</file>`;
  };
  const files = members.map(fileXml).join("");
  const toc = Buffer.from(
    `<?xml version="1.0" encoding="UTF-8"?><xar><toc><checksum style="sha1"><size>20</size><offset>0</offset></checksum>${files}</toc></xar>`,
  );
  const compressed = deflateSync(toc);
  const checksum = createHash("sha1").update(compressed).digest();
  if (options.corruptTocChecksum === true)
    checksum[0] = (checksum[0] ?? 0) ^ 0xff;
  heap[0] = checksum;
  const header = Buffer.alloc(28);
  header.writeUInt32BE(0x78617221, 0);
  header.writeUInt16BE(28, 4);
  header.writeUInt16BE(1, 6);
  header.writeBigUInt64BE(BigInt(compressed.length), 8);
  header.writeBigUInt64BE(BigInt(toc.length), 16);
  header.writeUInt32BE(1, 24);
  return Buffer.concat([header, compressed, ...heap]);
};

export interface CpioFixtureMember {
  readonly name: string;
  readonly mode: number;
  readonly data?: Uint8Array | string;
}

const octal = (value: number, width: number): string =>
  value.toString(8).padStart(width, "0");
const hex = (value: number): string => value.toString(16).padStart(8, "0");

/** Build a gzip-compressed odc or newc cpio archive ending in its trailer. */
export const gzipCpio = (
  members: readonly CpioFixtureMember[],
  format: "odc" | "newc" = "odc",
): Uint8Array => {
  const parts: Buffer[] = [];
  const pad = (length: number): void => {
    if (format === "newc" && length % 4 !== 0)
      parts.push(Buffer.alloc(4 - (length % 4)));
  };
  for (const member of [...members, { name: "TRAILER!!!", mode: 0 }]) {
    const data =
      typeof member.data === "string"
        ? Buffer.from(member.data)
        : Buffer.from(member.data ?? new Uint8Array());
    const name = Buffer.from(`${member.name}\0`);
    if (format === "odc")
      parts.push(
        Buffer.from(
          `070707${octal(0, 6)}${octal(1, 6)}${octal(member.mode, 6)}${octal(0, 6)}${octal(0, 6)}${octal(1, 6)}${octal(0, 6)}${octal(0, 11)}${octal(name.length, 6)}${octal(data.length, 11)}`,
        ),
        name,
        data,
      );
    else {
      parts.push(
        Buffer.from(
          `070701${hex(1)}${hex(member.mode)}${hex(0)}${hex(0)}${hex(1)}${hex(0)}${hex(data.length)}${hex(0)}${hex(0)}${hex(0)}${hex(0)}${hex(name.length)}${hex(0)}`,
        ),
        name,
      );
      pad(110 + name.length);
      parts.push(data);
      pad(data.length);
    }
  }
  return gzipSync(Buffer.concat(parts));
};

export const MODE = {
  directory: 0o040755,
  file: 0o100644,
  executable: 0o100755,
  symlink: 0o120755,
  fifo: 0o010644,
} as const;
