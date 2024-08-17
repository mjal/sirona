import fs from "fs";

export async function readFile(filePath) {
  const data = await fs.promises.readFile(filePath);
  return read(data);
}

export async function readArrayBuffer(arrayBuffer) {
  const data = new Uint8Array(arrayBuffer);
  return read(data);
}

export function read(data) {
  let files = [];
  let offset = 0;
  while (offset < data.length) {
    const header = data.subarray(offset, offset + 512);
    const name = readString(header, 0, 100);
    if (!name) break; // Fin du fichier

    const mode = readString(header, 100, 8);
    const uid = readString(header, 108, 8);
    const gid = readString(header, 116, 8);
    const size = parseInt(readString(header, 124, 12).trim(), 8);
    const mtime = readString(header, 136, 12);
    const checksum = readString(header, 148, 8);
    const type = readString(header, 156, 1);
    const linkname = readString(header, 157, 100);
    const ustar = readString(header, 257, 6);
    const content = new TextDecoder()
      .decode(data.slice(offset + 512, offset + 512 + size))
      .replace(/\0/g, "")
      .trim();

    const file = {
      name,
      mode,
      uid,
      gid,
      size,
      mtime,
      checksum,
      type,
      linkname,
      ustar,
      content,
    };
    files.push(file);

    offset += 512 + Math.ceil(size / 512) * 512;
  }

  return files;
}

export async function addFile(filePath, name, content) {
  const mode = "0000644";
  const uid = "0000000";
  const gid = "0000000";
  const size = content.length.toString(8).padStart(11, "0");
  const mtime = Math.floor(Date.now() / 1000)
    .toString(8)
    .padStart(11, "0");
  const type = "0";

  const header = new Uint8Array(512);
  header.set(new TextEncoder().encode(padString(name, 100)), 0);
  header.set(new TextEncoder().encode(padString(mode, 8)), 100);
  header.set(new TextEncoder().encode(padString(uid, 8)), 108);
  header.set(new TextEncoder().encode(padString(gid, 8)), 116);
  header.set(new TextEncoder().encode(padString(size, 12)), 124);
  header.set(new TextEncoder().encode(padString(mtime, 12)), 136);
  header.set(new TextEncoder().encode("        "), 148);
  header.set(new TextEncoder().encode(type), 156);
  header.set(new TextEncoder().encode(padString("", 100)), 157);
  header.set(new TextEncoder().encode(padString("", 6)), 257);

  let nChecksum = 0;
  for (let i = 0; i < 512; i++) {
    nChecksum += header[i];
  }
  const checksum = nChecksum.toString(8).padStart(6, "0") + "\0 ";
  header.set(new TextEncoder().encode(checksum), 148);

  const contentBuffer = new TextEncoder().encode(content);
  let tarBlock = new Uint8Array([...header, ...contentBuffer]);

  const padding = 512 - (contentBuffer.length % 512);
  if (padding < 512) {
    tarBlock = new Uint8Array([...tarBlock, ...new Uint8Array(padding)]);
  }

  await fs.promises.appendFile(filePath, tarBlock);
}

function readString(buffer, start, length) {
  return String.fromCharCode(...buffer.subarray(start, start + length))
    .replace(/\0/g, "")
    .trim();
}

function padString(str, length, padChar = "\0") {
  return str.length >= length
    ? str.slice(0, length)
    : str + padChar.repeat(length - str.length);
}
