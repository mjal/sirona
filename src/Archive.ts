import fs from "fs";

function readString(buffer, start, length) {
  return String.fromCharCode(...buffer.subarray(start, start + length))
    .replace(/\0/g, "")
    .trim();
}

export class Archive {

  constructor() {
    this.filePath = null;
    this.data = null;
    this.files = [];
    return this;
  }

  async fromFile(filePath) {
    this.filePath = filePath;
    this.data = await fs.promises.readFile(filePath);
    this.readFiles();
  }

  async fromArrayBuffer(arrayBuffer) {
    this.data = new Uint8Array(arrayBuffer);
    this.readFiles();
  }

  readFiles() {
    let offset = 0;
    while (offset < this.data.length) {
      const header = this.data.subarray(offset, offset + 512);
      const name = readString(header, 0, 100);
      if (!name) break; // Fin du fichier TAR

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
        .decode(this.data.slice(offset + 512, offset + 512 + size))
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

      this.files.push(file);

      // Avancer à l'en-tête suivant
      offset += 512 + Math.ceil(size / 512) * 512;
    }
  }

  getFiles() {
    return this.files;
  }
}
