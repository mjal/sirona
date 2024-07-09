export class TarFile {
  constructor(
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
  ) {
    this.name = name;
    this.mode = mode;
    this.uid = uid;
    this.gid = gid;
    this.size = size;
    this.mtime = mtime;
    this.checksum = checksum;
    this.type = type;
    this.linkname = linkname;
    this.ustar = ustar;
    this.content = content;
  }
}

export class TarReader {
  constructor(arrayBuffer) {
    this.data = new Uint8Array(arrayBuffer);
    this.files = [];
    this.readFiles();
  }

  readFiles() {
    let offset = 0;
    while (offset < this.data.length) {
      const header = this.data.subarray(offset, offset + 512);
      const name = this.readString(header, 0, 100);
      if (!name) break; // Fin du fichier TAR

      const mode = this.readString(header, 100, 8);
      const uid = this.readString(header, 108, 8);
      const gid = this.readString(header, 116, 8);
      const size = parseInt(this.readString(header, 124, 12).trim(), 8);
      const mtime = this.readString(header, 136, 12);
      const checksum = this.readString(header, 148, 8);
      const type = this.readString(header, 156, 1);
      const linkname = this.readString(header, 157, 100);
      const ustar = this.readString(header, 257, 6);

      const content = new TextDecoder()
        .decode(this.data.slice(offset + 512, offset + 512 + size))
        .replace(/\0/g, "")
        .trim();
      const file = new TarFile(
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
      );
      this.files.push(file);

      // Avancer à l'en-tête suivant
      offset += 512 + Math.ceil(size / 512) * 512;
    }
  }

  readString(buffer, start, length) {
    return String.fromCharCode(...buffer.subarray(start, start + length))
      .replace(/\0/g, "")
      .trim();
  }

  getFiles() {
    return this.files;
  }
}
