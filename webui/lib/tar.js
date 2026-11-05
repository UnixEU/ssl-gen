const zlib = require("zlib");

const BLOCK = 512;
const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_ENTRIES = 400;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;

function writeNumeric(buffer, offset, length, value) {
  const digits = length - 1;
  const text = Math.floor(value).toString(8).padStart(digits, "0");
  if (text.length > digits) {
    throw new Error("tar field overflow");
  }
  buffer.write(text, offset, digits, "ascii");
  buffer[offset + digits] = 0;
}

function readString(buffer, offset, length) {
  const slice = buffer.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString("utf8").trim();
}

function headerChecksum(header) {
  let sum = 0;
  for (let index = 0; index < BLOCK; index += 1) {
    const byte = index >= 148 && index < 156 ? 0x20 : header[index];
    sum += byte;
  }
  return sum;
}

function createHeader(name, size, type = "0", prefix = "") {
  if (Buffer.byteLength(name) > 100 || Buffer.byteLength(prefix) > 155) {
    throw new Error("tar entry name is too long");
  }

  const header = Buffer.alloc(BLOCK);
  header.write(name, 0, "utf8");
  writeNumeric(header, 100, 8, 0o644);
  writeNumeric(header, 108, 8, 0);
  writeNumeric(header, 116, 8, 0);
  writeNumeric(header, 124, 12, size);
  writeNumeric(header, 136, 12, Math.floor(Date.now() / 1000));
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  header.write("ustar\0", 257, 6, "ascii");
  header.write("00", 263, 2, "ascii");
  if (prefix) {
    header.write(prefix, 345, "utf8");
  }

  const sum = headerChecksum(header);
  const checksum = sum.toString(8).padStart(6, "0");
  header.write(checksum, 148, 6, "ascii");
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function packTar(files) {
  const parts = [];

  for (const file of files) {
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    if (data.length > MAX_ENTRY_BYTES) {
      throw new Error("tar entry is too large");
    }
    parts.push(createHeader(file.name, data.length, file.type || "0", file.prefix || ""));
    parts.push(data);
    const padding = (BLOCK - (data.length % BLOCK)) % BLOCK;
    if (padding > 0) {
      parts.push(Buffer.alloc(padding));
    }
  }

  parts.push(Buffer.alloc(BLOCK * 2));
  const archive = Buffer.concat(parts);
  if (archive.length > MAX_ARCHIVE_BYTES) {
    throw new Error("tar archive is too large");
  }
  return archive;
}

function readOctal(buffer, offset, length) {
  if (buffer[offset] & 0x80) {
    throw new Error("unsupported tar numeric field");
  }

  const text = buffer
    .subarray(offset, offset + length)
    .toString("ascii")
    .replace(/\0.*$/, "")
    .trim();

  if (!text) {
    return 0;
  }
  if (!/^[0-7]+$/.test(text)) {
    throw new Error("invalid tar numeric field");
  }
  return Number.parseInt(text, 8);
}

function entryName(header) {
  const name = readString(header, 0, 100);
  const prefix = readString(header, 345, 155);
  if (!prefix) {
    return name;
  }
  return `${prefix}/${name}`;
}

function storedChecksum(header) {
  const text = header
    .subarray(148, 156)
    .toString("ascii")
    .replace(/\0.*$/, "")
    .trim();
  if (!/^[0-7]+$/.test(text)) {
    throw new Error("invalid tar checksum");
  }
  return Number.parseInt(text, 8);
}

function unpackTar(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length > MAX_ARCHIVE_BYTES) {
    throw new Error("tar archive is too large");
  }
  if (buffer.length < BLOCK * 2) {
    throw new Error("tar archive is truncated");
  }

  const entries = [];
  let offset = 0;
  let zeroBlocks = 0;

  while (offset + BLOCK <= buffer.length) {
    const header = buffer.subarray(offset, offset + BLOCK);
    offset += BLOCK;

    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      if (zeroBlocks >= 2) {
        break;
      }
      continue;
    }

    zeroBlocks = 0;
    if (headerChecksum(header) !== storedChecksum(header)) {
      throw new Error("invalid tar checksum");
    }

    const size = readOctal(header, 124, 12);
    if (size > MAX_ENTRY_BYTES) {
      throw new Error("tar entry is too large");
    }

    const dataEnd = offset + size;
    if (dataEnd > buffer.length) {
      throw new Error("tar archive is truncated");
    }

    const data = Buffer.from(buffer.subarray(offset, dataEnd));
    offset = dataEnd + ((BLOCK - (size % BLOCK)) % BLOCK);
    entries.push({
      name: entryName(header),
      type: header[156],
      data,
    });

    if (entries.length > MAX_ENTRIES) {
      throw new Error("tar archive has too many entries");
    }
  }

  if (zeroBlocks < 2 && offset !== buffer.length) {
    throw new Error("tar archive is truncated");
  }

  return entries;
}

function packArchive(files) {
  return zlib.gzipSync(packTar(files));
}

function unpackArchive(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error("archive is empty");
  }
  if (buffer.length > MAX_ARCHIVE_BYTES) {
    throw new Error("archive is too large");
  }

  let tar = buffer;
  if (buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
    tar = zlib.gunzipSync(buffer, { maxOutputLength: MAX_ARCHIVE_BYTES });
  }

  return unpackTar(tar);
}

module.exports = {
  MAX_ARCHIVE_BYTES,
  packTar,
  unpackTar,
  packArchive,
  unpackArchive,
};
