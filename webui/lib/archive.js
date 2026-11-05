const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const {
  certificateFileNames,
  discoverStores,
  getCertsRoot,
  getStorePath,
  httpError,
  readCertMetadata,
  validateSafeName,
} = require("./certs");
const { packArchive, unpackArchive, MAX_ARCHIVE_BYTES } = require("./tar");

const POLICIES = new Set(["skip", "rename", "overwrite"]);
const SCOPES = new Set(["all", "store", "certificate"]);
const ALLOWED_EXTENSIONS = new Set([".crt", ".key", ".csr", ".pem", ".p12", ".cnf"]);
const FILE_SUFFIXES = [
  "-fullchain.pem",
  "-extensions.cnf",
  ".crt",
  ".key",
  ".csr",
  ".pem",
  ".p12",
  ".cnf",
];
const TYPE_FILE = new Set([0, 48]);
const TYPE_DIR = 53;
const OPENSSL_MAGIC = Buffer.from("Salted__");

function isSecretFile(fileName) {
  return fileName.endsWith(".key") || fileName.endsWith(".p12");
}

function extensionOf(fileName) {
  const dot = fileName.lastIndexOf(".");
  if (dot <= 0) {
    return "";
  }
  return fileName.slice(dot).toLowerCase();
}

function assertSegment(value, label) {
  try {
    validateSafeName(value, label);
  } catch (error) {
    throw httpError(400, error.message);
  }

  if (value === "." || value === "..") {
    throw httpError(400, "Archive entry escapes the certificate store");
  }
}

function splitFileName(fileName) {
  for (const suffix of FILE_SUFFIXES) {
    if (fileName.endsWith(suffix) && fileName.length > suffix.length) {
      return {
        base: fileName.slice(0, -suffix.length),
        suffix,
      };
    }
  }
  return null;
}

function logicalName(fileName) {
  return splitFileName(fileName)?.base || fileName;
}

function modeFor(fileName) {
  return isSecretFile(fileName) ? 0o600 : 0o644;
}

function requireStore(projectRoot, storeName) {
  try {
    assertSegment(storeName, "Store name");
    return getStorePath(projectRoot, storeName);
  } catch (error) {
    if (error.statusCode === 400) {
      throw error;
    }
    throw httpError(404, error.message);
  }
}

function confinedStore(projectRoot, storeName) {
  const certsReal = realCertsRoot(projectRoot);
  const storePath = requireStore(projectRoot, storeName);
  const storeReal = fs.realpathSync(storePath);
  if (fs.lstatSync(path.join(certsReal, storeName)).isSymbolicLink()) {
    throw httpError(400, "Store path escapes the certificate directory");
  }
  if (storeReal !== path.join(certsReal, storeName)) {
    throw httpError(400, "Store path escapes the certificate directory");
  }
  return storeReal;
}

function readRegularFile(storeReal, fileName) {
  assertSegment(fileName, "File name");
  if (!ALLOWED_EXTENSIONS.has(extensionOf(fileName)) || !splitFileName(fileName)) {
    return null;
  }

  const filePath = path.join(storeReal, fileName);
  let info;
  try {
    info = fs.lstatSync(filePath);
  } catch {
    return null;
  }

  if (!info.isFile()) {
    return null;
  }

  const fileReal = fs.realpathSync(filePath);
  if (path.dirname(fileReal) !== storeReal || path.basename(fileReal) !== fileName) {
    throw httpError(400, "Artifact path escapes the certificate store");
  }

  return fs.readFileSync(fileReal);
}

function realCertsRoot(projectRoot) {
  const projectReal = fs.realpathSync(projectRoot);
  const certsPath = getCertsRoot(projectRoot);
  if (!fs.existsSync(certsPath) || !fs.statSync(certsPath).isDirectory()) {
    throw httpError(404, "No certificate stores to export");
  }
  if (fs.lstatSync(certsPath).isSymbolicLink()) {
    throw httpError(400, "Certificate directory escapes the project");
  }

  const certsReal = fs.realpathSync(certsPath);
  if (certsReal !== path.join(projectReal, "certs")) {
    throw httpError(400, "Certificate directory escapes the project");
  }
  return certsReal;
}

function selectableNames(storeReal, includeKeys, onlyNames) {
  const available = new Set(
    fs
      .readdirSync(storeReal, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name),
  );

  const wanted = onlyNames ? [...onlyNames].filter((name) => available.has(name)) : [...available];
  return wanted
    .filter((name) => includeKeys || !isSecretFile(name))
    .filter((name) => ALLOWED_EXTENSIONS.has(extensionOf(name)) && splitFileName(name))
    .sort();
}

function describeFile(storeReal, storeName, fileName) {
  const data = readRegularFile(storeReal, fileName);
  if (!data) {
    return null;
  }

  const notAfter = fileName.endsWith(".crt")
    ? readCertMetadata(path.join(storeReal, fileName))?.notAfter || null
    : null;

  return {
    store: storeName,
    fileName,
    archivePath: `${storeName}/${fileName}`,
    data,
    notAfter,
  };
}

function filesForStore(storeReal, storeName, includeKeys) {
  return selectableNames(storeReal, includeKeys)
    .map((fileName) => describeFile(storeReal, storeName, fileName))
    .filter(Boolean);
}

function filesForCertificate(storeReal, storeName, certName, includeKeys) {
  assertSegment(certName, "Certificate name");
  const certPath = path.join(storeReal, `${certName}.crt`);
  const keyPath = path.join(storeReal, `${certName}.key`);
  const certExists = fs.existsSync(certPath);
  const keyExists = fs.existsSync(keyPath);
  if (!certExists && !keyExists) {
    throw httpError(404, `Certificate '${certName}' was not found in '${storeName}'`);
  }

  const wanted = new Set(certificateFileNames(certName));
  if (certName !== storeName) {
    wanted.add(`${storeName}.crt`);
  }

  return selectableNames(storeReal, includeKeys, wanted)
    .map((fileName) => describeFile(storeReal, storeName, fileName))
    .filter(Boolean);
}

function collectFiles(projectRoot, options) {
  const includeKeys = options.includeKeys === true;

  if (options.scope === "all") {
    const stores = discoverStores(projectRoot);
    if (stores.length === 0) {
      throw httpError(404, "No certificate stores to export");
    }
    return stores.flatMap((store) =>
      filesForStore(confinedStore(projectRoot, store.name), store.name, includeKeys),
    );
  }

  if (options.scope === "store") {
    const storeName = options.storeName;
    return filesForStore(confinedStore(projectRoot, storeName), storeName, includeKeys);
  }

  if (options.scope === "certificate") {
    const storeName = options.storeName;
    return filesForCertificate(
      confinedStore(projectRoot, storeName),
      storeName,
      options.certName,
      includeKeys,
    );
  }

  throw httpError(400, "Unknown export scope");
}

function buildManifest(files, options) {
  const groups = new Map();

  for (const file of files) {
    const name = logicalName(file.fileName);
    const key = `${file.store}\0${name}`;
    if (!groups.has(key)) {
      groups.set(key, {
        store: file.store,
        name,
        notAfter: null,
        files: [],
      });
    }
    const group = groups.get(key);
    group.files.push(file.archivePath);
    if (file.notAfter) {
      group.notAfter = file.notAfter;
    }
  }

  return {
    exportedAt: new Date().toISOString(),
    scope: options.scope,
    store: options.scope === "all" ? null : options.storeName,
    certificate: options.scope === "certificate" ? options.certName : null,
    entries: [...groups.values()].sort((left, right) =>
      `${left.store}/${left.name}`.localeCompare(`${right.store}/${right.name}`),
    ),
  };
}

function archiveFileName(options, encrypted) {
  let base = "ssl-gen-certs";
  if (options.scope === "store") {
    base = `ssl-gen-${options.storeName}`;
  } else if (options.scope === "certificate") {
    base = `ssl-gen-${options.storeName}-${options.certName}`;
  }
  return encrypted ? `${base}.tar.gz.enc` : `${base}.tar.gz`;
}

function opensslCipher(input, passphrase, decrypt) {
  try {
    return execFileSync(
      "openssl",
      [
        "enc",
        decrypt ? "-d" : "-e",
        "-aes-256-cbc",
        "-pbkdf2",
        "-salt",
        "-pass",
        "env:SSL_GEN_ARCHIVE_PASS",
      ],
      {
        input,
        stdio: ["pipe", "pipe", "ignore"],
        env: {
          PATH: process.env.PATH || "",
          LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH || "",
          SSL_GEN_ARCHIVE_PASS: passphrase,
        },
        maxBuffer: MAX_ARCHIVE_BYTES,
      },
    );
  } catch {
    throw httpError(
      400,
      decrypt
        ? "Could not decrypt the archive. Check the passphrase."
        : "Could not encrypt the archive",
    );
  }
}

function exportArchive(projectRoot, options = {}) {
  const scope = options.scope;
  if (!SCOPES.has(scope)) {
    throw httpError(400, "Unknown export scope");
  }

  const includeKeys = options.includeKeys === true;
  if (includeKeys && options.confirmKeys !== true) {
    throw httpError(400, "Including private keys requires confirmation");
  }

  const encrypt = options.encrypt === true;
  const passphrase = typeof options.passphrase === "string" ? options.passphrase : "";
  if (encrypt && passphrase.length === 0) {
    throw httpError(400, "Encryption requires a passphrase");
  }
  if (passphrase.length > 1024) {
    throw httpError(400, "Passphrase is too long");
  }

  if (scope !== "all") {
    assertSegment(options.storeName, "Store name");
  }
  if (scope === "certificate") {
    assertSegment(options.certName, "Certificate name");
  }

  const files = collectFiles(projectRoot, { ...options, includeKeys });

  if (files.length === 0) {
    throw httpError(404, "Nothing to export");
  }

  const manifest = buildManifest(files, {
    scope,
    storeName: options.storeName || null,
    certName: options.certName || null,
  });
  let data = packArchive([
    {
      name: "manifest.json",
      data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`),
    },
    ...files
      .sort((left, right) => left.archivePath.localeCompare(right.archivePath))
      .map((file) => ({ name: file.archivePath, data: file.data })),
  ]);

  if (data.length > MAX_ARCHIVE_BYTES) {
    throw httpError(413, "Archive is too large");
  }

  if (encrypt) {
    data = opensslCipher(data, passphrase, false);
  }

  return {
    data,
    fileName: archiveFileName(
      { scope, storeName: options.storeName, certName: options.certName },
      encrypt,
    ),
    manifest,
    encrypted: encrypt,
    includeKeys,
  };
}

function isEncrypted(buffer) {
  return buffer.length >= OPENSSL_MAGIC.length && buffer.subarray(0, OPENSSL_MAGIC.length).equals(OPENSSL_MAGIC);
}

function openArchive(buffer, passphrase) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw httpError(400, "Archive upload is empty");
  }
  if (buffer.length > MAX_ARCHIVE_BYTES) {
    throw httpError(413, "Archive is too large");
  }

  const encrypted = isEncrypted(buffer);
  const secret = typeof passphrase === "string" ? passphrase : "";
  if (encrypted && secret.length === 0) {
    throw httpError(400, "This archive is encrypted. Enter its passphrase to continue.");
  }
  if (!encrypted && secret.length > 0) {
    throw httpError(400, "A passphrase was provided, but this archive is not encrypted.");
  }

  const payload = encrypted ? opensslCipher(buffer, secret, true) : buffer;
  try {
    return {
      encrypted,
      entries: unpackArchive(payload),
    };
  } catch (error) {
    if (error.statusCode) {
      throw error;
    }
    throw httpError(400, "Could not read the archive");
  }
}

function rejectPath(reason) {
  throw httpError(400, reason);
}

function validateEntryName(rawName, type) {
  if (typeof rawName !== "string" || rawName.length === 0 || rawName.length > 240) {
    rejectPath("Archive entry escapes the certificate store");
  }
  if (rawName.includes("\0") || rawName.includes("\\") || rawName.includes(":")) {
    rejectPath("Archive entry escapes the certificate store");
  }
  if (rawName.startsWith("/") || rawName.startsWith("./")) {
    rejectPath("Archive entry escapes the certificate store");
  }

  const trimmed = rawName.replace(/\/+$/, "");
  const parts = trimmed.split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    rejectPath("Archive entry escapes the certificate store");
  }

  if (type === TYPE_DIR) {
    if (parts.length !== 1) {
      rejectPath("Archive entry escapes the certificate store");
    }
    assertSegment(parts[0], "Store name");
    return null;
  }

  if (!TYPE_FILE.has(type)) {
    throw httpError(400, "Archive contains a link or unsupported entry");
  }

  if (trimmed === "manifest.json") {
    return { manifest: true };
  }

  if (parts.length !== 2) {
    rejectPath("Archive entry escapes the certificate store");
  }

  const [storeName, fileName] = parts;
  assertSegment(storeName, "Store name");
  assertSegment(fileName, "File name");
  if (!ALLOWED_EXTENSIONS.has(extensionOf(fileName)) || !splitFileName(fileName)) {
    throw httpError(400, "Archive contains a file type that is not allowed");
  }

  return {
    manifest: false,
    store: storeName,
    fileName,
    archivePath: `${storeName}/${fileName}`,
  };
}

function readManifest(entry) {
  if (!entry) {
    return null;
  }
  if (entry.data.length > 1024 * 1024) {
    throw httpError(400, "Archive manifest is not valid JSON");
  }

  try {
    const parsed = JSON.parse(entry.data.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("invalid");
    }
    return parsed;
  } catch {
    throw httpError(400, "Archive manifest is not valid JSON");
  }
}

function publicManifest(manifest) {
  if (!manifest) {
    return null;
  }

  const entries = Array.isArray(manifest.entries) ? manifest.entries : [];
  return {
    exportedAt: typeof manifest.exportedAt === "string" ? manifest.exportedAt : null,
    scope: typeof manifest.scope === "string" ? manifest.scope : null,
    store: typeof manifest.store === "string" ? manifest.store : null,
    certificate: typeof manifest.certificate === "string" ? manifest.certificate : null,
    entries: entries.map((entry) => ({
      store: typeof entry?.store === "string" ? entry.store : "",
      name: typeof entry?.name === "string" ? entry.name : "",
      notAfter:
        typeof entry?.notAfter === "string" && entry.notAfter.length <= 120
          ? entry.notAfter
          : null,
      files: Array.isArray(entry?.files)
        ? entry.files.filter(
            (file) =>
              typeof file === "string" &&
              file.length <= 240 &&
              !file.includes("..") &&
              !file.startsWith("/") &&
              !file.includes("\\"),
          )
        : [],
    })),
  };
}

function notAfterFor(manifest, store, fileName) {
  const name = logicalName(fileName);
  const entry = manifest?.entries?.find((item) => item.store === store && item.name === name);
  return entry?.notAfter || null;
}

function occupyingFile(storeReal, fileName) {
  if (!storeReal) {
    return false;
  }

  const filePath = path.join(storeReal, fileName);
  let info;
  try {
    info = fs.lstatSync(filePath);
  } catch (error) {
    if (error.code === "ENOENT") {
      return false;
    }
    throw error;
  }

  if (info.isSymbolicLink() || !info.isFile()) {
    throw httpError(400, "Store path escapes the certificate directory");
  }
  return true;
}

function destinationName(storeReal, fileName, reserved) {
  const parts = splitFileName(fileName);
  if (!parts) {
    throw httpError(400, "Archive contains a file type that is not allowed");
  }

  const occupied = (candidate) =>
    reserved.has(candidate) || occupyingFile(storeReal, candidate);

  if (!occupied(fileName)) {
    return fileName;
  }

  for (let index = 1; index < 1000; index += 1) {
    const suffix = index === 1 ? "-imported" : `-imported-${index}`;
    const candidate = `${parts.base}${suffix}${parts.suffix}`;
    assertSegment(candidate, "File name");
    if (!occupied(candidate)) {
      return candidate;
    }
  }

  throw httpError(409, "Could not find a free file name for import");
}

function locateStore(projectRoot, storeName, create) {
  assertSegment(storeName, "Store name");
  const projectReal = fs.realpathSync(projectRoot);
  const certsPath = path.join(projectReal, "certs");

  if (!fs.existsSync(certsPath)) {
    if (!create) {
      return null;
    }
    fs.mkdirSync(certsPath, { recursive: true });
  }

  if (fs.lstatSync(certsPath).isSymbolicLink() || !fs.statSync(certsPath).isDirectory()) {
    throw httpError(400, "Certificate directory escapes the project");
  }

  const certsReal = fs.realpathSync(certsPath);
  if (certsReal !== certsPath) {
    throw httpError(400, "Certificate directory escapes the project");
  }

  const storePath = path.join(certsReal, storeName);
  if (path.dirname(storePath) !== certsReal) {
    throw httpError(400, "Archive entry escapes the certificate store");
  }

  if (!fs.existsSync(storePath)) {
    if (!create) {
      return null;
    }
    fs.mkdirSync(storePath);
  } else if (
    fs.lstatSync(storePath).isSymbolicLink() ||
    !fs.statSync(storePath).isDirectory()
  ) {
    throw httpError(400, "Store path escapes the certificate directory");
  }

  const storeReal = fs.realpathSync(storePath);
  if (storeReal !== storePath) {
    throw httpError(400, "Store path escapes the certificate directory");
  }
  return storeReal;
}

function classifyArchive(projectRoot, buffer, options, createDirs) {
  const policy = options.policy || "skip";
  if (!POLICIES.has(policy)) {
    throw httpError(400, "Unknown conflict policy");
  }

  const opened = openArchive(buffer, options.passphrase);
  const seen = new Set();
  let manifestEntry = null;
  const accepted = [];

  for (const entry of opened.entries) {
    const described = validateEntryName(entry.name, entry.type);
    if (!described) {
      continue;
    }
    if (described.manifest) {
      if (manifestEntry) {
        throw httpError(400, "Archive contains duplicate paths");
      }
      manifestEntry = entry;
      continue;
    }
    if (seen.has(described.archivePath)) {
      throw httpError(400, "Archive contains duplicate paths");
    }
    seen.add(described.archivePath);
    accepted.push({ ...described, data: entry.data });
  }

  if (accepted.length === 0) {
    throw httpError(400, "Archive does not contain any certificate files");
  }

  const manifest = publicManifest(readManifest(manifestEntry));
  const reservedByStore = new Map();
  const files = accepted.map((entry) => {
    const storeReal = locateStore(projectRoot, entry.store, createDirs);
    if (!reservedByStore.has(entry.store)) {
      reservedByStore.set(entry.store, new Set());
    }
    const reserved = reservedByStore.get(entry.store);
    const exists = occupyingFile(storeReal, entry.fileName);
    let action = "create";
    let destination = entry.fileName;

    if (exists || reserved.has(entry.fileName)) {
      if (policy === "skip") {
        action = "skip";
      } else if (policy === "overwrite") {
        action = "overwrite";
      } else {
        action = "rename";
        destination = destinationName(storeReal, entry.fileName, reserved);
      }
    }

    if (action !== "skip") {
      reserved.add(destination);
    }

    return {
      path: entry.archivePath,
      store: entry.store,
      fileName: entry.fileName,
      destination,
      action,
      bytes: entry.data.length,
      notAfter: notAfterFor(manifest, entry.store, entry.fileName),
      secret: isSecretFile(entry.fileName),
      data: entry.data,
    };
  });

  return {
    encrypted: opened.encrypted,
    manifest,
    policy,
    files,
  };
}

function summarize(files) {
  return files.reduce(
    (summary, file) => {
      summary[file.action] += 1;
      return summary;
    },
    { create: 0, skip: 0, rename: 0, overwrite: 0 },
  );
}

function presentPlan(plan) {
  return {
    encrypted: plan.encrypted,
    manifest: plan.manifest,
    policy: plan.policy,
    summary: summarize(plan.files),
    files: plan.files.map((file) => ({
      path: file.path,
      store: file.store,
      fileName: file.fileName,
      destination: file.destination,
      action: file.action,
      bytes: file.bytes,
      notAfter: file.notAfter,
      secret: file.secret,
    })),
  };
}

function previewImport(projectRoot, buffer, options = {}) {
  return presentPlan(classifyArchive(projectRoot, buffer, options, false));
}

function writeImportedFile(storeReal, fileName, data, overwrite) {
  assertSegment(fileName, "File name");
  const filePath = path.join(storeReal, fileName);
  if (path.dirname(filePath) !== storeReal) {
    throw httpError(400, "Archive entry escapes the certificate store");
  }

  const mode = modeFor(fileName);
  const flags =
    fs.constants.O_WRONLY |
    fs.constants.O_CREAT |
    fs.constants.O_NOFOLLOW |
    (overwrite ? fs.constants.O_TRUNC : fs.constants.O_EXCL);
  let handle;
  try {
    handle = fs.openSync(filePath, flags, mode);
  } catch (error) {
    if (error.code === "ELOOP" || error.code === "EEXIST") {
      throw httpError(400, "Archive entry escapes the certificate store");
    }
    throw error;
  }
  try {
    fs.writeSync(handle, data);
    fs.fchmodSync(handle, mode);
  } finally {
    fs.closeSync(handle);
  }

  const fileReal = fs.realpathSync(filePath);
  if (path.dirname(fileReal) !== storeReal || path.basename(fileReal) !== fileName) {
    fs.rmSync(filePath, { force: true });
    throw httpError(400, "Archive entry escapes the certificate store");
  }
}

function applyImport(projectRoot, buffer, options = {}) {
  const plan = classifyArchive(projectRoot, buffer, options, false);
  const needsConfirm = plan.files.some((file) => file.action === "overwrite");
  if (needsConfirm && options.confirmOverwrite !== true) {
    throw httpError(400, "Overwrite requires confirmation");
  }

  for (const file of plan.files) {
    if (file.action === "skip") {
      continue;
    }
    const storeReal = locateStore(projectRoot, file.store, true);
    writeImportedFile(storeReal, file.destination, file.data, file.action === "overwrite");
  }

  const result = presentPlan(plan);
  return {
    ...result,
    stores: discoverStores(projectRoot),
  };
}

module.exports = {
  exportArchive,
  previewImport,
  applyImport,
};
