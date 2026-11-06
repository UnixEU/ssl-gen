const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const {
  getCertsRoot,
  getStorePath,
  httpError,
  readCertMetadata,
  validateSafeName,
} = require("./certs");

const MAX_MATERIAL_BYTES = 512 * 1024;
const OPENSSL_TIMEOUT_MS = 10000;
const PASS_IN = "SSL_GEN_PASS_IN";
const PASS_OUT = "SSL_GEN_PASS_OUT";
const FILE_RESTS = [
  ".crt",
  ".pem",
  ".der",
  ".key",
  ".p12",
  "-fullchain.pem",
  "-fullchain.der",
  "-key.pem",
  "-key.der",
];

const PKCS12_REASON =
  "PKCS#12 files are not converted here. Change the password on the .p12 instead.";
const ENCRYPTED_KEY_REASON =
  "Encrypted private keys are not converted here. Change the password on the .key instead.";
const CHAIN_REASON =
  "This PEM contains more than one certificate. Convert a single certificate (.crt). Use Certificate info to read a chain.";
const MIXED_REASON =
  "This PEM contains both a certificate and a private key. Convert the .crt and the unencrypted .key separately.";

function assertSegment(value, label) {
  try {
    validateSafeName(value, label);
  } catch (error) {
    throw httpError(400, error.message);
  }
  if (value === "." || value === "..") {
    throw httpError(400, `${label} escapes the certificate store`);
  }
}

function baseEnv(extra = {}) {
  return {
    PATH: process.env.PATH || "",
    LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH || "",
    ...extra,
  };
}

function opensslFailure(error, fallback) {
  if (error?.code === "ENOENT") {
    return httpError(500, "OpenSSL is not available");
  }
  if (error?.killed || error?.signal === "SIGKILL" || error?.code === "ETIMEDOUT") {
    return httpError(500, "OpenSSL timed out");
  }
  const stderr = Buffer.isBuffer(error?.stderr)
    ? error.stderr.toString("utf8")
    : String(error?.stderr || "");
  const wrapped = httpError(400, fallback);
  wrapped.passwordRejected = /password|bad decrypt|mac verify/i.test(stderr);
  return wrapped;
}

function runOpenssl(args, options = {}) {
  const execOptions = {
    timeout: OPENSSL_TIMEOUT_MS,
    maxBuffer: 2 * 1024 * 1024,
    killSignal: "SIGKILL",
    env: options.env || baseEnv(),
    stdio: ["pipe", "pipe", "pipe"],
  };
  if (options.input !== undefined) {
    execOptions.input = options.input;
  }
  if (options.encoding) {
    execOptions.encoding = options.encoding;
  }
  try {
    return execFileSync("openssl", args, execOptions);
  } catch (error) {
    throw opensslFailure(error, options.failureMessage || "OpenSSL could not read this file");
  }
}

function realCertsRoot(projectRoot) {
  let projectReal;
  try {
    projectReal = fs.realpathSync(projectRoot);
  } catch {
    throw httpError(404, "Project directory was not found");
  }

  const certsPath = getCertsRoot(projectRoot);
  if (!fs.existsSync(certsPath) || !fs.statSync(certsPath).isDirectory()) {
    throw httpError(404, "Certificate directory was not found");
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

function confinedStore(projectRoot, storeName) {
  assertSegment(storeName, "Store name");
  const certsReal = realCertsRoot(projectRoot);
  let storePath;
  try {
    storePath = getStorePath(projectRoot, storeName);
  } catch (error) {
    if (error.statusCode) {
      throw error;
    }
    throw httpError(404, error.message);
  }

  const storeLink = path.join(certsReal, storeName);
  let linkStat;
  try {
    linkStat = fs.lstatSync(storeLink);
  } catch {
    throw httpError(404, `Certificate store '${storeName}' was not found`);
  }
  if (linkStat.isSymbolicLink()) {
    throw httpError(400, "Store path escapes the certificate directory");
  }

  const storeReal = fs.realpathSync(storePath);
  if (storeReal !== storeLink) {
    throw httpError(400, "Store path escapes the certificate directory");
  }
  return storeReal;
}

function confinedFilePath(storeReal, fileName) {
  assertSegment(fileName, "File name");
  const filePath = path.join(storeReal, fileName);
  if (path.dirname(filePath) !== storeReal || path.basename(filePath) !== fileName) {
    throw httpError(400, "Artifact path escapes the certificate store");
  }
  return filePath;
}

function readRegularFile(storeReal, fileName) {
  const filePath = confinedFilePath(storeReal, fileName);
  let info;
  try {
    info = fs.lstatSync(filePath);
  } catch {
    throw httpError(404, "Artifact was not found");
  }
  if (!info.isFile()) {
    throw httpError(404, "Artifact was not found");
  }
  if (info.size > MAX_MATERIAL_BYTES) {
    throw httpError(400, "File is too large");
  }

  const fileReal = fs.realpathSync(filePath);
  if (path.dirname(fileReal) !== storeReal || path.basename(fileReal) !== fileName) {
    throw httpError(400, "Artifact path escapes the certificate store");
  }
  return { filePath: fileReal, info };
}

function belongsToBase(fileName, base) {
  if (!fileName.startsWith(base)) {
    return false;
  }
  return FILE_RESTS.includes(fileName.slice(base.length));
}

function assertOutputName(fileName) {
  assertSegment(fileName, "Output name");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.(pem|der)$/.test(fileName)) {
    throw httpError(400, "Output name must be a single file ending in .pem or .der");
  }
}

function asPassword(value, label) {
  if (typeof value !== "string") {
    throw httpError(400, `${label} must be a string`);
  }
  if (value.length > 1024) {
    throw httpError(400, `${label} is too long`);
  }
  if (value.includes("\0")) {
    throw httpError(400, `${label} contains an unsupported character`);
  }
  return value;
}

function pemText(buffer) {
  const text = buffer.toString("utf8");
  if (!/^\s*-----BEGIN [A-Z0-9 ]+-----/.test(text)) {
    return null;
  }
  return text;
}

function headerEncrypted(buffer) {
  const text = buffer.toString("utf8");
  return (
    text.includes("BEGIN ENCRYPTED PRIVATE KEY") || /Proc-Type:\s*4,ENCRYPTED/.test(text)
  );
}

function classifyBuffer(buffer, hintName = "") {
  const name = String(hintName || "").toLowerCase();
  if (name.endsWith(".p12") || name.endsWith(".pfx")) {
    return { kind: "pkcs12", format: "der", encrypted: true, convertible: false, reason: PKCS12_REASON };
  }

  const text = pemText(buffer);
  if (text) {
    if (/-----BEGIN PKCS12-----|-----BEGIN PKCS7-----/.test(text)) {
      return { kind: "pkcs12", format: "pem", encrypted: true, convertible: false, reason: PKCS12_REASON };
    }
    const certCount = (text.match(/-----BEGIN (?:TRUSTED )?CERTIFICATE-----/g) || []).length;
    const hasKey = /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(text);
    const encrypted = headerEncrypted(buffer);
    if (encrypted) {
      return { kind: "key", format: "pem", encrypted: true, convertible: false, reason: ENCRYPTED_KEY_REASON };
    }
    if (certCount > 0 && hasKey) {
      return { kind: "mixed", format: "pem", encrypted: false, convertible: false, reason: MIXED_REASON };
    }
    if (certCount > 1) {
      return { kind: "chain", format: "pem", encrypted: false, convertible: false, reason: CHAIN_REASON };
    }
    if (certCount === 1) {
      return { kind: "certificate", format: "pem", encrypted: false, convertible: true, reason: "" };
    }
    if (hasKey) {
      return { kind: "key", format: "pem", encrypted: false, convertible: true, reason: "" };
    }
    return {
      kind: "unknown",
      format: "pem",
      encrypted: false,
      convertible: false,
      reason: "This PEM is not an X.509 certificate or an unencrypted private key.",
    };
  }

  if (opensslOk(["x509", "-inform", "DER", "-noout"], buffer)) {
    return { kind: "certificate", format: "der", encrypted: false, convertible: true, reason: "" };
  }
  if (opensslOk(["pkey", "-inform", "DER", "-noout"], buffer)) {
    return { kind: "key", format: "der", encrypted: false, convertible: true, reason: "" };
  }
  if (looksLikePkcs12(buffer)) {
    return { kind: "pkcs12", format: "der", encrypted: true, convertible: false, reason: PKCS12_REASON };
  }
  return {
    kind: "unknown",
    format: "der",
    encrypted: false,
    convertible: false,
    reason:
      "Could not read this file as an X.509 certificate or an unencrypted private key. Encrypted keys and PKCS#12 belong under Change password.",
  };
}

function opensslOk(args, input) {
  try {
    runOpenssl(args, { input });
    return true;
  } catch (error) {
    if (error.statusCode === 500) {
      throw error;
    }
    return false;
  }
}

function looksLikePkcs12(buffer) {
  const env = baseEnv({ [PASS_IN]: "" });
  try {
    runOpenssl(["pkcs12", "-noout", "-passin", `env:${PASS_IN}`], { input: buffer, env });
    return true;
  } catch (error) {
    if (error.statusCode === 500) {
      throw error;
    }
    return Boolean(error.passwordRejected);
  }
}

function defaultOutputName(sourceName, kind, to) {
  const extension = to === "der" ? "der" : "pem";
  const cleaned = String(sourceName || "converted").replace(/\.(crt|pem|der|key|p12|pfx)$/i, "");
  if (kind === "key") {
    const stem = cleaned.replace(/-key$/i, "");
    return `${stem}-key.${extension}`;
  }
  if (/fullchain$/i.test(cleaned)) {
    return `${cleaned}.${extension}`;
  }
  return `${cleaned || "converted"}.${extension}`;
}

function shredFile(filePath) {
  try {
    const info = fs.lstatSync(filePath);
    if (info.isSymbolicLink() || !info.isFile()) {
      fs.unlinkSync(filePath);
      return;
    }
    const fd = fs.openSync(filePath, "r+");
    try {
      const chunk = Buffer.alloc(64 * 1024, 0);
      let remaining = info.size;
      let offset = 0;
      while (remaining > 0) {
        const wrote = fs.writeSync(fd, chunk, 0, Math.min(chunk.length, remaining), offset);
        if (wrote <= 0) {
          break;
        }
        remaining -= wrote;
        offset += wrote;
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // The temporary file may already be gone.
  }
  try {
    fs.unlinkSync(filePath);
  } catch {
    // Already removed.
  }
}

function shredDirectory(dir) {
  if (!fs.existsSync(dir)) {
    return;
  }
  for (const entry of fs.readdirSync(dir)) {
    const target = path.join(dir, entry);
    let info;
    try {
      info = fs.lstatSync(target);
    } catch {
      continue;
    }
    if (info.isDirectory() && !info.isSymbolicLink()) {
      shredDirectory(target);
    } else {
      shredFile(target);
    }
  }
  fs.rmSync(dir, { recursive: true, force: true });
}

function withPrivateTemp(work) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-material-"));
  fs.chmodSync(dir, 0o700);
  try {
    return work(dir);
  } finally {
    shredDirectory(dir);
  }
}

function tempInStore(storeReal) {
  const name = `.ssl-gen-${crypto.randomBytes(9).toString("hex")}.tmp`;
  const full = path.join(storeReal, name);
  if (path.dirname(full) !== storeReal) {
    throw httpError(500, "Could not create a temporary file in the store");
  }
  return full;
}

function replaceRegularFile(dest, source, mode) {
  let existing;
  try {
    existing = fs.lstatSync(dest);
  } catch {
    throw httpError(404, "Artifact was not found");
  }
  if (existing.isSymbolicLink() || !existing.isFile()) {
    throw httpError(400, "Refusing to replace a symlink in the certificate store");
  }
  fs.chmodSync(source, mode);
  fs.renameSync(source, dest);
  fs.chmodSync(dest, mode);
}

function writeStoreFile(storeReal, fileName, data, overwrite, mode) {
  const dest = confinedFilePath(storeReal, fileName);
  let existing = null;
  try {
    existing = fs.lstatSync(dest);
  } catch {
    existing = null;
  }
  if (existing) {
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw httpError(400, "Refusing to replace a symlink in the certificate store");
    }
    if (!overwrite) {
      const error = httpError(
        409,
        `File '${fileName}' already exists. Confirm overwrite to replace it.`,
      );
      error.code = "exists";
      throw error;
    }
  }

  const tmp = tempInStore(storeReal);
  const flags =
    fs.constants.O_WRONLY |
    fs.constants.O_CREAT |
    fs.constants.O_EXCL |
    (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(tmp, flags, mode);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } catch (error) {
    fs.closeSync(fd);
    shredFile(tmp);
    throw error;
  }
  fs.closeSync(fd);

  try {
    if (existing) {
      replaceRegularFile(dest, tmp, mode);
    } else {
      fs.chmodSync(tmp, mode);
      fs.renameSync(tmp, dest);
      fs.chmodSync(dest, mode);
    }
  } catch (error) {
    shredFile(tmp);
    throw error;
  }
}

function decodeUpload(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw httpError(400, "Upload a PEM or DER file, or paste PEM text");
  }
  if (value.length > 800000) {
    throw httpError(400, "Upload is too large");
  }
  const buffer = Buffer.from(value, "base64");
  if (buffer.length === 0 || buffer.length > MAX_MATERIAL_BYTES) {
    throw httpError(400, "Upload is too large");
  }
  return buffer;
}

function passwordAccepted(filePath, artifact, password) {
  const env = baseEnv({ [PASS_IN]: password });
  const args =
    artifact === "key"
      ? ["pkey", "-in", filePath, "-noout", "-passin", `env:${PASS_IN}`]
      : ["pkcs12", "-in", filePath, "-noout", "-passin", `env:${PASS_IN}`];
  try {
    runOpenssl(args, { env, failureMessage: "Current password was not accepted" });
    return true;
  } catch (error) {
    if (error.statusCode === 500) {
      throw error;
    }
    return false;
  }
}

function fileHeaderEncrypted(filePath) {
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(256);
    const read = fs.readSync(fd, buffer, 0, buffer.length, 0);
    return headerEncrypted(buffer.subarray(0, read));
  } finally {
    fs.closeSync(fd);
  }
}

function passwordStatusFor(storeReal, base) {
  const status = {
    key: { present: false, encrypted: false, passwordRequired: false },
    p12: { present: false, encrypted: false, passwordRequired: false },
  };

  for (const artifact of ["key", "p12"]) {
    const fileName = `${base}.${artifact === "key" ? "key" : "p12"}`;
    let located;
    try {
      located = readRegularFile(storeReal, fileName);
    } catch (error) {
      if (error.statusCode === 404) {
        continue;
      }
      throw error;
    }
    const encrypted = artifact === "key" ? fileHeaderEncrypted(located.filePath) : true;
    const emptyAccepted = passwordAccepted(located.filePath, artifact, "");
    status[artifact] = {
      present: true,
      encrypted: artifact === "key" ? encrypted : !emptyAccepted,
      passwordRequired: !emptyAccepted,
    };
  }

  return status;
}

function describeMaterial(projectRoot, storeName, certName = null) {
  if (certName) {
    assertSegment(certName, "Certificate name");
  }
  const storeReal = confinedStore(projectRoot, storeName);
  const base = certName || storeName;
  const names = fs
    .readdirSync(storeReal, { withFileTypes: true })
    .filter((entry) => entry.isFile() && belongsToBase(entry.name, base))
    .map((entry) => entry.name)
    .sort();

  const files = names.map((fileName) => {
    const { filePath } = readRegularFile(storeReal, fileName);
    const classified = classifyBuffer(fs.readFileSync(filePath), fileName);
    return {
      fileName,
      kind: classified.kind,
      format: classified.format,
      encrypted: Boolean(classified.encrypted),
      convertible: Boolean(classified.convertible),
      reason: classified.reason || "",
    };
  });

  return {
    storeName,
    certName: certName || null,
    baseName: base,
    files,
    password: passwordStatusFor(storeReal, base),
  };
}

function extensionValue(text, label) {
  const lines = text.split(/\r?\n/);
  const headerIndex = lines.findIndex((line) => line.includes(label));
  if (headerIndex === -1) {
    return "";
  }
  const headerLine = lines[headerIndex];
  const headerIndent = headerLine.match(/^\s*/)[0].length;
  const critical = /:\s*critical\s*$/i.test(headerLine.trim());
  const values = [];
  for (let index = headerIndex + 1; index < lines.length; index += 1) {
    const line = lines[index];
    const indent = line.match(/^\s*/)[0].length;
    if (indent <= headerIndent) {
      break;
    }
    const trimmed = line.trim();
    if (trimmed) {
      values.push(trimmed);
    }
  }
  const body = values.join(", ");
  if (!body) {
    return critical ? "critical" : "";
  }
  return critical ? `critical, ${body}` : body;
}

function splitDn(value) {
  const parts = [];
  let current = "";
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === "\\" && index + 1 < value.length) {
      current += char + value[index + 1];
      index += 1;
      continue;
    }
    if (char === ",") {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts;
}

function normalizeDn(value = "") {
  const cleaned = String(value)
    .replace(/^(subject|issuer)=/i, "")
    .trim();
  return splitDn(cleaned)
    .map((part) => part.trim().replace(/\s*=\s*/g, "=").replace(/\s+/g, " ").toLowerCase())
    .filter(Boolean)
    .sort()
    .join(",");
}

function commonNameFromDn(value = "") {
  const match = String(value).match(/(?:^|,)\s*CN\s*=\s*([^,]+)/i);
  return match ? match[1].trim() : "";
}

function parseSerial(text) {
  const hex = text.match(/Serial Number:\s*\n\s*((?:[0-9a-f]{2}:)+[0-9a-f]{2})/i);
  if (hex) {
    return hex[1].replace(/:/g, "").toUpperCase();
  }
  const decimal = text.match(/Serial Number:\s*(\d+)\s*(?:\(0x([0-9a-f]+)\))?/i);
  if (!decimal) {
    return "";
  }
  if (decimal[2]) {
    return decimal[2].toUpperCase();
  }
  return BigInt(decimal[1]).toString(16).toUpperCase();
}

function parseFingerprint(text) {
  const match = String(text).match(/Fingerprint=([0-9A-Fa-f:]+)/);
  return match ? match[1].toUpperCase() : "";
}

function keyDescription(algorithm, bits, curve) {
  let name = algorithm || "Unknown";
  if (/ecPublicKey/i.test(algorithm)) {
    name = "EC";
  } else if (/rsa/i.test(algorithm)) {
    name = "RSA";
  } else if (/dsa/i.test(algorithm)) {
    name = "DSA";
  } else if (/ed25519/i.test(algorithm)) {
    name = "Ed25519";
  }
  const size = bits ? `${bits}-bit ` : "";
  const curveText = curve ? ` (${curve})` : "";
  return `${size}${name}${curveText}`.trim();
}

function describeCertificateBuffer(buffer) {
  const inform = pemText(buffer) ? "PEM" : "DER";
  const text = runOpenssl(
    ["x509", "-inform", inform, "-noout", "-text", "-nameopt", "RFC2253"],
    { input: buffer, encoding: "utf8", failureMessage: "Could not read this certificate" },
  );
  if (String(text).includes("PRIVATE KEY")) {
    throw httpError(500, "Certificate inspection stopped because the output was unexpected");
  }
  const sha256 = runOpenssl(
    ["x509", "-inform", inform, "-noout", "-fingerprint", "-sha256"],
    { input: buffer, encoding: "utf8", failureMessage: "Could not fingerprint this certificate" },
  );
  const sha1 = runOpenssl(
    ["x509", "-inform", inform, "-noout", "-fingerprint", "-sha1"],
    { input: buffer, encoding: "utf8", failureMessage: "Could not fingerprint this certificate" },
  );

  const subject = (text.match(/^\s+Subject:\s*(.+)$/m) || [])[1]?.trim() || "";
  const issuer = (text.match(/^\s+Issuer:\s*(.+)$/m) || [])[1]?.trim() || "";
  const notBefore = (text.match(/Not Before:\s*(.+)$/m) || [])[1]?.trim() || "";
  const notAfter = (text.match(/Not After\s*:\s*(.+)$/m) || [])[1]?.trim() || "";
  const algorithm = (text.match(/Public Key Algorithm:\s*(.+)$/m) || [])[1]?.trim() || "";
  const bitsMatch = text.match(/Public-Key:\s*\((\d+)\s*bit\)/i) || text.match(/RSA Public-Key:\s*\((\d+)\s*bit\)/i);
  const bits = bitsMatch ? Number(bitsMatch[1]) : null;
  const curve = (text.match(/ASN1 OID:\s*(.+)$/m) || [])[1]?.trim() || "";
  const subjectAltName = extensionValue(text, "X509v3 Subject Alternative Name:");
  const basicConstraints = extensionValue(text, "X509v3 Basic Constraints:");
  const keyUsage = extensionValue(text, "X509v3 Key Usage:");
  const extendedKeyUsage = extensionValue(text, "X509v3 Extended Key Usage:");

  return {
    format: inform.toLowerCase(),
    subject,
    issuer,
    commonName: commonNameFromDn(subject),
    notBefore,
    notAfter,
    serial: parseSerial(text),
    fingerprints: {
      sha256: parseFingerprint(sha256),
      sha1: parseFingerprint(sha1),
    },
    key: {
      algorithm,
      bits,
      curve: curve || null,
      summary: keyDescription(algorithm, bits, curve),
    },
    subjectAltName,
    basicConstraints,
    keyUsage,
    extendedKeyUsage,
    selfSigned: Boolean(subject) && normalizeDn(subject) === normalizeDn(issuer),
    text: String(text).trim(),
  };
}

function splitCertificates(buffer) {
  const text = pemText(buffer);
  if (!text) {
    return [buffer];
  }
  const matches = text.match(/-----BEGIN (?:TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE-----/g);
  return matches ? matches.map((pem) => Buffer.from(pem)) : [];
}

function mergeMetadata(parsed, metadata) {
  if (!metadata) {
    return parsed;
  }
  return {
    ...parsed,
    subject: parsed.subject || metadata.subject || "",
    issuer: parsed.issuer || metadata.issuer || "",
    commonName: parsed.commonName || metadata.commonName || "",
    notBefore: parsed.notBefore || metadata.notBefore || "",
    notAfter: parsed.notAfter || metadata.notAfter || "",
    subjectAltName: parsed.subjectAltName || metadata.subjectAltName || "",
    fingerprints: {
      sha256: parsed.fingerprints.sha256 || metadata.fingerprint || "",
      sha1: parsed.fingerprints.sha1 || "",
    },
  };
}

function publicCertificate(certificate) {
  const copy = { ...certificate };
  if (String(copy.text || "").includes("PRIVATE KEY")) {
    copy.text = "";
  }
  return copy;
}

function analyzeChain(leaf, certificates) {
  const links = [];
  let orderWrong = false;
  for (let index = 0; index < certificates.length - 1; index += 1) {
    const current = certificates[index];
    const next = certificates[index + 1];
    const matches = normalizeDn(current.issuer) === normalizeDn(next.subject);
    if (!matches) {
      orderWrong = true;
    }
    links.push({
      fromIndex: index + 1,
      toIndex: index + 2,
      issuer: current.issuer,
      nextSubject: next.subject,
      matches,
    });
  }

  const startsWithLeaf =
    certificates.length > 0 &&
    certificates[0].fingerprints.sha256 &&
    certificates[0].fingerprints.sha256 === leaf.fingerprints.sha256;
  if (certificates.length > 0 && !startsWithLeaf) {
    orderWrong = true;
  }

  const last = certificates[certificates.length - 1];
  const incomplete = !last?.selfSigned;
  const notes = [];
  if (certificates.length > 0 && !startsWithLeaf) {
    notes.push("The chain does not start with this certificate.");
  }
  if (links.some((link) => !link.matches)) {
    notes.push("A certificate issuer does not match the next certificate's subject.");
  }
  if (incomplete) {
    notes.push("The last certificate is not self-signed, so the chain is incomplete.");
  }
  if (!orderWrong && !incomplete) {
    notes.push("Each certificate is issued by the next, and the last certificate is self-signed.");
  }

  return {
    present: true,
    count: certificates.length,
    incomplete,
    orderWrong,
    startsWithLeaf: Boolean(startsWithLeaf),
    notes,
    links,
    certificates: certificates.map((certificate, index) =>
      publicCertificate({ ...certificate, index: index + 1 }),
    ),
  };
}

function inspectMaterial(projectRoot, storeName, certName = null) {
  if (certName) {
    assertSegment(certName, "Certificate name");
  }
  const storeReal = confinedStore(projectRoot, storeName);
  const base = certName || storeName;
  const certNameOnDisk = `${base}.crt`;
  const { filePath } = readRegularFile(storeReal, certNameOnDisk);
  const metadata = readCertMetadata(filePath);
  let certificate;
  try {
    certificate = mergeMetadata(describeCertificateBuffer(fs.readFileSync(filePath)), metadata);
  } catch (error) {
    if (!metadata) {
      throw error.statusCode ? error : httpError(400, "Could not read this certificate");
    }
    certificate = {
      format: "pem",
      subject: metadata.subject || "",
      issuer: metadata.issuer || "",
      commonName: metadata.commonName || "",
      notBefore: metadata.notBefore || "",
      notAfter: metadata.notAfter || "",
      serial: "",
      fingerprints: { sha256: metadata.fingerprint || "", sha1: "" },
      key: { algorithm: "", bits: null, curve: null, summary: "" },
      subjectAltName: metadata.subjectAltName || "",
      basicConstraints: "",
      keyUsage: "",
      extendedKeyUsage: "",
      selfSigned: normalizeDn(metadata.subject) === normalizeDn(metadata.issuer),
      text: "",
    };
  }
  certificate = publicCertificate({ ...certificate, sourceFile: certNameOnDisk });

  const chainName = `${base}-fullchain.pem`;
  let chain = {
    present: false,
    sourceFile: chainName,
    count: 0,
    incomplete: false,
    orderWrong: false,
    startsWithLeaf: false,
    notes: ["No full chain file is stored for this certificate."],
    links: [],
    certificates: [],
  };

  let chainLocated = null;
  try {
    chainLocated = readRegularFile(storeReal, chainName);
  } catch (error) {
    if (error.statusCode !== 404) {
      throw error;
    }
  }

  if (chainLocated) {
    try {
      const parts = splitCertificates(fs.readFileSync(chainLocated.filePath));
      if (parts.length === 0) {
        throw httpError(400, "Full chain file has no certificates");
      }
      const parsed = parts.map((part) => describeCertificateBuffer(part));
      chain = {
        ...analyzeChain(certificate, parsed),
        sourceFile: chainName,
      };
    } catch (error) {
      chain = {
        present: true,
        sourceFile: chainName,
        count: 0,
        incomplete: true,
        orderWrong: false,
        startsWithLeaf: false,
        notes: [error.statusCode ? error.message : "Could not read the full chain file."],
        links: [],
        certificates: [],
      };
    }
  }

  return {
    storeName,
    certName: certName || null,
    baseName: base,
    certificate,
    chain,
  };
}

function convertMaterial(projectRoot, options = {}) {
  const to = options.to === "pem" || options.to === "der" ? options.to : null;
  if (!to) {
    throw httpError(400, "Choose PEM or DER output");
  }
  const destination = options.destination || "download";
  if (!["download", "store", "both"].includes(destination)) {
    throw httpError(400, "Choose download, store, or both");
  }
  const source = options.source === "upload" ? "upload" : "store";
  const wantsStore = destination !== "download";

  let storeName = null;
  let storeReal = null;
  if (source === "store" || wantsStore) {
    if (typeof options.storeName !== "string" || options.storeName.length === 0) {
      throw httpError(400, "Store name is required");
    }
    storeName = options.storeName;
    storeReal = confinedStore(projectRoot, storeName);
  }

  let certName = null;
  if (typeof options.certName === "string" && options.certName.length > 0) {
    assertSegment(options.certName, "Certificate name");
    certName = options.certName;
  }
  const base = certName || storeName;

  let inputName = "converted.pem";
  let input;
  if (source === "store") {
    if (typeof options.fileName !== "string" || options.fileName.length === 0) {
      throw httpError(400, "Choose a file in the store");
    }
    inputName = options.fileName;
    if (!belongsToBase(inputName, base)) {
      throw httpError(400, "That file is not part of this certificate");
    }
    const located = readRegularFile(storeReal, inputName);
    input = fs.readFileSync(located.filePath);
  } else {
    input = decodeUpload(options.contentBase64);
    if (typeof options.fileName === "string" && options.fileName.length > 0) {
      assertSegment(options.fileName, "File name");
      inputName = options.fileName;
    }
  }

  const classified = classifyBuffer(input, inputName);
  if (!classified.convertible) {
    throw httpError(400, classified.reason);
  }
  if (classified.kind === "key" && options.confirmSecret !== true) {
    throw httpError(400, "Converting a private key requires confirmation");
  }

  const outputName =
    typeof options.outputName === "string" && options.outputName.length > 0
      ? options.outputName
      : defaultOutputName(inputName, classified.kind, to);
  assertOutputName(outputName);

  const output = withPrivateTemp((dir) => {
    const inPath = path.join(dir, "input");
    const outPath = path.join(dir, "output");
    fs.writeFileSync(inPath, input, { mode: 0o600 });
    const inform = classified.format === "der" ? "DER" : "PEM";
    const outform = to === "der" ? "DER" : "PEM";
    const command = classified.kind === "key" ? "pkey" : "x509";
    runOpenssl(
      [command, "-inform", inform, "-outform", outform, "-in", inPath, "-out", outPath],
      {
        failureMessage:
          classified.kind === "key"
            ? "Could not convert this private key. Encrypted keys are not supported here; use Change password."
            : "Could not convert this certificate",
      },
    );
    return fs.readFileSync(outPath);
  });

  const mode = classified.kind === "key" ? 0o600 : 0o644;
  let relativePath = null;
  if (wantsStore) {
    writeStoreFile(storeReal, outputName, output, options.overwrite === true, mode);
    relativePath = `./certs/${storeName}/${outputName}`;
  }

  return {
    message: relativePath ? `Saved ${relativePath}` : `Converted to ${to.toUpperCase()}`,
    fileName: outputName,
    relativePath,
    stored: Boolean(relativePath),
    kind: classified.kind,
    format: to,
    contentType: to === "pem" ? "application/x-pem-file" : "application/octet-stream",
    data: output,
  };
}

function assertRewritten(filePath, artifact, newPassword) {
  const accepted = passwordAccepted(filePath, artifact, newPassword);
  if (!accepted) {
    throw httpError(500, "Could not verify the updated file");
  }
  if (artifact === "key") {
    const encrypted = fileHeaderEncrypted(filePath);
    if (newPassword.length > 0 && !encrypted) {
      throw httpError(500, "Could not verify the updated private key");
    }
    if (newPassword.length === 0 && encrypted) {
      throw httpError(500, "Could not verify the updated private key");
    }
    return;
  }
  if (newPassword.length > 0 && passwordAccepted(filePath, artifact, `${newPassword}!`)) {
    throw httpError(500, "Could not verify the updated PKCS#12 file");
  }
  if (newPassword.length === 0 && passwordAccepted(filePath, artifact, "!")) {
    throw httpError(500, "Could not verify the updated PKCS#12 file");
  }
}

function rewriteKey(dest, currentPassword, newPassword) {
  const outTmp = tempInStore(path.dirname(dest));
  const env = baseEnv({
    [PASS_IN]: currentPassword,
    [PASS_OUT]: newPassword,
  });
  const args = ["pkey", "-in", dest, "-out", outTmp, "-passin", `env:${PASS_IN}`];
  if (newPassword.length > 0) {
    args.push("-aes-256-cbc", "-passout", `env:${PASS_OUT}`);
  }
  try {
    runOpenssl(args, { env, failureMessage: "Current password was not accepted" });
    fs.chmodSync(outTmp, 0o600);
    assertRewritten(outTmp, "key", newPassword);
    replaceRegularFile(dest, outTmp, 0o600);
  } finally {
    if (fs.existsSync(outTmp)) {
      shredFile(outTmp);
    }
  }
}

function rewritePkcs12(dest, currentPassword, newPassword) {
  const storeReal = path.dirname(dest);
  const id = crypto.randomBytes(9).toString("hex");
  const pemTmp = path.join(storeReal, `.ssl-gen-${id}.pem.tmp`);
  const outTmp = path.join(storeReal, `.ssl-gen-${id}.p12.tmp`);
  const env = baseEnv({
    [PASS_IN]: currentPassword,
    [PASS_OUT]: newPassword,
  });
  try {
    runOpenssl(
      ["pkcs12", "-in", dest, "-out", pemTmp, "-nodes", "-passin", `env:${PASS_IN}`],
      { env, failureMessage: "Current password was not accepted" },
    );
    fs.chmodSync(pemTmp, 0o600);
    runOpenssl(
      ["pkcs12", "-export", "-in", pemTmp, "-out", outTmp, "-passout", `env:${PASS_OUT}`],
      { env, failureMessage: "Could not write the PKCS#12 file" },
    );
    shredFile(pemTmp);
    fs.chmodSync(outTmp, 0o600);
    assertRewritten(outTmp, "p12", newPassword);
    replaceRegularFile(dest, outTmp, 0o600);
  } finally {
    if (fs.existsSync(pemTmp)) {
      shredFile(pemTmp);
    }
    if (fs.existsSync(outTmp)) {
      shredFile(outTmp);
    }
  }
}

function changeMaterialPassword(projectRoot, storeName, certName, options = {}) {
  const artifact = options.artifact === "p12" ? "p12" : options.artifact === "key" ? "key" : null;
  if (!artifact) {
    throw httpError(400, "Choose a private key or a PKCS#12 file");
  }
  const currentPassword = asPassword(options.currentPassword, "Current password");
  const newPassword = asPassword(options.newPassword, "New password");
  const confirmPassword = asPassword(options.confirmPassword, "Password confirmation");
  if (newPassword !== confirmPassword) {
    throw httpError(400, "New password and confirmation do not match");
  }
  if (certName) {
    assertSegment(certName, "Certificate name");
  }

  const storeReal = confinedStore(projectRoot, storeName);
  const base = certName || storeName;
  const fileName = artifact === "key" ? `${base}.key` : `${base}.p12`;
  const { filePath } = readRegularFile(storeReal, fileName);
  const passwordRequired = !passwordAccepted(filePath, artifact, "");
  if (passwordRequired && currentPassword.length === 0) {
    throw httpError(400, "Current password is required");
  }
  if (passwordRequired && !passwordAccepted(filePath, artifact, currentPassword)) {
    throw httpError(400, "Current password was not accepted");
  }
  if (!passwordRequired && newPassword.length === 0) {
    throw httpError(400, "Refusing to set an empty password on a file that already has no password");
  }

  const unlockPassword = passwordRequired ? currentPassword : "";
  if (artifact === "key") {
    rewriteKey(filePath, unlockPassword, newPassword);
  } else {
    rewritePkcs12(filePath, unlockPassword, newPassword);
  }

  return {
    message:
      newPassword.length === 0
        ? `Removed the password from ${fileName}`
        : `Password updated for ${fileName}`,
    fileName,
    encrypted: newPassword.length > 0,
    relativePath: `./certs/${storeName}/${fileName}`,
  };
}

function publicConversion(result) {
  return {
    message: result.message,
    fileName: result.fileName,
    relativePath: result.relativePath,
    stored: result.stored,
    kind: result.kind,
    format: result.format,
  };
}

module.exports = {
  changeMaterialPassword,
  convertMaterial,
  describeMaterial,
  inspectMaterial,
  publicConversion,
  shredFile,
};
