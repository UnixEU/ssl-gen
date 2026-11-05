const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const CERTS_DIR_NAME = "certs";
const SAFE_NAME_PATTERN = /^[a-zA-Z0-9._-]+$/;

const DOWNLOAD_ARTIFACTS = {
  crt: {
    extension: ".crt",
    contentType: "application/x-pem-file",
  },
  fullchain: {
    extension: "-fullchain.pem",
    contentType: "application/x-pem-file",
  },
  p12: {
    extension: ".p12",
    contentType: "application/x-pkcs12",
  },
  key: {
    extension: ".key",
    contentType: "application/octet-stream",
    secret: true,
  },
};

function getCertsRoot(projectRoot) {
  return path.join(projectRoot, CERTS_DIR_NAME);
}

function validateSafeName(value, label) {
  if (!SAFE_NAME_PATTERN.test(value)) {
    throw new Error(
      `${label} may only contain letters, numbers, dots, underscores, and hyphens`,
    );
  }
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function withStatus(error, statusCode) {
  error.statusCode = error.statusCode || statusCode;
  return error;
}

function listEntries(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return [];
  }

  return fs
    .readdirSync(dirPath, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);
}

function readCertMetadata(certPath) {
  if (!fs.existsSync(certPath)) {
    return null;
  }

  try {
    const text = execFileSync(
      "openssl",
      [
        "x509",
        "-in",
        certPath,
        "-noout",
        "-subject",
        "-dates",
        "-fingerprint",
        "-sha256",
        "-ext",
        "subjectAltName",
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );

    const subject = (text.match(/subject=([^\n]+)/) || [])[1] ?? "";
    const notBefore = (text.match(/notBefore=([^\n]+)/) || [])[1] ?? "";
    const notAfter = (text.match(/notAfter=([^\n]+)/) || [])[1] ?? "";
    const fingerprint = (text.match(/Fingerprint=([0-9A-Fa-f:]+)/i) || [])[1] ?? "";
    const sanMatch = text.match(/X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)/);
    const subjectAltName = sanMatch ? sanMatch[1].trim() : "";

    return {
      subject,
      notBefore,
      notAfter,
      subjectAltName,
      fingerprint,
    };
  } catch {
    return null;
  }
}

function isCertificateStore(storePath, storeName) {
  const rootCert = path.join(storePath, `${storeName}.crt`);
  const rootKey = path.join(storePath, `${storeName}.key`);
  return fs.existsSync(rootCert) && fs.existsSync(rootKey);
}

function getStorePath(projectRoot, storeName) {
  validateSafeName(storeName, "Store name");
  const storePath = path.join(getCertsRoot(projectRoot), storeName);

  if (!isCertificateStore(storePath, storeName)) {
    throw new Error(`Certificate store '${storeName}' was not found`);
  }

  return storePath;
}

function listDownloadArtifacts(storePath, baseName) {
  const artifacts = {};

  for (const [kind, spec] of Object.entries(DOWNLOAD_ARTIFACTS)) {
    const filePath = path.join(storePath, `${baseName}${spec.extension}`);

    try {
      artifacts[kind] = fs.lstatSync(filePath).isFile();
    } catch {
      artifacts[kind] = false;
    }
  }

  return artifacts;
}

function relativeCertPath(storeName, baseName) {
  return `./${CERTS_DIR_NAME}/${storeName}/${baseName}.crt`;
}

function isDirectChild(parent, candidate) {
  return path.dirname(candidate) === parent;
}

function resolveDownloadArtifact(projectRoot, storeName, certName, artifact, options = {}) {
  const spec = DOWNLOAD_ARTIFACTS[artifact];
  if (!spec) {
    throw httpError(400, "Unknown artifact");
  }

  try {
    validateSafeName(storeName, "Store name");
  } catch (error) {
    throw withStatus(error, 400);
  }

  const baseName = certName || storeName;
  if (certName) {
    try {
      validateSafeName(certName, "Certificate name");
    } catch (error) {
      throw withStatus(error, 400);
    }
  }

  if (spec.secret && options.confirm !== true) {
    throw httpError(400, "Private key download requires confirmation");
  }

  const certsRoot = path.resolve(getCertsRoot(projectRoot));
  const storePath = path.resolve(certsRoot, storeName);
  const fileName = `${baseName}${spec.extension}`;
  const filePath = path.resolve(storePath, fileName);

  if (!isDirectChild(certsRoot, storePath) || !isDirectChild(storePath, filePath)) {
    throw httpError(400, "Artifact path escapes the certificate store");
  }

  let resolvedStore;
  try {
    resolvedStore = getStorePath(projectRoot, storeName);
  } catch (error) {
    throw withStatus(error, 404);
  }

  if (path.resolve(resolvedStore) !== storePath) {
    throw httpError(400, "Artifact path escapes the certificate store");
  }

  let fileStat;
  try {
    fileStat = fs.lstatSync(filePath);
  } catch {
    throw httpError(404, "Artifact was not found");
  }

  if (!fileStat.isFile()) {
    throw httpError(404, "Artifact was not found");
  }

  let certsRootReal;
  let fileReal;
  try {
    certsRootReal = fs.realpathSync(certsRoot);
    fileReal = fs.realpathSync(filePath);
  } catch {
    throw httpError(404, "Artifact was not found");
  }

  const relativeReal = path.relative(certsRootReal, fileReal);
  const expected = path.join(storeName, fileName);
  if (relativeReal !== expected) {
    throw httpError(400, "Artifact path escapes the certificate store");
  }

  return {
    filePath: fileReal,
    fileName,
    contentType: spec.contentType,
    secret: Boolean(spec.secret),
  };
}

function discoverStores(projectRoot) {
  const certsRoot = getCertsRoot(projectRoot);

  if (!fs.existsSync(certsRoot)) {
    return [];
  }

  const stores = [];

  for (const entry of fs.readdirSync(certsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith(".")) {
      continue;
    }

    const storePath = path.join(certsRoot, entry.name);

    if (!isCertificateStore(storePath, entry.name)) {
      continue;
    }

    const files = listEntries(storePath);
    const certNames = new Set();

    for (const file of files) {
      const match = file.match(/^(.+)\.crt$/);
      if (!match) {
        continue;
      }

      const certName = match[1];
      if (certName === entry.name) {
        continue;
      }

      certNames.add(certName);
    }

    const certificates = [...certNames].sort().map((certName) => {
      const certPath = path.join(storePath, `${certName}.crt`);
      const keyPath = path.join(storePath, `${certName}.key`);
      const metadata = readCertMetadata(certPath);

      return {
        name: certName,
        files: files.filter(
          (file) =>
            file.startsWith(`${certName}.`) || file === `${certName}-extensions.cnf`,
        ),
        hasKey: fs.existsSync(keyPath),
        artifacts: listDownloadArtifacts(storePath, certName),
        relativeCert: relativeCertPath(entry.name, certName),
        metadata,
      };
    });

    stores.push({
      name: entry.name,
      path: storePath,
      relativePath: `./${CERTS_DIR_NAME}/${entry.name}`,
      relativeCert: relativeCertPath(entry.name, entry.name),
      rootCert: path.join(storePath, `${entry.name}.crt`),
      rootKey: path.join(storePath, `${entry.name}.key`),
      artifacts: listDownloadArtifacts(storePath, entry.name),
      metadata: readCertMetadata(path.join(storePath, `${entry.name}.crt`)),
      certificates,
      files,
    });
  }

  return stores.sort((a, b) => a.name.localeCompare(b.name));
}

function certificateFileNames(certName) {
  return [
    `${certName}.key`,
    `${certName}.csr`,
    `${certName}.crt`,
    `${certName}.pem`,
    `${certName}-fullchain.pem`,
    `${certName}.p12`,
    `${certName}-extensions.cnf`,
  ];
}

function deleteCertificate(projectRoot, storeName, certName) {
  validateSafeName(certName, "Certificate name");
  const storePath = getStorePath(projectRoot, storeName);
  const certPath = path.join(storePath, `${certName}.crt`);
  const keyPath = path.join(storePath, `${certName}.key`);

  if (!fs.existsSync(certPath) && !fs.existsSync(keyPath)) {
    throw new Error(`Certificate '${certName}' was not found in '${storeName}'`);
  }

  const removed = [];

  for (const fileName of certificateFileNames(certName)) {
    const filePath = path.join(storePath, fileName);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      removed.push(fileName);
    }
  }

  return {
    storeName,
    certName,
    removed,
  };
}

function deleteStore(projectRoot, storeName) {
  const storePath = getStorePath(projectRoot, storeName);
  fs.rmSync(storePath, { recursive: true, force: true });

  return {
    storeName,
    path: storePath,
  };
}

function parseSubjectDn(subjectLine = "") {
  const cleaned = subjectLine.replace(/^subject=/, "").trim();
  const fields = {};

  for (const part of cleaned.split(/,\s*/)) {
    const separator = part.indexOf("=");
    if (separator === -1) {
      continue;
    }

    fields[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
  }

  return {
    ROOT_CA_COUNTRY: fields.C || "",
    ROOT_CA_STATE: fields.ST || "",
    ROOT_CA_LOCALITY: fields.L || "",
    ROOT_CA_ORGANIZATION: fields.O || "",
    ROOT_CA_ORGANIZATIONAL_UNIT: fields.OU || "",
    ROOT_CA_COMMON_NAME: fields.CN || "",
  };
}

function detectKeyType(keyPath) {
  try {
    execFileSync("openssl", ["rsa", "-in", keyPath, "-noout"], { stdio: "ignore" });
    return "rsa";
  } catch {
    return "ec";
  }
}

function isKeyEncrypted(keyPath) {
  const content = fs.readFileSync(keyPath, "utf8");
  return content.includes("ENCRYPTED");
}

function validityDaysFromMetadata(metadata) {
  if (!metadata?.notBefore || !metadata?.notAfter) {
    return "";
  }

  const start = new Date(metadata.notBefore);
  const end = new Date(metadata.notAfter);

  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return "";
  }

  return String(Math.max(1, Math.round((end.getTime() - start.getTime()) / 86400000)));
}

function buildReuseConfig(projectRoot, storeName, certDefaults = {}) {
  const storePath = getStorePath(projectRoot, storeName);
  const rootKey = path.join(storePath, `${storeName}.key`);
  const rootCert = path.join(storePath, `${storeName}.crt`);
  const metadata = readCertMetadata(rootCert);
  const dn = parseSubjectDn(metadata?.subject || "");

  return {
    values: {
      ROOT_CA_NAME: storeName,
      ROOT_CA_COUNTRY: dn.ROOT_CA_COUNTRY,
      ROOT_CA_STATE: dn.ROOT_CA_STATE,
      ROOT_CA_LOCALITY: dn.ROOT_CA_LOCALITY,
      ROOT_CA_ORGANIZATION: dn.ROOT_CA_ORGANIZATION,
      ROOT_CA_ORGANIZATIONAL_UNIT: dn.ROOT_CA_ORGANIZATIONAL_UNIT,
      ROOT_CA_COMMON_NAME: dn.ROOT_CA_COMMON_NAME,
      ROOT_CA_VALIDITY_DAYS: validityDaysFromMetadata(metadata),
      ROOT_CA_PASSPHRASE: "",
      CERT_NAME: "new-cert",
      CERT_COUNTRY: certDefaults.CERT_COUNTRY || dn.ROOT_CA_COUNTRY || "US",
      CERT_STATE: certDefaults.CERT_STATE || dn.ROOT_CA_STATE || "",
      CERT_LOCALITY: certDefaults.CERT_LOCALITY || dn.ROOT_CA_LOCALITY || "",
      CERT_ORGANIZATION: certDefaults.CERT_ORGANIZATION || dn.ROOT_CA_ORGANIZATION || "",
      CERT_ORGANIZATIONAL_UNIT:
        certDefaults.CERT_ORGANIZATIONAL_UNIT || "Web Services",
      CERT_COMMON_NAME: certDefaults.CERT_COMMON_NAME || "localhost",
      CERT_DNS_NAMES: certDefaults.CERT_DNS_NAMES || "localhost",
      CERT_IP_ADDRESSES: certDefaults.CERT_IP_ADDRESSES || "",
      CERT_VALIDITY_DAYS: certDefaults.CERT_VALIDITY_DAYS || "365",
      KEY_TYPE: detectKeyType(rootKey),
      FORCE_REGENERATE: "no",
      EXPORT_P12: certDefaults.EXPORT_P12 || "yes",
      P12_PASSWORD: certDefaults.P12_PASSWORD || "changeit",
    },
    encryptedKey: isKeyEncrypted(rootKey),
  };
}

module.exports = {
  CERTS_DIR_NAME,
  DOWNLOAD_ARTIFACTS,
  getCertsRoot,
  discoverStores,
  deleteStore,
  deleteCertificate,
  buildReuseConfig,
  readCertMetadata,
  resolveDownloadArtifact,
};