const fs = require("fs");

const ENV_KEYS = [
  "ROOT_CA_NAME",
  "ROOT_CA_COUNTRY",
  "ROOT_CA_STATE",
  "ROOT_CA_LOCALITY",
  "ROOT_CA_ORGANIZATION",
  "ROOT_CA_ORGANIZATIONAL_UNIT",
  "ROOT_CA_COMMON_NAME",
  "ROOT_CA_VALIDITY_DAYS",
  "ROOT_CA_PASSPHRASE",
  "CERT_NAME",
  "CERT_COUNTRY",
  "CERT_STATE",
  "CERT_LOCALITY",
  "CERT_ORGANIZATION",
  "CERT_ORGANIZATIONAL_UNIT",
  "CERT_COMMON_NAME",
  "CERT_DNS_NAMES",
  "CERT_IP_ADDRESSES",
  "CERT_VALIDITY_DAYS",
  "KEY_TYPE",
  "FORCE_REGENERATE",
  "EXPORT_P12",
  "P12_PASSWORD",
  "WEBUI_PORT",
  "WEBUI_BIND",
];

const ENV_SECTIONS = {
  rootCa: {
    title: "Root CA",
    keys: [
      "ROOT_CA_NAME",
      "ROOT_CA_COUNTRY",
      "ROOT_CA_STATE",
      "ROOT_CA_LOCALITY",
      "ROOT_CA_ORGANIZATION",
      "ROOT_CA_ORGANIZATIONAL_UNIT",
      "ROOT_CA_COMMON_NAME",
      "ROOT_CA_VALIDITY_DAYS",
      "ROOT_CA_PASSPHRASE",
    ],
  },
  certificate: {
    title: "Certificate",
    keys: [
      "CERT_NAME",
      "CERT_COUNTRY",
      "CERT_STATE",
      "CERT_LOCALITY",
      "CERT_ORGANIZATION",
      "CERT_ORGANIZATIONAL_UNIT",
      "CERT_COMMON_NAME",
      "CERT_DNS_NAMES",
      "CERT_IP_ADDRESSES",
      "CERT_VALIDITY_DAYS",
    ],
  },
  advanced: {
    title: "Advanced",
    keys: ["KEY_TYPE", "FORCE_REGENERATE", "EXPORT_P12", "P12_PASSWORD"],
  },
  webui: {
    title: "Web UI",
    keys: ["WEBUI_BIND", "WEBUI_PORT"],
  },
};

const ENV_COMMENTS = {
  ROOT_CA_NAME: "Root CA identity and file naming",
  ROOT_CA_COUNTRY: "Root CA distinguished name fields",
  ROOT_CA_PASSPHRASE:
    "Optional passphrase to encrypt the Root CA private key (leave empty for none)",
  CERT_NAME: "SSL certificate identity and file naming",
  CERT_COUNTRY: "SSL certificate distinguished name fields",
  CERT_DNS_NAMES:
    "Subject Alternative Names (SAN), separated by commas\n# IP addresses in this list are auto-detected and added as IP SAN entries",
  CERT_IP_ADDRESSES:
    "Optional additional IP SAN entries, separated by commas",
  CERT_VALIDITY_DAYS: "SSL certificate validity in days",
  KEY_TYPE: "Key algorithm: ec (P-256, default) or rsa",
  FORCE_REGENERATE:
    "Overwrite an existing certificate with the same CERT_NAME: yes or no",
  EXPORT_P12: "Export a PKCS#12 (.p12) bundle: yes or no",
  P12_PASSWORD: "Password used for the exported .p12 file",
  WEBUI_BIND: "Bind address for the web UI (localhost only)",
  WEBUI_PORT: "Port for the web UI on the bind address",
};

function trim(value) {
  return String(value).trim();
}

function parseEnvFile(content) {
  const values = {};
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    if (!line || line.startsWith("#")) {
      continue;
    }

    const normalized = line.replace(/^\s*export\s+/, "");
    const separator = normalized.indexOf("=");
    if (separator === -1) {
      continue;
    }

    const key = trim(normalized.slice(0, separator));
    let value = normalized.slice(separator + 1);

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    values[key] = value;
  }

  return values;
}

function readEnvFile(envPath) {
  if (!fs.existsSync(envPath)) {
    throw new Error(`.env file not found at ${envPath}`);
  }

  const content = fs.readFileSync(envPath, "utf8");
  const values = parseEnvFile(content);

  for (const key of ENV_KEYS) {
    if (!(key in values)) {
      values[key] = "";
    }
  }

  return values;
}

function serializeEnvFile(values) {
  const emitted = new Set();
  const lines = [];

  const writeKey = (key) => {
    if (emitted.has(key)) {
      return;
    }

    const comment = ENV_COMMENTS[key];
    if (comment) {
      for (const commentLine of comment.split("\n")) {
        lines.push(`# ${commentLine}`);
      }
    }

    const value = values[key] ?? "";
    lines.push(`${key}=${value}`);
    emitted.add(key);
  };

  for (const section of Object.values(ENV_SECTIONS)) {
    for (const key of section.keys) {
      writeKey(key);
    }
    lines.push("");
  }

  for (const key of ENV_KEYS) {
    writeKey(key);
  }

  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }

  return `${lines.join("\n")}\n`;
}

function writeEnvFile(envPath, values) {
  const content = serializeEnvFile(values);
  fs.writeFileSync(envPath, content, "utf8");
  return content;
}

function validateConfig(values) {
  const errors = [];

  const requireValue = (key, label) => {
    if (!trim(values[key] ?? "")) {
      errors.push(`${label} is required`);
    }
  };

  const safeName = (key, label) => {
    const value = values[key] ?? "";
    if (value && !/^[a-zA-Z0-9._-]+$/.test(value)) {
      errors.push(
        `${label} may only contain letters, numbers, dots, underscores, and hyphens`,
      );
    }
  };

  const country = (key, label) => {
    const value = values[key] ?? "";
    if (value && !/^[A-Za-z]{2}$/.test(value)) {
      errors.push(`${label} must be a two-letter country code`);
    }
  };

  const positiveInt = (key, label) => {
    const value = values[key] ?? "";
    if (!/^[0-9]+$/.test(value) || Number(value) <= 0) {
      errors.push(`${label} must be a positive integer`);
    }
  };

  requireValue("ROOT_CA_NAME", "ROOT_CA_NAME");
  requireValue("CERT_NAME", "CERT_NAME");
  requireValue("CERT_COMMON_NAME", "CERT_COMMON_NAME");
  requireValue("CERT_DNS_NAMES", "CERT_DNS_NAMES");

  safeName("ROOT_CA_NAME", "ROOT_CA_NAME");
  safeName("CERT_NAME", "CERT_NAME");
  country("ROOT_CA_COUNTRY", "ROOT_CA_COUNTRY");
  country("CERT_COUNTRY", "CERT_COUNTRY");
  positiveInt("ROOT_CA_VALIDITY_DAYS", "ROOT_CA_VALIDITY_DAYS");
  positiveInt("CERT_VALIDITY_DAYS", "CERT_VALIDITY_DAYS");

  if (!["ec", "rsa"].includes(values.KEY_TYPE ?? "ec")) {
    errors.push("KEY_TYPE must be 'ec' or 'rsa'");
  }

  const dnsNames = (values.CERT_DNS_NAMES ?? "")
    .split(",")
    .map(trim)
    .filter(Boolean);
  const ipAddresses = (values.CERT_IP_ADDRESSES ?? "")
    .split(",")
    .map(trim)
    .filter(Boolean);

  if (dnsNames.length + ipAddresses.length === 0) {
    errors.push(
      "At least one SAN entry is required in CERT_DNS_NAMES or CERT_IP_ADDRESSES",
    );
  }

  if (!dnsNames.includes(trim(values.CERT_COMMON_NAME ?? ""))) {
    errors.push("CERT_COMMON_NAME must appear in CERT_DNS_NAMES");
  }

  const bind = trim(values.WEBUI_BIND ?? "127.0.0.1");
  if (bind !== "127.0.0.1") {
    errors.push("WEBUI_BIND must be 127.0.0.1");
  }

  const port = Number(values.WEBUI_PORT ?? "8443");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    errors.push("WEBUI_PORT must be a valid port number");
  }

  return errors;
}

module.exports = {
  ENV_SECTIONS,
  readEnvFile,
  writeEnvFile,
  validateConfig,
};