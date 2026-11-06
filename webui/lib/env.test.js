const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { readEnvFile, readMergedEnv, validateConfig, writeEnvFile } = require("./env");

function baseConfig(overrides = {}) {
  return {
    ROOT_CA_NAME: "my-root-ca",
    ROOT_CA_COUNTRY: "US",
    ROOT_CA_STATE: "California",
    ROOT_CA_LOCALITY: "San Francisco",
    ROOT_CA_ORGANIZATION: "My Company",
    ROOT_CA_ORGANIZATIONAL_UNIT: "IT Department",
    ROOT_CA_COMMON_NAME: "My Local Root CA",
    ROOT_CA_VALIDITY_DAYS: "3650",
    ROOT_CA_PASSPHRASE: "",
    CERT_NAME: "my-local-cert",
    CERT_COUNTRY: "US",
    CERT_STATE: "California",
    CERT_LOCALITY: "San Francisco",
    CERT_ORGANIZATION: "My Company",
    CERT_ORGANIZATIONAL_UNIT: "Web Services",
    CERT_COMMON_NAME: "localhost",
    CERT_DNS_NAMES: "localhost",
    CERT_IP_ADDRESSES: "",
    CERT_VALIDITY_DAYS: "365",
    KEY_TYPE: "ec",
    KEY_SIZE: "256",
    FORCE_REGENERATE: "no",
    EXPORT_P12: "yes",
    P12_PASSWORD: "changeit",
    WEBUI_BIND: "127.0.0.1",
    WEBUI_PORT: "8443",
    ...overrides,
  };
}

test("KEY_SIZE accepts the sizes for the selected key type and rejects the other", () => {
  assert.deepEqual(validateConfig(baseConfig()), []);
  assert.deepEqual(validateConfig(baseConfig({ KEY_SIZE: "" })), []);
  assert.deepEqual(validateConfig(baseConfig({ KEY_SIZE: "384" })), []);
  assert.deepEqual(validateConfig(baseConfig({ KEY_SIZE: "521" })), []);
  assert.deepEqual(
    validateConfig(baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "2048" })),
    [],
  );
  assert.deepEqual(
    validateConfig(baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "3072" })),
    [],
  );
  assert.deepEqual(
    validateConfig(baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "4096" })),
    [],
  );
  assert.deepEqual(validateConfig(baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "" })), []);

  assert.match(
    validateConfig(baseConfig({ KEY_SIZE: "2048" })).join("\n"),
    /KEY_SIZE for ec must be 256, 384, or 521/,
  );
  assert.match(
    validateConfig(baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "256" })).join("\n"),
    /KEY_SIZE for rsa must be 2048, 3072, or 4096/,
  );
  assert.match(
    validateConfig(baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "1024" })).join("\n"),
    /KEY_SIZE for rsa must be 2048, 3072, or 4096/,
  );
});

test("saving configuration writes KEY_SIZE into the advanced section", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-env-"));
  const envPath = path.join(dir, ".env");
  writeEnvFile(envPath, baseConfig({ KEY_TYPE: "rsa", KEY_SIZE: "3072" }));
  const text = fs.readFileSync(envPath, "utf8");
  assert.match(text, /KEY_TYPE=rsa\n# Key size\./);
  assert.match(text, /KEY_SIZE=3072\n/);
  assert.equal(readEnvFile(envPath).KEY_SIZE, "3072");

  const legacy = path.join(dir, "legacy.env");
  fs.writeFileSync(legacy, "KEY_TYPE=ec\nROOT_CA_NAME=my-root-ca\n");
  const values = readEnvFile(legacy);
  assert.equal(values.KEY_SIZE, "");
  assert.equal(values.KEY_TYPE, "ec");
});

test("merged config uses .env.example and overlays only keys present in .env", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-merge-"));
  const examplePath = path.join(dir, ".env.example");
  const envPath = path.join(dir, ".env");
  writeEnvFile(
    examplePath,
    baseConfig({
      ROOT_CA_NAME: "from-example",
      ROOT_CA_COMMON_NAME: "Example Root CA",
      ROOT_CA_PASSPHRASE: "example-pass",
      P12_PASSWORD: "example-secret",
    }),
  );
  const partial = "ROOT_CA_NAME=from-env\nROOT_CA_PASSPHRASE=\n";
  fs.writeFileSync(envPath, partial);

  const merged = readMergedEnv(envPath, examplePath);
  assert.equal(merged.envExists, true);
  assert.equal(merged.values.ROOT_CA_NAME, "from-env");
  assert.equal(merged.values.ROOT_CA_PASSPHRASE, "");
  assert.equal(merged.values.ROOT_CA_COMMON_NAME, "Example Root CA");
  assert.equal(merged.values.P12_PASSWORD, "example-secret");
  assert.equal(merged.values.CERT_NAME, "my-local-cert");
  assert.equal(merged.defaults.ROOT_CA_NAME, "from-example");
  assert.equal(merged.defaults.ROOT_CA_PASSPHRASE, "example-pass");
  assert.equal(fs.readFileSync(envPath, "utf8"), partial);

  fs.unlinkSync(envPath);
  const fallback = readMergedEnv(envPath, examplePath);
  assert.equal(fallback.envExists, false);
  assert.equal(fallback.values.ROOT_CA_NAME, "from-example");
  assert.equal(fallback.values.P12_PASSWORD, "example-secret");
  assert.equal(fs.existsSync(envPath), false);
});
