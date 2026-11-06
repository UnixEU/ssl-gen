const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-api-"));
fs.mkdirSync(path.join(projectRoot, "scripts"));
fs.copyFileSync(
  path.join(__dirname, "..", "..", ".env.example"),
  path.join(projectRoot, ".env.example"),
);
fs.writeFileSync(
  path.join(projectRoot, "scripts", "generate-certs.sh"),
  "#!/bin/sh\necho generated\n",
);

const previousRoot = process.env.PROJECT_ROOT;
process.env.PROJECT_ROOT = projectRoot;
const { app } = require("../server");
if (previousRoot === undefined) {
  delete process.env.PROJECT_ROOT;
} else {
  process.env.PROJECT_ROOT = previousRoot;
}

function request(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: server.address().port,
        path: urlPath,
        method,
        headers: payload
          ? {
              "Content-Type": "application/json",
              "Content-Length": payload.length,
            }
          : {},
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = {};
          if (text) {
            json = JSON.parse(text);
          }
          resolve({ status: res.statusCode, headers: res.headers, json });
        });
      },
    );
    req.on("error", reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

let server;

test.before(() => {
  server = app.listen(0, "127.0.0.1");
  return new Promise((resolve) => server.once("listening", resolve));
});

test.after(() => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
}));

test("config falls back to .env.example and does not create .env", async () => {
  const envPath = path.join(projectRoot, ".env");
  assert.equal(fs.existsSync(envPath), false);

  const response = await request("GET", "/api/config");
  assert.equal(response.status, 200);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(response.json.defaults.ROOT_CA_NAME, "my-root-ca");
  assert.equal(response.json.values.ROOT_CA_NAME, "my-root-ca");
  assert.equal(response.json.values.CERT_COMMON_NAME, "localhost");
  assert.equal(fs.existsSync(envPath), false);
});

test("a partial .env overlays only the keys it contains", async () => {
  const envPath = path.join(projectRoot, ".env");
  const original = "ROOT_CA_NAME=UnixEURootCA\nROOT_CA_COMMON_NAME=Kept Subject\n";
  fs.writeFileSync(envPath, original);

  const response = await request("GET", "/api/config");
  assert.equal(response.status, 200);
  assert.equal(response.json.values.ROOT_CA_NAME, "UnixEURootCA");
  assert.equal(response.json.values.ROOT_CA_COMMON_NAME, "Kept Subject");
  assert.equal(response.json.values.CERT_NAME, response.json.defaults.CERT_NAME);
  assert.equal(response.json.values.P12_PASSWORD, response.json.defaults.P12_PASSWORD);
  assert.equal(response.json.defaults.ROOT_CA_NAME, "my-root-ca");
  assert.equal(fs.readFileSync(envPath, "utf8"), original);
});

test("generate writes .env only when save is explicitly true", async () => {
  const envPath = path.join(projectRoot, ".env");
  const original = fs.readFileSync(envPath, "utf8");
  const values = {
    ROOT_CA_NAME: "secret-root",
    ROOT_CA_COUNTRY: "US",
    ROOT_CA_STATE: "California",
    ROOT_CA_LOCALITY: "San Francisco",
    ROOT_CA_ORGANIZATION: "Secret Org",
    ROOT_CA_ORGANIZATIONAL_UNIT: "IT Department",
    ROOT_CA_COMMON_NAME: "Secret Root CA",
    ROOT_CA_VALIDITY_DAYS: "3650",
    ROOT_CA_PASSPHRASE: "s3cret-pass",
    CERT_NAME: "secret-cert",
    CERT_COUNTRY: "US",
    CERT_STATE: "California",
    CERT_LOCALITY: "San Francisco",
    CERT_ORGANIZATION: "Secret Org",
    CERT_ORGANIZATIONAL_UNIT: "Web Services",
    CERT_COMMON_NAME: "localhost",
    CERT_DNS_NAMES: "localhost",
    CERT_IP_ADDRESSES: "",
    CERT_VALIDITY_DAYS: "365",
    KEY_TYPE: "ec",
    KEY_SIZE: "256",
    FORCE_REGENERATE: "no",
    EXPORT_P12: "yes",
    P12_PASSWORD: "secret-p12",
    WEBUI_BIND: "127.0.0.1",
    WEBUI_PORT: "8443",
  };

  const omitted = await request("POST", "/api/generate", { values });
  assert.equal(omitted.status, 200);
  assert.equal(omitted.json.success, true);
  assert.equal(fs.readFileSync(envPath, "utf8"), original);
  assert.equal(fs.existsSync(path.join(projectRoot, ".env.run")), false);

  const declined = await request("POST", "/api/generate", { values, save: false });
  assert.equal(declined.status, 200);
  assert.equal(fs.readFileSync(envPath, "utf8"), original);
  assert.equal(original.includes("s3cret-pass"), false);
  assert.equal(original.includes("Secret Root CA"), false);

  const saved = await request("POST", "/api/generate", { values, save: true });
  assert.equal(saved.status, 200);
  const written = fs.readFileSync(envPath, "utf8");
  assert.match(written, /ROOT_CA_NAME=secret-root/);
  assert.match(written, /ROOT_CA_COMMON_NAME=Secret Root CA/);
  assert.match(written, /ROOT_CA_PASSPHRASE=s3cret-pass/);
  assert.match(written, /P12_PASSWORD=secret-p12/);
  assert.equal(fs.existsSync(path.join(projectRoot, ".env.run")), false);
});
