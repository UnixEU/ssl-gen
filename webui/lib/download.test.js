const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const {
  discoverStores,
  readCertMetadata,
  resolveDownloadArtifact,
} = require("./certs");

function makeProject() {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-download-"));
  const storeName = "root-ca";
  const storePath = path.join(projectRoot, "certs", storeName);
  fs.mkdirSync(storePath, { recursive: true });
  fs.writeFileSync(path.join(storePath, `${storeName}.crt`), "ROOT CERT\n");
  fs.writeFileSync(path.join(storePath, `${storeName}.key`), "ROOT KEY\n");
  fs.writeFileSync(path.join(storePath, "leaf.crt"), "LEAF CERT\n");
  fs.writeFileSync(path.join(storePath, "leaf.key"), "LEAF KEY\n");
  fs.writeFileSync(path.join(storePath, "leaf-fullchain.pem"), "LEAF CHAIN\n");
  fs.writeFileSync(path.join(storePath, "leaf.p12"), "LEAF P12\n");
  return { projectRoot, storeName, storePath };
}

function expectStatus(fn, statusCode) {
  assert.throws(fn, (error) => {
    assert.equal(error.statusCode, statusCode);
    return true;
  });
}

test("resolveDownloadArtifact serves files inside the store", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  const crt = resolveDownloadArtifact(projectRoot, storeName, "leaf", "crt");
  assert.equal(crt.fileName, "leaf.crt");
  assert.equal(fs.readFileSync(crt.filePath, "utf8"), "LEAF CERT\n");
  assert.equal(path.dirname(crt.filePath), fs.realpathSync(storePath));

  const chain = resolveDownloadArtifact(projectRoot, storeName, "leaf", "fullchain");
  assert.equal(chain.fileName, "leaf-fullchain.pem");
  const p12 = resolveDownloadArtifact(projectRoot, storeName, "leaf", "p12");
  assert.equal(p12.fileName, "leaf.p12");
  const rootCrt = resolveDownloadArtifact(projectRoot, storeName, null, "crt");
  assert.equal(rootCrt.fileName, `${storeName}.crt`);
});

test("private key download requires confirmation", () => {
  const { projectRoot, storeName } = makeProject();
  expectStatus(
    () => resolveDownloadArtifact(projectRoot, storeName, "leaf", "key"),
    400,
  );
  expectStatus(
    () => resolveDownloadArtifact(projectRoot, storeName, null, "key", { confirm: false }),
    400,
  );

  const key = resolveDownloadArtifact(projectRoot, storeName, "leaf", "key", {
    confirm: true,
  });
  assert.equal(key.secret, true);
  assert.equal(fs.readFileSync(key.filePath, "utf8"), "LEAF KEY\n");
});

test("resolveDownloadArtifact rejects traversal and unknown artifacts", () => {
  const { projectRoot, storeName } = makeProject();
  const outside = path.join(projectRoot, "secret.txt");
  fs.writeFileSync(outside, "secret\n");

  expectStatus(
    () => resolveDownloadArtifact(projectRoot, "..", null, "crt"),
    400,
  );
  expectStatus(
    () => resolveDownloadArtifact(projectRoot, storeName, "../secret.txt", "crt"),
    400,
  );
  expectStatus(
    () => resolveDownloadArtifact(projectRoot, `${storeName}/../../secret.txt`, null, "crt"),
    400,
  );
  expectStatus(
    () => resolveDownloadArtifact(projectRoot, storeName, "leaf", "csr"),
    400,
  );
  expectStatus(
    () => resolveDownloadArtifact(projectRoot, storeName, "missing", "crt"),
    404,
  );
});

test("resolveDownloadArtifact rejects symlinks that leave the store", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-outside-"));
  fs.writeFileSync(path.join(outside, "escaped.crt"), "ESCAPED\n");
  fs.rmSync(path.join(storePath, "leaf-fullchain.pem"));
  fs.symlinkSync(path.join(outside, "escaped.crt"), path.join(storePath, "leaf-fullchain.pem"));

  expectStatus(
    () => resolveDownloadArtifact(projectRoot, storeName, "leaf", "fullchain"),
    404,
  );

  const linkedName = "linked-ca";
  const linkedOutside = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-linked-"));
  fs.writeFileSync(path.join(linkedOutside, `${linkedName}.crt`), "LINKED CERT\n");
  fs.writeFileSync(path.join(linkedOutside, `${linkedName}.key`), "LINKED KEY\n");
  fs.symlinkSync(linkedOutside, path.join(projectRoot, "certs", linkedName));

  expectStatus(
    () => resolveDownloadArtifact(projectRoot, linkedName, null, "crt"),
    400,
  );
});

test("discoverStores reports artifacts, relative path, and fingerprint", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-meta-"));
  const storeName = "meta-ca";
  const storePath = path.join(projectRoot, "certs", storeName);
  fs.mkdirSync(storePath, { recursive: true });
  const keyPath = path.join(storePath, `${storeName}.key`);
  const certPath = path.join(storePath, `${storeName}.crt`);
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:prime256v1",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "5",
    "-subj",
    "/CN=Meta Root",
  ]);
  fs.writeFileSync(path.join(storePath, "soon.crt"), fs.readFileSync(certPath));
  fs.writeFileSync(path.join(storePath, "soon.key"), "soon-key\n");

  const stores = discoverStores(projectRoot);
  assert.equal(stores.length, 1);
  assert.equal(stores[0].relativeCert, `./certs/${storeName}/${storeName}.crt`);
  assert.deepEqual(stores[0].artifacts, {
    crt: true,
    fullchain: false,
    p12: false,
    key: true,
  });
  assert.equal(stores[0].certificates[0].artifacts.crt, true);
  assert.equal(stores[0].certificates[0].artifacts.fullchain, false);
  assert.match(stores[0].metadata.fingerprint, /^[0-9A-F]{2}(?::[0-9A-F]{2})+$/);
  assert.match(stores[0].metadata.subject, /Meta Root/);
  assert.equal(readCertMetadata(certPath).fingerprint, stores[0].metadata.fingerprint);
});

test("download routes keep responses inside the certificate store", async () => {
  const { projectRoot, storeName } = makeProject();
  process.env.PROJECT_ROOT = projectRoot;
  const serverPath = require.resolve("../server");
  delete require.cache[serverPath];
  const { app } = require("../server");
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  async function request(urlPath) {
    const response = await fetch(`http://127.0.0.1:${port}${urlPath}`);
    const body = Buffer.from(await response.arrayBuffer());
    return {
      status: response.status,
      type: response.headers.get("content-type"),
      disposition: response.headers.get("content-disposition"),
      body: body.toString("utf8"),
    };
  }

  try {
    const crt = await request(
      `/api/stores/${storeName}/certificates/leaf/download/crt`,
    );
    assert.equal(crt.status, 200);
    assert.equal(crt.body, "LEAF CERT\n");
    assert.match(crt.disposition, /attachment; filename="leaf.crt"/);
    assert.match(crt.type, /application\/x-pem-file/);

    const denied = await request(`/api/stores/${storeName}/certificates/leaf/download/key`);
    assert.equal(denied.status, 400);
    assert.match(denied.body, /confirmation/);

    const key = await request(
      `/api/stores/${storeName}/certificates/leaf/download/key?confirm=1`,
    );
    assert.equal(key.status, 200);
    assert.equal(key.body, "LEAF KEY\n");
    assert.match(key.disposition, /filename="leaf.key"/);

    const escaped = await request("/api/stores/..%2F..%2Fetc/download/crt");
    assert.notEqual(escaped.status, 200);
    assert.doesNotMatch(escaped.body, /root:/);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    delete require.cache[serverPath];
  }
});
