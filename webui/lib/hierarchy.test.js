const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const { discoverStores, signedByRootCa } = require("./certs");

function openssl(args, cwd) {
  execFileSync("openssl", args, { cwd, stdio: "ignore" });
}

test("signedByRootCa compares normalized issuer and subject names", () => {
  const root = { subject: "CN = Hierarchy Root, O = UnixEU" };
  assert.equal(
    signedByRootCa(root, { issuer: "CN = Hierarchy Root, O = UnixEU" }),
    true,
  );
  assert.equal(
    signedByRootCa(root, { issuer: "issuer=CN=Hierarchy Root,O=UnixEU" }),
    true,
  );
  assert.equal(signedByRootCa(root, { issuer: "CN = Someone Else, O = UnixEU" }), false);
  assert.equal(signedByRootCa(root, null), false);
  assert.equal(signedByRootCa(null, { issuer: "CN = Hierarchy Root" }), false);
});

test("discoverStores places signed certificates under their Root CA", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-hierarchy-"));
  const storeName = "hierarchy-ca";
  const storePath = path.join(projectRoot, "certs", storeName);
  fs.mkdirSync(storePath, { recursive: true });

  openssl(
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-keyout",
      `${storeName}.key`,
      "-out",
      `${storeName}.crt`,
      "-days",
      "30",
      "-subj",
      "/CN=Hierarchy Root/O=UnixEU",
    ],
    storePath,
  );
  openssl(
    [
      "req",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-keyout",
      "api-local.key",
      "-out",
      "api-local.csr",
      "-subj",
      "/CN=api.localhost/O=UnixEU",
    ],
    storePath,
  );
  openssl(
    [
      "x509",
      "-req",
      "-in",
      "api-local.csr",
      "-CA",
      `${storeName}.crt`,
      "-CAkey",
      `${storeName}.key`,
      "-CAcreateserial",
      "-CAserial",
      "hierarchy-ca.srl",
      "-out",
      "api-local.crt",
      "-days",
      "10",
    ],
    storePath,
  );
  openssl(
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-keyout",
      "stranger.key",
      "-out",
      "stranger.crt",
      "-days",
      "5",
      "-subj",
      "/CN=Stranger",
    ],
    storePath,
  );
  fs.writeFileSync(path.join(storePath, "notes.crt"), "not a certificate\n");

  const stores = discoverStores(projectRoot);
  assert.equal(stores.length, 1);
  assert.equal(stores[0].metadata.commonName, "Hierarchy Root");
  assert.match(stores[0].metadata.issuer, /Hierarchy Root/);

  const byName = Object.fromEntries(stores[0].certificates.map((cert) => [cert.name, cert]));
  assert.deepEqual(Object.keys(byName).sort(), ["api-local", "notes", "stranger"]);
  assert.equal(byName["api-local"].signedByRoot, true);
  assert.equal(byName["api-local"].metadata.commonName, "api.localhost");
  assert.match(byName["api-local"].metadata.issuer, /Hierarchy Root/);
  assert.equal(byName.stranger.signedByRoot, false);
  assert.equal(byName.stranger.metadata.commonName, "Stranger");
  assert.equal(byName.notes.signedByRoot, false);
  assert.equal(byName.notes.metadata, null);
});
