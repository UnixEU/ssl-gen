const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const { discoverStores } = require("./certs");
const { applyImport, exportArchive, previewImport } = require("./archive");
const { packArchive, packTar, unpackArchive } = require("./tar");

function makeProject() {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-archive-"));
  const alpha = addStore(projectRoot, "alpha-ca");
  const beta = addStore(projectRoot, "beta-ca");
  return { projectRoot, alpha, beta };
}

function addStore(projectRoot, storeName) {
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
    "30",
    "-subj",
    `/CN=${storeName}`,
  ]);
  fs.writeFileSync(path.join(storePath, "leaf.crt"), fs.readFileSync(certPath));
  fs.writeFileSync(path.join(storePath, "leaf.key"), `KEY ${storeName}\n`);
  fs.writeFileSync(path.join(storePath, "leaf.pem"), "LEAF PEM\n");
  fs.writeFileSync(path.join(storePath, "leaf-fullchain.pem"), "LEAF CHAIN\n");
  fs.writeFileSync(path.join(storePath, "leaf.p12"), "P12_PASSWORD=changeit\n");
  fs.writeFileSync(path.join(storePath, "leaf-extensions.cnf"), "SAN\n");
  fs.writeFileSync(path.join(storePath, "other.crt"), "OTHER\n");
  fs.writeFileSync(path.join(storePath, "notes.txt"), "not a certificate\n");
  return { storeName, storePath };
}

function namesOf(archive) {
  return unpackArchive(archive.data).map((entry) => entry.name);
}

function manifestOf(archive) {
  const entry = unpackArchive(archive.data).find((item) => item.name === "manifest.json");
  assert.ok(entry, "manifest.json missing");
  return JSON.parse(entry.data.toString("utf8"));
}

function assertNoSecrets(value) {
  const json = JSON.stringify(value);
  assert.doesNotMatch(json, /passphrase/i);
  assert.doesNotMatch(json, /password/i);
  assert.doesNotMatch(json, /changeit/);
}

function expectStatus(fn, statusCode, pattern) {
  assert.throws(fn, (error) => {
    assert.equal(error.statusCode, statusCode);
    if (pattern) {
      assert.match(error.message, pattern);
    }
    return true;
  });
}

test("export omits private keys by default and writes a safe manifest", () => {
  const { projectRoot, alpha } = makeProject();
  const archive = exportArchive(projectRoot, { scope: "store", storeName: alpha.storeName });
  const names = namesOf(archive);

  assert.equal(archive.fileName, "ssl-gen-alpha-ca.tar.gz");
  assert.equal(archive.includeKeys, false);
  assert.ok(names.includes("manifest.json"));
  assert.ok(names.includes("alpha-ca/alpha-ca.crt"));
  assert.ok(names.includes("alpha-ca/leaf.crt"));
  assert.ok(names.includes("alpha-ca/leaf.pem"));
  assert.ok(names.includes("alpha-ca/leaf-fullchain.pem"));
  assert.ok(names.includes("alpha-ca/leaf-extensions.cnf"));
  assert.equal(names.some((name) => name.endsWith(".key") || name.endsWith(".p12")), false);
  assert.equal(names.includes("alpha-ca/notes.txt"), false);

  const manifest = manifestOf(archive);
  assert.equal(manifest.scope, "store");
  assert.equal(manifest.store, "alpha-ca");
  assert.equal(manifest.certificate, null);
  assert.equal(Number.isNaN(Date.parse(manifest.exportedAt)), false);
  const root = manifest.entries.find((entry) => entry.name === "alpha-ca");
  const leaf = manifest.entries.find((entry) => entry.name === "leaf");
  assert.match(root.notAfter, /GMT|UTC/);
  assert.equal(leaf.notAfter, root.notAfter);
  assert.ok(leaf.files.includes("alpha-ca/leaf.crt"));
  assertNoSecrets(manifest);
  assert.equal(JSON.stringify(manifest).includes("KEY alpha-ca"), false);
});

test("including private keys requires confirmation", () => {
  const { projectRoot, alpha } = makeProject();
  expectStatus(
    () =>
      exportArchive(projectRoot, {
        scope: "store",
        storeName: alpha.storeName,
        includeKeys: true,
      }),
    400,
    /confirmation/,
  );

  const archive = exportArchive(projectRoot, {
    scope: "store",
    storeName: alpha.storeName,
    includeKeys: true,
    confirmKeys: true,
  });
  const names = namesOf(archive);
  assert.ok(names.includes("alpha-ca/alpha-ca.key"));
  assert.ok(names.includes("alpha-ca/leaf.key"));
  assert.ok(names.includes("alpha-ca/leaf.p12"));
  assertNoSecrets(manifestOf(archive));
});

test("certificate export is a subset and all-stores export includes every store", () => {
  const { projectRoot, alpha } = makeProject();
  const subset = exportArchive(projectRoot, {
    scope: "certificate",
    storeName: alpha.storeName,
    certName: "leaf",
    includeKeys: true,
    confirmKeys: true,
  });
  const subsetNames = namesOf(subset);
  assert.equal(subset.fileName, "ssl-gen-alpha-ca-leaf.tar.gz");
  assert.ok(subsetNames.includes("alpha-ca/leaf.key"));
  assert.ok(subsetNames.includes("alpha-ca/alpha-ca.crt"));
  assert.equal(subsetNames.includes("alpha-ca/alpha-ca.key"), false);
  assert.equal(subsetNames.includes("alpha-ca/other.crt"), false);
  assert.equal(subsetNames.some((name) => name.startsWith("beta-ca/")), false);

  const everything = exportArchive(projectRoot, { scope: "all" });
  const allNames = namesOf(everything);
  assert.equal(everything.fileName, "ssl-gen-certs.tar.gz");
  assert.ok(allNames.includes("alpha-ca/leaf.crt"));
  assert.ok(allNames.includes("beta-ca/beta-ca.crt"));
  assert.equal(allNames.some((name) => name.endsWith(".key")), false);
  assert.equal(manifestOf(everything).store, null);
});

test("export skips symlink files and refuses a certs directory symlink", () => {
  const { projectRoot, alpha } = makeProject();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-outside-"));
  fs.writeFileSync(path.join(outside, "escaped.crt"), "ESCAPED-SECRET\n");
  fs.symlinkSync(path.join(outside, "escaped.crt"), path.join(alpha.storePath, "linked.crt"));

  const archive = exportArchive(projectRoot, { scope: "store", storeName: alpha.storeName });
  assert.equal(archive.data.includes(Buffer.from("ESCAPED-SECRET")), false);
  assert.equal(namesOf(archive).includes("alpha-ca/linked.crt"), false);

  const linkedProject = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-linked-project-"));
  fs.symlinkSync(path.join(projectRoot, "certs"), path.join(linkedProject, "certs"));
  expectStatus(
    () => exportArchive(linkedProject, { scope: "store", storeName: alpha.storeName }),
    400,
    /escapes/,
  );
});

test("encrypted export round-trips without putting the passphrase in the manifest", () => {
  const { projectRoot, alpha } = makeProject();
  const passphrase = "archive-secret-value";
  const archive = exportArchive(projectRoot, {
    scope: "certificate",
    storeName: alpha.storeName,
    certName: "leaf",
    includeKeys: true,
    confirmKeys: true,
    encrypt: true,
    passphrase,
  });

  assert.equal(archive.fileName, "ssl-gen-alpha-ca-leaf.tar.gz.enc");
  assert.equal(archive.data.subarray(0, 8).toString("ascii"), "Salted__");
  assert.equal(archive.data.includes(Buffer.from("KEY alpha-ca")), false);
  assert.equal(archive.data.includes(Buffer.from(passphrase)), false);
  assertNoSecrets(archive.manifest);

  expectStatus(
    () => previewImport(projectRoot, archive.data, {}),
    400,
    /passphrase/,
  );
  expectStatus(
    () => previewImport(projectRoot, archive.data, { passphrase: "wrong-passphrase" }),
    400,
    /decrypt/,
  );

  const preview = previewImport(projectRoot, archive.data, { passphrase });
  assert.equal(preview.encrypted, true);
  assert.equal(preview.files.some((file) => file.secret && file.fileName === "leaf.key"), true);
  assertNoSecrets(preview.manifest);
});

test("preview is a dry run and import refreshes a public store", () => {
  const source = makeProject();
  const archive = exportArchive(source.projectRoot, {
    scope: "certificate",
    storeName: "alpha-ca",
    certName: "leaf",
  });
  const destination = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-import-"));

  const preview = previewImport(destination, archive.data, { policy: "skip" });
  assert.equal(fs.existsSync(path.join(destination, "certs")), false);
  assert.equal(preview.summary.create > 0, true);
  assert.equal(preview.files.some((file) => file.secret), false);

  const imported = applyImport(destination, archive.data, { policy: "skip" });
  const stores = discoverStores(destination);
  assert.equal(stores.length, 1);
  assert.equal(stores[0].name, "alpha-ca");
  assert.deepEqual(
    stores[0].certificates.map((cert) => cert.name),
    ["leaf"],
  );
  assert.equal(stores[0].artifacts.key, false);
  assert.equal(fs.existsSync(path.join(destination, "certs", "alpha-ca", "leaf.key")), false);
  assert.equal(fs.existsSync(path.join(destination, "manifest.json")), false);
  assert.equal(imported.stores.length, 1);
});

test("conflict policies skip, rename, and overwrite", () => {
  const source = makeProject();
  const archive = exportArchive(source.projectRoot, {
    scope: "store",
    storeName: "alpha-ca",
    includeKeys: true,
    confirmKeys: true,
  });
  const destination = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-conflict-"));
  const storePath = path.join(destination, "certs", "alpha-ca");
  fs.mkdirSync(storePath, { recursive: true });
  fs.writeFileSync(path.join(storePath, "alpha-ca.crt"), "KEEP ROOT\n");
  fs.writeFileSync(path.join(storePath, "leaf.crt"), "KEEP LEAF\n");

  const skipped = applyImport(destination, archive.data, { policy: "skip" });
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.crt"), "utf8"), "KEEP LEAF\n");
  assert.equal(skipped.summary.skip >= 2, true);
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.pem"), "utf8"), "LEAF PEM\n");

  const renamed = applyImport(destination, archive.data, { policy: "rename" });
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.crt"), "utf8"), "KEEP LEAF\n");
  assert.equal(fs.existsSync(path.join(storePath, "leaf-imported.crt")), true);
  assert.equal(renamed.files.some((file) => file.destination === "leaf-imported.crt"), true);

  expectStatus(
    () => applyImport(destination, archive.data, { policy: "overwrite" }),
    400,
    /confirmation/,
  );
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.crt"), "utf8"), "KEEP LEAF\n");

  applyImport(destination, archive.data, { policy: "overwrite", confirmOverwrite: true });
  assert.notEqual(fs.readFileSync(path.join(storePath, "leaf.crt"), "utf8"), "KEEP LEAF\n");
  const keyMode = fs.statSync(path.join(storePath, "leaf.key")).mode & 0o777;
  assert.equal(keyMode, 0o600);
  const certMode = fs.statSync(path.join(storePath, "leaf.crt")).mode & 0o777;
  assert.equal(certMode, 0o644);
});

test("import rejects traversal, links, and files outside the whitelist", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-reject-"));
  const secret = path.join(projectRoot, "secret.txt");
  fs.writeFileSync(secret, "DO-NOT-LEAK\n");

  const cases = [
    packArchive([{ name: "../secret.txt", data: Buffer.from("DO-NOT-LEAK\n") }]),
    packArchive([{ name: "/tmp/secret.crt", data: Buffer.from("NO\n") }]),
    packArchive([{ name: "alpha-ca/../../secret.crt", data: Buffer.from("NO\n") }]),
    packTar([{ name: "leaf.crt", prefix: "..", data: Buffer.from("NO\n") }]),
    packArchive([{ name: "alpha-ca/leaf.crt", data: Buffer.from("OK\n"), type: "2" }]),
    packArchive([
      { name: "alpha-ca/alpha-ca.crt", data: Buffer.from("ROOT\n") },
      { name: "alpha-ca/leaf.txt", data: Buffer.from("NO\n") },
    ]),
    packArchive([
      { name: "alpha-ca/alpha-ca.crt", data: Buffer.from("ROOT\n") },
      { name: "alpha-ca/nested/leaf.crt", data: Buffer.from("NO\n") },
    ]),
  ];

  for (const archive of cases) {
    expectStatus(() => previewImport(projectRoot, archive, {}), 400);
    expectStatus(() => applyImport(projectRoot, archive, { policy: "overwrite", confirmOverwrite: true }), 400);
  }

  assert.equal(fs.readFileSync(secret, "utf8"), "DO-NOT-LEAK\n");
  assert.equal(fs.existsSync(path.join(projectRoot, "certs")), false);
  assert.equal(fs.existsSync("/tmp/secret.crt"), false);
});

test("import does not follow a symlink out of the store", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-symlink-import-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-symlink-target-"));
  const outsideFile = path.join(outside, "target.crt");
  fs.writeFileSync(outsideFile, "OUTSIDE\n");
  const storePath = path.join(projectRoot, "certs", "alpha-ca");
  fs.mkdirSync(storePath, { recursive: true });
  fs.writeFileSync(path.join(storePath, "alpha-ca.crt"), "ROOT\n");
  fs.symlinkSync(outsideFile, path.join(storePath, "leaf.crt"));

  const archive = packArchive([
    { name: "alpha-ca/alpha-ca.crt", data: Buffer.from("ROOT\n") },
    { name: "alpha-ca/leaf.crt", data: Buffer.from("IMPORTED\n") },
  ]);

  expectStatus(
    () => previewImport(projectRoot, archive, { policy: "overwrite" }),
    400,
    /escapes/,
  );
  assert.equal(fs.readFileSync(outsideFile, "utf8"), "OUTSIDE\n");
});

test("preview drops manifest fields that are not names or expiry", () => {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-manifest-"));
  const archive = packArchive([
    {
      name: "manifest.json",
      data: Buffer.from(
        JSON.stringify({
          exportedAt: "2026-01-01T00:00:00.000Z",
          passphrase: "hidden-pass",
          entries: [
            {
              store: "alpha-ca",
              name: "alpha-ca",
              notAfter: "Jan 1 00:00:00 2027 GMT",
              password: "hidden-p12",
              files: ["../secret.crt", "alpha-ca/alpha-ca.crt"],
            },
          ],
        }),
      ),
    },
    { name: "alpha-ca/alpha-ca.crt", data: Buffer.from("ROOT\n") },
  ]);

  const preview = previewImport(projectRoot, archive, {});
  assertNoSecrets(preview);
  assert.deepEqual(preview.manifest.entries[0].files, ["alpha-ca/alpha-ca.crt"]);
  assert.equal(preview.files[0].notAfter, "Jan 1 00:00:00 2027 GMT");
  assert.equal(fs.existsSync(path.join(projectRoot, "certs")), false);
});

test("gnu tar can read an exported archive", () => {
  const { projectRoot } = makeProject();
  const archive = exportArchive(projectRoot, { scope: "all" });
  const filePath = path.join(projectRoot, "bundle.tar.gz");
  fs.writeFileSync(filePath, archive.data);
  const listing = execFileSync("tar", ["-tzf", filePath], { encoding: "utf8" });
  assert.match(listing, /manifest\.json/);
  assert.match(listing, /alpha-ca\/alpha-ca\.crt/);
  assert.match(listing, /beta-ca\/leaf\.crt/);
  assert.doesNotMatch(listing, /\.key|\.p12/);
});

test("archive routes keep export and import inside certs", async () => {
  const { projectRoot, alpha } = makeProject();
  const secret = path.join(projectRoot, "secret.txt");
  fs.writeFileSync(secret, "DO-NOT-LEAK\n");
  process.env.PROJECT_ROOT = projectRoot;
  const serverPath = require.resolve("../server");
  delete require.cache[serverPath];
  delete require.cache[require.resolve("./archive")];
  delete require.cache[require.resolve("./certs")];
  const { app } = require("../server");
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  async function request(urlPath, body, contentType = "application/json") {
    const response = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
      method: "POST",
      headers: { "Content-Type": contentType },
      body: JSON.stringify(body),
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    return {
      status: response.status,
      disposition: response.headers.get("content-disposition"),
      bytes,
      text: bytes.toString("utf8"),
    };
  }

  try {
    const denied = await request("/api/export", {
      scope: "store",
      storeName: alpha.storeName,
      includeKeys: true,
    });
    assert.equal(denied.status, 400);
    assert.match(denied.text, /confirmation/);
    assert.doesNotMatch(denied.text, /KEY alpha-ca/);

    const exported = await request("/api/export", {
      scope: "store",
      storeName: alpha.storeName,
      includeKeys: true,
      confirmKeys: true,
    });
    assert.equal(exported.status, 200);
    assert.match(exported.disposition, /filename="ssl-gen-alpha-ca\.tar\.gz"/);
    assert.equal(exported.bytes.subarray(0, 2).toString("hex"), "1f8b");
    assert.equal(unpackArchive(exported.bytes).some((entry) => entry.name.endsWith(".key")), true);

    const escaped = packArchive([
      { name: "../../secret.txt", data: Buffer.from("DO-NOT-LEAK\n") },
    ]);
    const rejected = await request(
      "/api/import",
      { archiveBase64: escaped.toString("base64"), policy: "overwrite", confirmOverwrite: true },
      "application/vnd.ssl-gen.import+json",
    );
    assert.equal(rejected.status, 400);
    assert.match(rejected.text, /escapes/);
    assert.doesNotMatch(rejected.text, /DO-NOT-LEAK/);
    assert.equal(fs.readFileSync(secret, "utf8"), "DO-NOT-LEAK\n");
  } finally {
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    delete require.cache[serverPath];
  }
});
