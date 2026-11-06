const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const test = require("node:test");
const { readCertMetadata } = require("./certs");
const {
  changeMaterialPassword,
  convertMaterial,
  inspectMaterial,
} = require("./material");

function openssl(args, options = {}) {
  execFileSync("openssl", args, {
    cwd: options.cwd,
    env: options.env || process.env,
    stdio: options.stdio || "ignore",
    input: options.input,
  });
}

function fingerprint(filePath) {
  const text = execFileSync(
    "openssl",
    ["x509", "-in", filePath, "-noout", "-fingerprint", "-sha256"],
    { encoding: "utf8" },
  );
  return (text.match(/Fingerprint=([0-9A-F:]+)/i) || [])[1].toUpperCase();
}

function makeProject(prefix = "ssl-gen-material-") {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const storeName = "root-ca";
  const storePath = path.join(projectRoot, "certs", storeName);
  fs.mkdirSync(storePath, { recursive: true });
  return { projectRoot, storeName, storePath };
}

function writeRoot(storePath, storeName) {
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
      "/CN=Root CA/O=UnixEU",
    ],
    { cwd: storePath },
  );
}

function writeLeaf(storePath, storeName) {
  const ext = path.join(storePath, "leaf-ext.cnf");
  fs.writeFileSync(
    ext,
    [
      "basicConstraints = CA:FALSE",
      "keyUsage = digitalSignature, keyEncipherment",
      "extendedKeyUsage = serverAuth",
      "subjectAltName = DNS:api.localhost,IP:127.0.0.1",
      "",
    ].join("\n"),
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
      "leaf.key",
      "-out",
      "leaf.csr",
      "-subj",
      "/CN=api.localhost/O=UnixEU",
    ],
    { cwd: storePath },
  );
  openssl(
    [
      "x509",
      "-req",
      "-in",
      "leaf.csr",
      "-CA",
      `${storeName}.crt`,
      "-CAkey",
      `${storeName}.key`,
      "-CAcreateserial",
      "-out",
      "leaf.crt",
      "-days",
      "10",
      "-sha256",
      "-extfile",
      "leaf-ext.cnf",
    ],
    { cwd: storePath },
  );
  fs.copyFileSync(path.join(storePath, "leaf.crt"), path.join(storePath, "leaf.pem"));
  fs.writeFileSync(
    path.join(storePath, "leaf-fullchain.pem"),
    `${fs.readFileSync(path.join(storePath, "leaf.crt"), "utf8")}${fs.readFileSync(path.join(storePath, `${storeName}.crt`), "utf8")}`,
  );
}

function encryptKey(keyPath, password) {
  openssl(
    ["pkey", "-in", keyPath, "-aes-256-cbc", "-passout", "env:SSL_GEN_PASS_OUT", "-out", `${keyPath}.enc`],
    { env: { ...process.env, SSL_GEN_PASS_OUT: password } },
  );
  fs.renameSync(`${keyPath}.enc`, keyPath);
}

function writeP12(storePath, password) {
  openssl(
    [
      "pkcs12",
      "-export",
      "-out",
      "leaf.p12",
      "-inkey",
      "leaf.key",
      "-in",
      "leaf.crt",
      "-certfile",
      "root-ca.crt",
      "-passout",
      "env:SSL_GEN_PASS_OUT",
    ],
    { cwd: storePath, env: { ...process.env, SSL_GEN_PASS_OUT: password } },
  );
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

function leftovers(storePath) {
  return fs.readdirSync(storePath).filter((name) => name.startsWith(".ssl-gen-") || name.endsWith(".tmp"));
}

test("PEM certificate converts to DER and back without clobbering", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const originalFingerprint = fingerprint(path.join(storePath, "leaf.crt"));

  const der = convertMaterial(projectRoot, {
    source: "store",
    storeName,
    certName: "leaf",
    fileName: "leaf.crt",
    to: "der",
    destination: "store",
    outputName: "leaf.der",
  });
  assert.equal(der.stored, true);
  assert.equal(der.relativePath, "./certs/root-ca/leaf.der");
  assert.equal(der.data[0], 0x30);
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.der")).equals(der.data), true);
  assert.doesNotMatch(der.message, /PRIVATE KEY/);

  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.crt",
        to: "der",
        destination: "store",
        outputName: "leaf.der",
      }),
    409,
    /Confirm overwrite/,
  );
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.der")).equals(der.data), true);

  const replaced = convertMaterial(projectRoot, {
    source: "store",
    storeName,
    certName: "leaf",
    fileName: "leaf.crt",
    to: "der",
    destination: "both",
    outputName: "leaf.der",
    overwrite: true,
  });
  assert.equal(replaced.data.equals(der.data), true);

  const pem = convertMaterial(projectRoot, {
    source: "upload",
    contentBase64: der.data.toString("base64"),
    fileName: "leaf.der",
    to: "pem",
    destination: "download",
    outputName: "leaf-roundtrip.pem",
  });
  assert.equal(pem.stored, false);
  assert.match(pem.data.toString("utf8"), /BEGIN CERTIFICATE/);
  const roundTrip = path.join(storePath, "roundtrip.pem");
  fs.writeFileSync(roundTrip, pem.data);
  assert.equal(fingerprint(roundTrip), originalFingerprint);
  assert.deepEqual(leftovers(storePath), []);
});

test("unencrypted key converts and encrypted keys and PKCS#12 are refused", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const password = "key-passphrase-value";
  writeP12(storePath, password);

  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.key",
        to: "der",
        destination: "download",
      }),
    400,
    /confirmation/,
  );

  const der = convertMaterial(projectRoot, {
    source: "store",
    storeName,
    certName: "leaf",
    fileName: "leaf.key",
    to: "der",
    destination: "store",
    confirmSecret: true,
  });
  assert.equal(der.fileName, "leaf-key.der");
  assert.equal(fs.statSync(path.join(storePath, "leaf-key.der")).mode & 0o777, 0o600);
  const pem = convertMaterial(projectRoot, {
    source: "store",
    storeName,
    certName: "leaf",
    fileName: "leaf-key.der",
    to: "pem",
    destination: "download",
    confirmSecret: true,
  });
  assert.match(pem.data.toString("utf8"), /BEGIN PRIVATE KEY/);
  assert.doesNotMatch(pem.message, /BEGIN PRIVATE KEY/);
  const roundTripKey = path.join(storePath, "roundtrip.key");
  fs.writeFileSync(roundTripKey, pem.data, { mode: 0o600 });
  openssl(["pkey", "-in", roundTripKey, "-noout"]);
  fs.rmSync(roundTripKey);

  encryptKey(path.join(storePath, "leaf.key"), password);
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.key",
        to: "der",
        destination: "download",
        confirmSecret: true,
      }),
    400,
    /Encrypted private keys/,
  );
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.p12",
        to: "pem",
        destination: "download",
      }),
    400,
    /PKCS#12/,
  );
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf-fullchain.pem",
        to: "der",
        destination: "download",
      }),
    400,
    /more than one certificate/,
  );
  assert.equal(JSON.stringify(leftovers(storePath)).includes(password), false);
});

test("conversion refuses traversal and symlink escape", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-material-outside-"));
  const marker = "OUTSIDE-SECRET-MARKER";
  fs.writeFileSync(path.join(outside, "escaped.crt"), `${marker}\n`);
  fs.symlinkSync(path.join(outside, "escaped.crt"), path.join(storePath, "leaf.der"));

  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName: "..",
        fileName: "leaf.crt",
        to: "der",
        destination: "store",
      }),
    400,
  );
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "../leaf",
        fileName: "leaf.crt",
        to: "der",
        destination: "download",
      }),
    400,
  );
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "other.crt",
        to: "der",
        destination: "download",
      }),
    400,
  );
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.crt",
        to: "der",
        destination: "store",
        outputName: "../escaped.der",
      }),
    400,
  );
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.der",
        to: "pem",
        destination: "download",
      }),
    404,
  );
  assert.equal(fs.existsSync(path.join(projectRoot, "escaped.der")), false);
  assert.equal(fs.readFileSync(path.join(outside, "escaped.crt"), "utf8").includes(marker), true);

  const linkedName = "linked-ca";
  fs.writeFileSync(path.join(outside, `${linkedName}.crt`), "not-a-store\n");
  fs.symlinkSync(outside, path.join(projectRoot, "certs", linkedName));
  expectStatus(
    () =>
      convertMaterial(projectRoot, {
        source: "store",
        storeName: linkedName,
        fileName: `${linkedName}.crt`,
        to: "der",
        destination: "download",
      }),
    400,
    /escapes/,
  );

  const linkedProject = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-material-link-"));
  fs.symlinkSync(path.join(projectRoot, "certs"), path.join(linkedProject, "certs"));
  expectStatus(
    () =>
      convertMaterial(linkedProject, {
        source: "store",
        storeName,
        certName: "leaf",
        fileName: "leaf.crt",
        to: "der",
        destination: "download",
      }),
    400,
    /escapes/,
  );
});

test("wrong current password does not change the key or PKCS#12", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const current = "current-secret-value";
  const next = "next-secret-value";
  const wrong = "wrong-secret-value";
  writeP12(storePath, current);
  const p12Before = fs.readFileSync(path.join(storePath, "leaf.p12"));
  encryptKey(path.join(storePath, "leaf.key"), current);
  const keyBefore = fs.readFileSync(path.join(storePath, "leaf.key"));

  expectStatus(
    () =>
      changeMaterialPassword(projectRoot, storeName, "leaf", {
        artifact: "key",
        currentPassword: "",
        newPassword: next,
        confirmPassword: next,
      }),
    400,
    /Current password is required/,
  );
  expectStatus(
    () =>
      changeMaterialPassword(projectRoot, storeName, "leaf", {
        artifact: "key",
        currentPassword: wrong,
        newPassword: next,
        confirmPassword: next,
      }),
    400,
    /not accepted/,
  );
  expectStatus(
    () =>
      changeMaterialPassword(projectRoot, storeName, "leaf", {
        artifact: "p12",
        currentPassword: wrong,
        newPassword: next,
        confirmPassword: next,
      }),
    400,
    /not accepted/,
  );
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.key")).equals(keyBefore), true);
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.p12")).equals(p12Before), true);
  assert.deepEqual(leftovers(storePath), []);

  const updated = changeMaterialPassword(projectRoot, storeName, "leaf", {
    artifact: "key",
    currentPassword: current,
    newPassword: next,
    confirmPassword: next,
  });
  assert.equal(updated.encrypted, true);
  assert.equal(updated.message.includes(current), false);
  assert.equal(updated.message.includes(next), false);
  openssl(["pkey", "-in", path.join(storePath, "leaf.key"), "-noout", "-passin", "env:SSL_GEN_PASS_IN"], {
    env: { ...process.env, SSL_GEN_PASS_IN: next },
  });
  assert.equal(fs.statSync(path.join(storePath, "leaf.key")).mode & 0o777, 0o600);

  const p12 = changeMaterialPassword(projectRoot, storeName, "leaf", {
    artifact: "p12",
    currentPassword: current,
    newPassword: next,
    confirmPassword: next,
  });
  assert.equal(p12.fileName, "leaf.p12");
  openssl(["pkcs12", "-in", path.join(storePath, "leaf.p12"), "-noout", "-passin", "env:SSL_GEN_PASS_IN"], {
    env: { ...process.env, SSL_GEN_PASS_IN: next },
  });
  assert.throws(() =>
    openssl(["pkcs12", "-in", path.join(storePath, "leaf.p12"), "-noout", "-passin", "env:SSL_GEN_PASS_IN"], {
      env: { ...process.env, SSL_GEN_PASS_IN: current },
    }),
  );
  assert.deepEqual(leftovers(storePath), []);
});

test("unencrypted key can gain a password and empty-to-empty is refused", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const before = fs.readFileSync(path.join(storePath, "leaf.key"));

  expectStatus(
    () =>
      changeMaterialPassword(projectRoot, storeName, "leaf", {
        artifact: "key",
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      }),
    400,
    /already has no password/,
  );
  expectStatus(
    () =>
      changeMaterialPassword(projectRoot, storeName, "leaf", {
        artifact: "key",
        currentPassword: "",
        newPassword: "alpha",
        confirmPassword: "beta",
      }),
    400,
    /do not match/,
  );
  assert.equal(fs.readFileSync(path.join(storePath, "leaf.key")).equals(before), true);

  const result = changeMaterialPassword(projectRoot, storeName, "leaf", {
    artifact: "key",
    currentPassword: "",
    newPassword: "alpha-secret",
    confirmPassword: "alpha-secret",
  });
  assert.equal(result.encrypted, true);
  assert.equal(result.message.includes("alpha-secret"), false);
  assert.match(fs.readFileSync(path.join(storePath, "leaf.key"), "utf8"), /ENCRYPTED/);
  assert.deepEqual(leftovers(storePath), []);
});

test("password change refuses symlink escape", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-pass-outside-"));
  const marker = "OUTSIDE-KEY-MARKER";
  fs.writeFileSync(path.join(outside, "leaf.key"), marker);
  fs.symlinkSync(path.join(outside, "leaf.key"), path.join(storePath, "leaf.key"));

  expectStatus(
    () =>
      changeMaterialPassword(projectRoot, storeName, "leaf", {
        artifact: "key",
        currentPassword: "",
        newPassword: "new-secret",
        confirmPassword: "new-secret",
      }),
    404,
  );
  assert.equal(fs.readFileSync(path.join(outside, "leaf.key"), "utf8"), marker);

  fs.rmSync(path.join(storePath, "leaf.key"));
  fs.writeFileSync(path.join(storePath, "leaf.key"), "not-a-symlink\n");
  const linkedProject = fs.mkdtempSync(path.join(os.tmpdir(), "ssl-gen-pass-link-"));
  fs.symlinkSync(path.join(projectRoot, "certs"), path.join(linkedProject, "certs"));
  expectStatus(
    () =>
      changeMaterialPassword(linkedProject, storeName, "leaf", {
        artifact: "key",
        currentPassword: "",
        newPassword: "new-secret",
        confirmPassword: "new-secret",
      }),
    400,
    /escapes/,
  );
});

test("inspect reports certificate fields and chain order", () => {
  const { projectRoot, storeName, storePath } = makeProject();
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const metadata = readCertMetadata(path.join(storePath, "leaf.crt"));
  const info = inspectMaterial(projectRoot, storeName, "leaf");
  const certificate = info.certificate;

  assert.equal(certificate.fingerprints.sha256, metadata.fingerprint.toUpperCase());
  assert.match(certificate.subject, /api\.localhost/);
  assert.match(certificate.issuer, /Root CA/);
  assert.match(certificate.subjectAltName, /api\.localhost/);
  assert.match(certificate.subjectAltName, /127\.0\.0\.1/);
  assert.match(certificate.basicConstraints, /CA:FALSE/);
  assert.match(certificate.keyUsage, /Digital Signature/);
  assert.match(certificate.extendedKeyUsage, /TLS Web Server Authentication/);
  assert.match(certificate.key.summary, /EC/);
  assert.equal(certificate.key.bits, 256);
  assert.match(certificate.serial, /^[0-9A-F]+$/);
  assert.match(certificate.fingerprints.sha1, /^[0-9A-F]{2}(?::[0-9A-F]{2})+$/);
  assert.notEqual(certificate.fingerprints.sha1, certificate.fingerprints.sha256);
  assert.match(certificate.text, /Subject Public Key Info/);
  assert.doesNotMatch(JSON.stringify(info), /PRIVATE KEY/);

  assert.equal(info.chain.present, true);
  assert.equal(info.chain.count, 2);
  assert.equal(info.chain.incomplete, false);
  assert.equal(info.chain.orderWrong, false);
  assert.equal(info.chain.startsWithLeaf, true);
  assert.equal(info.chain.links[0].matches, true);
  assert.match(info.chain.certificates[1].basicConstraints, /CA:TRUE/);

  const swapped = `${fs.readFileSync(path.join(storePath, `${storeName}.crt`))}${fs.readFileSync(path.join(storePath, "leaf.crt"))}`;
  fs.writeFileSync(path.join(storePath, "leaf-fullchain.pem"), swapped);
  const wrong = inspectMaterial(projectRoot, storeName, "leaf");
  assert.equal(wrong.chain.orderWrong, true);
  assert.equal(wrong.chain.startsWithLeaf, false);
  assert.match(wrong.chain.notes.join(" "), /does not start|does not match/);

  fs.writeFileSync(path.join(storePath, "leaf-fullchain.pem"), fs.readFileSync(path.join(storePath, "leaf.crt")));
  const incomplete = inspectMaterial(projectRoot, storeName, "leaf");
  assert.equal(incomplete.chain.incomplete, true);
  assert.equal(incomplete.chain.orderWrong, false);
  assert.match(incomplete.chain.notes.join(" "), /incomplete/);

  fs.rmSync(path.join(storePath, "leaf-fullchain.pem"));
  const missing = inspectMaterial(projectRoot, storeName, "leaf");
  assert.equal(missing.chain.present, false);
  const root = inspectMaterial(projectRoot, storeName, null);
  assert.match(root.certificate.basicConstraints, /CA:TRUE/);
  assert.equal(root.chain.present, false);
});

test("material routes keep secrets out of JSON and inside the store", async () => {
  const { projectRoot, storeName, storePath } = makeProject("ssl-gen-material-http-");
  writeRoot(storePath, storeName);
  writeLeaf(storePath, storeName);
  const current = "http-current-secret";
  const next = "http-next-secret";
  const wrong = "http-wrong-secret";
  encryptKey(path.join(storePath, "leaf.key"), current);
  const keyBefore = fs.readFileSync(path.join(storePath, "leaf.key"));

  process.env.PROJECT_ROOT = projectRoot;
  const serverPath = require.resolve("../server");
  delete require.cache[serverPath];
  const { app } = require("../server");
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  async function request(urlPath, body) {
    const response = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
      method: body ? "POST" : "GET",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    return { status: response.status, text, type: response.headers.get("content-type") };
  }

  try {
    const denied = await request("/api/convert", {
      source: "store",
      storeName: "..",
      certName: "leaf",
      fileName: "leaf.crt",
      to: "der",
      destination: "store",
      outputName: "leaf.der",
    });
    assert.equal(denied.status, 400);
    assert.doesNotMatch(denied.text, /PRIVATE KEY/);

    const info = await request(`/api/stores/${storeName}/certificates/leaf/inspect`);
    assert.equal(info.status, 200);
    assert.match(info.text, /api\.localhost/);
    assert.doesNotMatch(info.text, /PRIVATE KEY/);
    assert.doesNotMatch(info.text, new RegExp(current));

    const password = await request(`/api/stores/${storeName}/certificates/leaf/password`, {
      artifact: "key",
      currentPassword: wrong,
      newPassword: next,
      confirmPassword: next,
    });
    assert.equal(password.status, 400);
    assert.match(password.text, /not accepted/);
    assert.equal(password.text.includes(current), false);
    assert.equal(password.text.includes(wrong), false);
    assert.equal(password.text.includes(next), false);
    assert.equal(fs.readFileSync(path.join(storePath, "leaf.key")).equals(keyBefore), true);

    const material = await request(`/api/stores/${storeName}/certificates/leaf/material`);
    assert.equal(material.status, 200);
    assert.match(material.text, /passwordRequired":true/);
    assert.equal(material.text.includes(current), false);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    delete require.cache[serverPath];
  }
});
