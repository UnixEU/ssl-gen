const test = require("node:test");
const assert = require("node:assert/strict");

test("certificate presets keep the common name in the SAN list", async () => {
  const { buildPreset, isIpAddress } = await import("../public/presets.js");

  const localhost = buildPreset("localhost");
  assert.equal(localhost.error, undefined);
  assert.ok(localhost.values.CERT_DNS_NAMES.split(",").includes(localhost.values.CERT_COMMON_NAME));
  assert.equal(localhost.values.CERT_IP_ADDRESSES, "::1");
  assert.equal(isIpAddress("::1"), true);
  assert.equal(isIpAddress("192.168.1.20"), true);
  assert.equal(isIpAddress("999.1.1.1"), false);

  const lan = buildPreset("lan", { lanIp: "192.168.1.20" });
  assert.equal(lan.values.CERT_COMMON_NAME, "host.local");
  assert.equal(lan.values.CERT_DNS_NAMES, "host.local,*.local");
  assert.equal(lan.values.CERT_IP_ADDRESSES, "192.168.1.20");
  assert.match(buildPreset("lan", { lanIp: "not-an-ip" }).error, /LAN IP/);
  assert.equal(buildPreset("lan").values.CERT_IP_ADDRESSES, "");

  const wildcard = buildPreset("wildcard", { apex: "*.Dev.Local" });
  assert.equal(wildcard.values.CERT_COMMON_NAME, "*.Dev.Local");
  assert.equal(wildcard.values.CERT_DNS_NAMES, "*.Dev.Local,Dev.Local");
  assert.equal(wildcard.values.CERT_NAME, "wildcard-Dev.Local");
  assert.equal(wildcard.values.CERT_NAME.includes("*"), false);
  assert.match(buildPreset("wildcard", { apex: "bad name" }).error, /apex/);
  assert.match(buildPreset("nope").error, /Unknown preset/);
});

test("trust guide selects only root CAs that exist on disk", async () => {
  const { selectTrustStore, trustCommandsFor } = await import("../public/trust-commands.js");
  const onDisk = (name) => ({ name, artifacts: { crt: true } });

  assert.equal(selectTrustStore([], "UnixEURootCA", "UnixEURootCA"), "");
  assert.equal(
    selectTrustStore([onDisk("my-root-ca")], "UnixEURootCA", "UnixEURootCA"),
    "my-root-ca",
  );
  assert.equal(
    selectTrustStore([{ name: "gone", artifacts: { crt: false } }], "gone", "gone"),
    "",
  );
  assert.equal(
    selectTrustStore([onDisk("beta"), onDisk("alpha")], "deleted", "UnixEURootCA"),
    "beta",
  );
  assert.equal(selectTrustStore([onDisk("beta"), onDisk("alpha")], "", "alpha"), "alpha");
  assert.equal(
    selectTrustStore([onDisk("beta"), onDisk("alpha")], "beta", "alpha"),
    "beta",
  );

  const selected = selectTrustStore([onDisk("my-root-ca")], "", "UnixEURootCA");
  const commands = trustCommandsFor(selected);
  assert.match(commands.map((entry) => entry.command).join("\n"), /my-root-ca\.crt/);
  assert.equal(
    commands.some((entry) => entry.command.includes("UnixEURootCA")),
    false,
  );
});

test("trust commands copy the public root certificate only", async () => {
  const { trustCommandsFor } = await import("../public/trust-commands.js");
  const commands = trustCommandsFor("lab-root");
  const byId = Object.fromEntries(commands.map((entry) => [entry.id, entry.command]));

  assert.equal(
    byId.macos,
    "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./certs/lab-root/lab-root.crt",
  );
  assert.equal(
    byId.linux,
    "sudo cp ./certs/lab-root/lab-root.crt /usr/local/share/ca-certificates/lab-root.crt\nsudo update-ca-certificates",
  );
  assert.match(byId.windows, /Trusted Root Certification Authorities/);
  assert.match(byId.windows, /\.\/certs\/lab-root\/lab-root\.crt/);

  const joined = commands.map((entry) => entry.command).join("\n");
  assert.match(joined, /lab-root\.crt/);
  assert.doesNotMatch(joined, /lab-root\.key/);
  assert.equal(joined.includes(".p12"), false);
  assert.equal(trustCommandsFor("").some((entry) => entry.command.includes("my-root-ca.crt")), true);
});
