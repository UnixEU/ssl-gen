export function trustCommandsFor(rootCaName) {
  const name = String(rootCaName ?? "").trim() || "my-root-ca";
  const relativeCert = `./certs/${name}/${name}.crt`;

  return [
    {
      id: "macos",
      title: "macOS",
      command: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${relativeCert}`,
    },
    {
      id: "linux",
      title: "Linux (Debian/Ubuntu)",
      command: [
        `sudo cp ${relativeCert} /usr/local/share/ca-certificates/${name}.crt`,
        "sudo update-ca-certificates",
      ].join("\n"),
    },
    {
      id: "windows",
      title: "Windows",
      command: `Import ${relativeCert} into Trusted Root Certification Authorities via certmgr.msc`,
    },
  ];
}
