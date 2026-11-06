const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isIpAddress(value) {
  const trimmed = String(value ?? "").trim();
  if (!trimmed) {
    return false;
  }
  if (IPV4.test(trimmed)) {
    return true;
  }
  return trimmed.includes(":") && /^[0-9a-fA-F:]+$/.test(trimmed);
}

function normalizeApex(value) {
  const apex = String(value ?? "")
    .trim()
    .replace(/^\*\./, "");

  if (!apex) {
    return { ok: false, error: "Enter an apex name such as dev.local." };
  }

  const valid =
    apex.length <= 253 &&
    /^[A-Za-z0-9.-]+$/.test(apex) &&
    !apex.startsWith(".") &&
    !apex.endsWith(".") &&
    !apex.startsWith("-") &&
    !apex.endsWith("-") &&
    !apex.includes("..") &&
    !apex.includes("*");

  if (!valid) {
    return {
      ok: false,
      error: "Use an apex name such as dev.local, with letters, numbers, dots, and hyphens.",
    };
  }

  return { ok: true, value: apex };
}

export function buildPreset(id, options = {}) {
  const lanIp = String(options.lanIp ?? "").trim();
  const apexInput = options.apex == null ? "dev.local" : String(options.apex);

  if (id === "localhost") {
    return {
      id,
      message: "Preset applied: localhost, *.localhost, 127.0.0.1, and ::1.",
      values: {
        CERT_NAME: "localhost",
        CERT_COMMON_NAME: "localhost",
        CERT_DNS_NAMES: "localhost,*.localhost,127.0.0.1",
        CERT_IP_ADDRESSES: "::1",
      },
    };
  }

  if (id === "lan") {
    if (lanIp && !isIpAddress(lanIp)) {
      return {
        id,
        error: "Enter a valid LAN IP address, or leave the field blank.",
      };
    }

    const ipNote = lanIp
      ? ` IP SAN ${lanIp} added.`
      : " Add a LAN IP if this certificate should include one.";

    return {
      id,
      message: `Preset applied: host.local and *.local.${ipNote}`,
      values: {
        CERT_NAME: "lan-local",
        CERT_COMMON_NAME: "host.local",
        CERT_DNS_NAMES: "host.local,*.local",
        CERT_IP_ADDRESSES: lanIp,
      },
    };
  }

  if (id === "wildcard") {
    const apex = normalizeApex(apexInput);
    if (!apex.ok) {
      return { id, error: apex.error };
    }

    return {
      id,
      message: `Preset applied: *.${apex.value} and ${apex.value}.`,
      values: {
        CERT_NAME: `wildcard-${apex.value}`,
        CERT_COMMON_NAME: `*.${apex.value}`,
        CERT_DNS_NAMES: `*.${apex.value},${apex.value}`,
        CERT_IP_ADDRESSES: "",
      },
    };
  }

  return { id, error: "Unknown preset." };
}
