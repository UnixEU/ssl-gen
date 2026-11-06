import { buildPreset, isIpAddress } from "./presets.js";
import { selectTrustStore, trustCommandsFor } from "./trust-commands.js";

const state = {
  config: {},
  defaults: {},
  sections: {},
  stores: [],
  activeView: "dashboard",
  detail: null,
  tool: null,
  archive: null,
  archivePreview: null,
  hierarchyStore: "",
  trustStore: "",
  storeQuery: "",
  activePreset: "",
  generateOpen: null,
  selection: new Set(),
};

let applyingPreset = false;

const viewMeta = {
  dashboard: {
    title: "Dashboard",
    description: "Overview of your local certificate stores.",
  },
  generate: {
    title: "Generate Certificate",
    description: "Start from a preset, or open a section and sign a certificate with your Root CA.",
  },
  stores: {
    title: "Certificates",
    description: "Search stores, inspect a chain, convert PEM and DER, or change a key password.",
  },
  hierarchy: {
    title: "Hierarchy",
    description: "A Root CA at the top, with the certificates it signed underneath.",
  },
  config: {
    title: "Configuration",
    description: "Manage the project .env values used by the terminal workflow.",
  },
  trust: {
    title: "Trust Guide",
    description: "Copy install commands and download the public Root CA certificate.",
  },
};

const fieldMeta = {
  ROOT_CA_NAME: { label: "Root CA Name", help: "Output folder and Root CA filename." },
  ROOT_CA_COUNTRY: { label: "Country", help: "Two-letter country code." },
  ROOT_CA_STATE: { label: "State / Province" },
  ROOT_CA_LOCALITY: { label: "Locality" },
  ROOT_CA_ORGANIZATION: { label: "Organization" },
  ROOT_CA_ORGANIZATIONAL_UNIT: { label: "Organizational Unit" },
  ROOT_CA_COMMON_NAME: { label: "Common Name" },
  ROOT_CA_VALIDITY_DAYS: { label: "Validity Days", type: "number" },
  ROOT_CA_PASSPHRASE: {
    label: "Passphrase",
    type: "password",
    help: "Optional encryption for the Root CA private key.",
  },
  CERT_NAME: { label: "Certificate Name", help: "Base filename for server certificate artifacts." },
  CERT_COUNTRY: { label: "Country", help: "Two-letter country code." },
  CERT_STATE: { label: "State / Province" },
  CERT_LOCALITY: { label: "Locality" },
  CERT_ORGANIZATION: { label: "Organization" },
  CERT_ORGANIZATIONAL_UNIT: { label: "Organizational Unit" },
  CERT_COMMON_NAME: { label: "Common Name" },
  CERT_DNS_NAMES: {
    label: "DNS / SAN Entries",
    type: "textarea",
    full: true,
    help: "Comma-separated hostnames and IP addresses.",
  },
  CERT_IP_ADDRESSES: {
    label: "Additional IP SAN Entries",
    type: "textarea",
    full: true,
    help: "Optional comma-separated IP addresses.",
  },
  CERT_VALIDITY_DAYS: { label: "Validity Days", type: "number" },
  KEY_TYPE: {
    label: "Key Type",
    type: "select",
    options: ["ec", "rsa"],
  },
  KEY_SIZE: {
    label: "Key Size",
    type: "select",
    help: "Saved as KEY_SIZE. Used for this certificate and for a new Root CA.",
  },
  FORCE_REGENERATE: {
    label: "Force Regenerate",
    type: "select",
    options: ["no", "yes"],
  },
  EXPORT_P12: {
    label: "Export PKCS#12",
    type: "select",
    options: ["yes", "no"],
  },
  P12_PASSWORD: { label: "PKCS#12 Password", type: "password" },
  WEBUI_BIND: {
    label: "Bind Address",
    help: "Must remain 127.0.0.1 for localhost-only access.",
  },
  WEBUI_PORT: { label: "Port", type: "number" },
};

const els = {
  viewTitle: document.getElementById("view-title"),
  viewDescription: document.getElementById("view-description"),
  webuiUrl: document.getElementById("webui-url"),
  statsGrid: document.getElementById("stats-grid"),
  dashboardStores: document.getElementById("dashboard-stores"),
  dashboardLog: document.getElementById("dashboard-log"),
  generateFields: document.getElementById("generate-fields"),
  configFields: document.getElementById("config-fields"),
  generateForm: document.getElementById("generate-form"),
  configForm: document.getElementById("config-form"),
  generateLog: document.getElementById("generate-log"),
  testLog: document.getElementById("test-log"),
  storesList: document.getElementById("stores-list"),
  hierarchySelect: document.getElementById("hierarchy-ca"),
  hierarchySummary: document.getElementById("hierarchy-summary"),
  hierarchyTree: document.getElementById("hierarchy-tree"),
  trustCommands: document.getElementById("trust-commands"),
  trustSelect: document.getElementById("trust-ca"),
  trustDownload: document.getElementById("trust-download"),
  storeSearch: document.getElementById("store-search"),
  storeSearchCount: document.getElementById("store-search-count"),
  dashboardExpiring: document.getElementById("dashboard-expiring"),
  detailModal: document.getElementById("detail-modal"),
  detailKicker: document.getElementById("detail-kicker"),
  detailTitle: document.getElementById("detail-title"),
  detailBody: document.getElementById("detail-body"),
  detailFooter: document.getElementById("detail-footer"),
  archiveModal: document.getElementById("archive-modal"),
  archiveKicker: document.getElementById("archive-kicker"),
  archiveTitle: document.getElementById("archive-title"),
  archiveBody: document.getElementById("archive-body"),
  archiveFooter: document.getElementById("archive-footer"),
  toolModal: document.getElementById("tool-modal"),
  toolKicker: document.getElementById("tool-kicker"),
  toolTitle: document.getElementById("tool-title"),
  toolBody: document.getElementById("tool-body"),
  toolFooter: document.getElementById("tool-footer"),
  toastStack: document.getElementById("toast-stack"),
  overlay: document.getElementById("overlay"),
  overlayMessage: document.getElementById("overlay-message"),
};

const EXPIRY_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const ARTIFACTS = [
  ["crt", ".crt"],
  ["fullchain", "Full chain"],
  ["p12", ".p12"],
  ["key", ".key"],
];

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      payload.message ||
      (Array.isArray(payload.errors) ? payload.errors.join("\n") : "Request failed");
    throw new Error(message);
  }

  return payload;
}

const TOAST_LABELS = {
  success: "Success",
  error: "Error",
  warning: "Warning",
  info: "Info",
};

function showToast(message, type = "success") {
  const kind = TOAST_LABELS[type] ? type : "info";
  const toast = document.createElement("div");
  toast.className = `toast toast-${kind}`;
  toast.setAttribute("role", kind === "error" || kind === "warning" ? "alert" : "status");

  const kicker = document.createElement("span");
  kicker.className = "toast-kicker";
  kicker.textContent = TOAST_LABELS[kind];

  const body = document.createElement("p");
  body.className = "toast-message";
  body.textContent = message;

  toast.append(kicker, body);
  toast.addEventListener("click", () => toast.remove());
  els.toastStack.appendChild(toast);
  const duration = kind === "error" || kind === "warning" ? 6400 : 4200;
  setTimeout(() => toast.remove(), duration);
}

function setBusy(active, message = "Working...") {
  els.overlay.hidden = !active;
  els.overlayMessage.textContent = message;
  document.body.style.pointerEvents = active ? "none" : "";
}

function formatSubject(subject = "") {
  return subject.replace(/^subject=/, "").trim() || "Unknown";
}

const KEY_SIZE_OPTIONS = {
  ec: [
    { value: "256", label: "P-256 (prime256v1)" },
    { value: "384", label: "P-384 (secp384r1)" },
    { value: "521", label: "P-521 (secp521r1)" },
  ],
  rsa: [
    { value: "2048", label: "2048" },
    { value: "3072", label: "3072" },
    { value: "4096", label: "4096" },
  ],
};

function keyTypeOf(value) {
  return value === "rsa" ? "rsa" : "ec";
}

function keySizeChoices(keyType) {
  return KEY_SIZE_OPTIONS[keyTypeOf(keyType)];
}

function defaultKeySize(keyType) {
  return keyTypeOf(keyType) === "rsa" ? "2048" : "256";
}

function resolvedKeySize(keyType, value) {
  const choices = keySizeChoices(keyType);
  const raw = String(value ?? "");
  return choices.some((option) => option.value === raw) ? raw : defaultKeySize(keyType);
}

function keySizeSummary(keyType, value) {
  const type = keyTypeOf(keyType);
  const size = resolvedKeySize(type, value);
  if (type === "rsa") {
    return `${size}-bit`;
  }
  const choice = keySizeChoices(type).find((option) => option.value === size);
  return choice ? choice.label.split(" ")[0] : `P-${size}`;
}

function syncKeySizeField(form) {
  const typeField = form?.elements?.namedItem("KEY_TYPE");
  const sizeField = form?.elements?.namedItem("KEY_SIZE");
  if (!typeField || !sizeField) {
    return;
  }

  const choices = keySizeChoices(typeField.value);
  const selected = resolvedKeySize(typeField.value, sizeField.value);
  sizeField.innerHTML = choices
    .map(
      (option) =>
        `<option value="${escapeHtml(option.value)}"${option.value === selected ? " selected" : ""}>${escapeHtml(option.label)}</option>`,
    )
    .join("");
  sizeField.value = selected;
}

function renderOptions(options, selected) {
  return (options || [])
    .map((option) => {
      const optionValue = typeof option === "object" ? option.value : option;
      const optionLabel = typeof option === "object" ? option.label : option;
      const isSelected = optionValue === selected ? " selected" : "";
      return `<option value="${escapeHtml(optionValue)}"${isSelected}>${escapeHtml(optionLabel)}</option>`;
    })
    .join("");
}

function renderField(key, prefix) {
  const meta = fieldMeta[key] || { label: key };
  const value = state.config[key] ?? "";
  const id = `${prefix}-${key}`;
  const fieldClass = meta.full ? "field full" : "field";
  let options = meta.options || [];
  let selectedValue = value;
  if (key === "KEY_SIZE") {
    const keyType = keyTypeOf(state.config.KEY_TYPE);
    options = keySizeChoices(keyType);
    selectedValue = resolvedKeySize(keyType, value);
  }

  let control = `<input id="${id}" name="${key}" value="${escapeHtml(value)}" />`;

  if (meta.type === "textarea") {
    control = `<textarea id="${id}" name="${key}">${escapeHtml(value)}</textarea>`;
  } else if (meta.type === "select") {
    control = `<select id="${id}" name="${key}">
      ${renderOptions(options, selectedValue)}
    </select>`;
  } else if (meta.type === "password") {
    control = `<input id="${id}" name="${key}" type="password" value="${escapeHtml(value)}" autocomplete="off" />`;
  } else if (meta.type === "number") {
    control = `<input id="${id}" name="${key}" type="number" value="${escapeHtml(value)}" />`;
  }

  const help = meta.help ? `<span class="meta-label">${meta.help}</span>` : "";

  return `
    <div class="${fieldClass}">
      <label for="${id}">${meta.label}</label>
      ${control}
      ${help}
    </div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function expiryInfo(notAfter, now = Date.now()) {
  const parsed = Date.parse(notAfter || "");
  if (!notAfter || Number.isNaN(parsed)) {
    return { status: "unknown", label: "Unknown", tone: "" };
  }

  const remaining = parsed - now;
  if (remaining < 0) {
    return { status: "expired", label: "Expired", tone: "danger" };
  }
  if (remaining <= EXPIRY_WINDOW_MS) {
    return { status: "soon", label: "≤30d", tone: "warning" };
  }
  return { status: "ok", label: "OK", tone: "success" };
}

function notAfterTime(metadata) {
  const parsed = Date.parse(metadata?.notAfter || "");
  return Number.isNaN(parsed) ? Number.POSITIVE_INFINITY : parsed;
}

function compareByNotAfter(left, right) {
  const delta = notAfterTime(left.metadata) - notAfterTime(right.metadata);
  if (delta !== 0) {
    return delta;
  }
  return String(left.name).localeCompare(String(right.name));
}

function formatDate(value) {
  if (!value) {
    return "Unknown";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toUTCString();
}

function renderExpiryBadge(notAfter) {
  const expiry = expiryInfo(notAfter);
  const tone = expiry.tone ? ` ${expiry.tone}` : "";
  const title = notAfter ? formatDate(notAfter) : "Expiry date unavailable";
  return `<span class="badge${tone}" title="${escapeHtml(title)}">${escapeHtml(expiry.label)}</span>`;
}

function expiryRowClass(notAfter) {
  const status = expiryInfo(notAfter).status;
  if (status === "soon" || status === "expired") {
    return `expiry-${status}`;
  }
  return "";
}

function sortedStores() {
  return [...state.stores].sort(compareByNotAfter);
}

function inventory() {
  const items = [];
  for (const store of state.stores) {
    items.push({
      kind: "root",
      storeName: store.name,
      certName: null,
      name: store.name,
      metadata: store.metadata,
      artifacts: store.artifacts || {},
      relativeCert: store.relativeCert || `./certs/${store.name}/${store.name}.crt`,
    });
    for (const cert of store.certificates) {
      items.push({
        kind: "certificate",
        storeName: store.name,
        certName: cert.name,
        name: cert.name,
        metadata: cert.metadata,
        artifacts: cert.artifacts || {},
        relativeCert: cert.relativeCert || `./certs/${store.name}/${cert.name}.crt`,
      });
    }
  }
  return items.sort(compareByNotAfter);
}

function expiringItems() {
  return inventory().filter((item) => {
    const status = expiryInfo(item.metadata?.notAfter).status;
    return status === "soon" || status === "expired";
  });
}

function renderDownloadButtons(storeName, certName, artifacts = {}) {
  return ARTIFACTS.filter(([kind]) => artifacts[kind])
    .map(([kind, label]) => {
      const secret = kind === "key" ? `<span class="badge secret">secret</span>` : "";
      const className =
        kind === "key" ? "button button-secret button-small" : "button button-secondary button-small";
      const certAttr = certName ? ` data-cert="${escapeHtml(certName)}"` : "";
      const aria = kind === "key" ? ` aria-label="Download private key"` : "";
      return `<button type="button" class="${className}" data-action="download" data-artifact="${kind}" data-store="${escapeHtml(storeName)}"${certAttr}${aria}>${label}${secret}</button>`;
    })
    .join("");
}

function renderDetailsButton(storeName, certName) {
  const kind = certName ? "certificate" : "root";
  const certAttr = certName ? ` data-cert="${escapeHtml(certName)}"` : "";
  return `<button type="button" class="button button-secondary button-small" data-action="show-detail" data-kind="${kind}" data-store="${escapeHtml(storeName)}"${certAttr}>Details</button>`;
}

function renderToolButtons(storeName, certName) {
  const certAttr = certName ? ` data-cert="${escapeHtml(certName)}"` : "";
  const attrs = `data-store="${escapeHtml(storeName)}"${certAttr}`;
  return `
    <button type="button" class="button button-secondary button-small" data-action="view-info" ${attrs}>Info</button>
    <button type="button" class="button button-secondary button-small" data-action="open-convert" ${attrs}>Convert</button>
    <button type="button" class="button button-secondary button-small" data-action="open-password" ${attrs}>Password</button>
  `;
}

function downloadUrl(storeName, certName, artifact, confirm = false) {
  const store = encodeURIComponent(storeName);
  const kind = encodeURIComponent(artifact);
  const path = certName
    ? `/api/stores/${store}/certificates/${encodeURIComponent(certName)}/download/${kind}`
    : `/api/stores/${store}/download/${kind}`;
  return confirm ? `${path}?confirm=1` : path;
}

function filenameFor(storeName, certName, artifact) {
  const base = certName || storeName;
  if (artifact === "fullchain") {
    return `${base}-fullchain.pem`;
  }
  if (artifact === "p12") {
    return `${base}.p12`;
  }
  if (artifact === "key") {
    return `${base}.key`;
  }
  return `${base}.crt`;
}

function saveBlob(blob, fileName) {
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
}

function filenameFromDisposition(header) {
  const match = header?.match(/filename="([^"]+)"/);
  return match?.[1] || "";
}

async function copyText(value, message) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(message);
      return;
    } catch {
      // Fall through to the selection fallback when the clipboard API is blocked.
    }
  }

  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  document.body.appendChild(input);
  input.select();
  const copied = document.execCommand("copy");
  input.remove();
  if (!copied) {
    throw new Error("Could not copy to the clipboard");
  }
  showToast(message);
}

function sectionSummary(name, values) {
  if (name === "rootCa") {
    return values.ROOT_CA_NAME || "Unset";
  }
  if (name === "certificate") {
    return values.CERT_COMMON_NAME || values.CERT_NAME || "Unset";
  }
  if (name === "advanced") {
    const keyType = values.KEY_TYPE || "ec";
    return `${keyType} ${keySizeSummary(keyType, values.KEY_SIZE)} · regenerate ${values.FORCE_REGENERATE || "no"}`;
  }
  if (name === "webui") {
    return `${values.WEBUI_BIND || "127.0.0.1"}:${values.WEBUI_PORT || "8443"}`;
  }
  return "";
}

function defaultGenerateOpen() {
  const name = state.config.ROOT_CA_NAME;
  const exists = state.stores.some((store) => store.name === name);
  return { rootCa: !exists, certificate: true, advanced: false };
}

function refreshSectionSummaries() {
  if (!els.generateForm) {
    return;
  }
  const values = readFormValues(els.generateForm);
  els.generateFields.querySelectorAll("[data-summary]").forEach((node) => {
    node.textContent = sectionSummary(node.dataset.summary, values);
  });
}

function renderFormSections(container, options = {}) {
  const includeWebUi = options.includeWebUi === true;
  const collapsible = options.collapsible === true;
  const formPrefix = options.prefix || (includeWebUi ? "config" : "generate");
  const openState = collapsible ? state.generateOpen || defaultGenerateOpen() : null;

  const sections = Object.entries(state.sections)
    .filter(([name]) => includeWebUi || name !== "webui")
    .map(([name, section]) => {
      const fields = section.keys.map((key) => renderField(key, `${formPrefix}-${name}`)).join("");
      if (!collapsible) {
        return `
          <section class="form-section">
            <h3>${escapeHtml(section.title)}</h3>
            <div class="field-grid">${fields}</div>
          </section>
        `;
      }

      const isOpen = Object.prototype.hasOwnProperty.call(openState, name)
        ? openState[name]
        : name !== "advanced";
      return `
        <details class="form-section" data-section="${name}"${isOpen ? " open" : ""}>
          <summary>
            <span class="section-title">${escapeHtml(section.title)}</span>
            <span class="section-summary" data-summary="${name}">${escapeHtml(sectionSummary(name, state.config))}</span>
          </summary>
          <div class="field-grid">${fields}</div>
        </details>
      `;
    });

  container.innerHTML = sections.join("");
  if (collapsible) {
    refreshSectionSummaries();
  }
}

function updatePresetChrome() {
  document.querySelectorAll(".preset-chip").forEach((button) => {
    const active = button.dataset.preset === state.activePreset;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  });

  const lan = document.getElementById("preset-lan");
  const wildcard = document.getElementById("preset-wildcard");
  if (lan) {
    lan.hidden = state.activePreset !== "lan";
  }
  if (wildcard) {
    wildcard.hidden = state.activePreset !== "wildcard";
  }
}

function applyPreset(id, { quiet = false } = {}) {
  const lanIp = document.getElementById("preset-lan-ip")?.value || "";
  const apex = document.getElementById("preset-wildcard-base")?.value || "";
  const result = buildPreset(id, { lanIp, apex });
  if (result.error) {
    if (!quiet) {
      showToast(result.error, "warning");
    }
    return;
  }

  applyingPreset = true;
  for (const [key, value] of Object.entries(result.values)) {
    const field = els.generateForm.elements.namedItem(key);
    if (field && "value" in field) {
      field.value = value;
    }
  }
  applyingPreset = false;

  state.activePreset = id;
  updatePresetChrome();
  const certificate = els.generateFields.querySelector('details[data-section="certificate"]');
  if (certificate) {
    certificate.open = true;
    state.generateOpen = {
      ...(state.generateOpen || defaultGenerateOpen()),
      certificate: true,
    };
  }
  refreshSectionSummaries();

  const preview = document.getElementById("preset-wildcard-preview");
  const apexName = result.values.CERT_DNS_NAMES?.split(",").pop();
  if (preview && apexName && id === "wildcard") {
    preview.textContent = apexName;
  }

  if (!quiet) {
    showToast(result.message, "info");
  }
}

function readFormValues(form) {
  const values = { ...state.config };
  const formData = new FormData(form);

  for (const [key, value] of formData.entries()) {
    values[key] = String(value).trim();
  }

  return values;
}

function renderStats() {
  const totalCerts = state.stores.reduce(
    (count, store) => count + store.certificates.length,
    0,
  );
  const expiring = expiringItems();
  const hasExpired = expiring.some(
    (item) => expiryInfo(item.metadata?.notAfter).status === "expired",
  );
  const expiringClass = hasExpired
    ? "stat-card attention-danger"
    : expiring.length > 0
      ? "stat-card attention"
      : "stat-card";

  const cards = [
    ["Root CAs", state.stores.length, "stat-card"],
    ["Certificates", totalCerts, "stat-card"],
    ["Current CA", state.config.ROOT_CA_NAME || "—", "stat-card"],
    ["Expiring Soon", expiring.length, expiringClass],
  ];

  els.statsGrid.innerHTML = cards
    .map(
      ([label, value, className]) => `
        <article class="${className}">
          <p class="stat-label">${label}</p>
          <p class="stat-value">${escapeHtml(String(value))}</p>
        </article>
      `,
    )
    .join("");
}

function renderExpiring() {
  const items = expiringItems();
  if (!els.dashboardExpiring) {
    return;
  }

  if (items.length === 0) {
    els.dashboardExpiring.innerHTML = `<p class="empty-state">Nothing is expired or due within 30 days.</p>`;
    return;
  }

  els.dashboardExpiring.innerHTML = `<div class="cert-list">${items
    .map((item) => {
      const expiryClass = expiryRowClass(item.metadata?.notAfter);
      const kindLabel = item.kind === "root" ? "Root CA" : `Certificate · ${item.storeName}`;
      const certAttr = item.certName ? ` data-cert="${escapeHtml(item.certName)}"` : "";
      return `
        <div class="cert-row ${expiryClass}">
          <div>
            <button
              type="button"
              class="link-button"
              data-action="show-detail"
              data-kind="${item.kind}"
              data-store="${escapeHtml(item.storeName)}"${certAttr}
            >${escapeHtml(item.name)}</button>
            <div class="meta-label">${escapeHtml(kindLabel)}</div>
            <div class="meta-label">${escapeHtml(formatDate(item.metadata?.notAfter))}</div>
          </div>
          <div class="cert-actions">
            ${renderExpiryBadge(item.metadata?.notAfter)}
            ${renderDetailsButton(item.storeName, item.certName)}
            ${renderToolButtons(item.storeName, item.certName)}
          </div>
        </div>
      `;
    })
    .join("")}</div>`;
}

function selectionKey(kind, storeName, certName) {
  if (kind === "certificate") {
    return `certificate:${storeName}:${certName}`;
  }
  return `store:${storeName}`;
}

function parseSelectionKey(key) {
  if (key.startsWith("certificate:")) {
    const rest = key.slice("certificate:".length);
    const splitAt = rest.indexOf(":");
    return {
      kind: "certificate",
      storeName: rest.slice(0, splitAt),
      certName: rest.slice(splitAt + 1),
    };
  }
  return {
    kind: "store",
    storeName: key.slice("store:".length),
    certName: null,
  };
}

function selectionCheckbox(kind, storeName, certName) {
  const key = selectionKey(kind, storeName, certName);
  const checked = state.selection.has(key) ? " checked" : "";
  const certAttr = certName ? ` data-cert="${escapeHtml(certName)}"` : "";
  const label =
    kind === "certificate"
      ? `Select certificate ${certName}`
      : `Select Root CA ${storeName}`;
  return `<label class="select-check">
    <input
      type="checkbox"
      data-select="${kind}"
      data-store="${escapeHtml(storeName)}"${certAttr}${checked}
      aria-label="${escapeHtml(label)}"
    />
  </label>`;
}

function pruneSelection() {
  const valid = new Set();
  for (const store of state.stores) {
    valid.add(selectionKey("store", store.name));
    for (const cert of store.certificates) {
      valid.add(selectionKey("certificate", store.name, cert.name));
    }
  }
  for (const key of state.selection) {
    if (!valid.has(key)) {
      state.selection.delete(key);
    }
  }
}

function syncExportSelectedButtons() {
  const empty = state.selection.size === 0;
  for (const id of ["dashboard-export-selected-button", "stores-export-selected-button"]) {
    const button = document.getElementById(id);
    if (!button) {
      continue;
    }
    button.disabled = empty;
    button.title = empty
      ? "Select a Root CA or certificate first"
      : "Export the selected Root CAs and certificates";
  }
}

function syncSelectionChecks() {
  document.querySelectorAll("[data-select]").forEach((box) => {
    const key = selectionKey(box.dataset.select, box.dataset.store, box.dataset.cert);
    box.checked = state.selection.has(key);
  });
  syncExportSelectedButtons();
}

function renderStoreCard(store, compact = false) {
  const rootExpiryClass = expiryRowClass(store.metadata?.notAfter);
  const reuseStoreButton =
    compact || !store.artifacts?.key
      ? ""
      : `<button
        class="button button-accent button-small"
        data-action="reuse-store"
        data-store="${escapeHtml(store.name)}"
        type="button"
      >Reuse this RootCA</button>`;

  const deleteStoreButton = compact
    ? ""
    : `<button
        class="button button-danger button-small"
        data-action="delete-store"
        data-store="${escapeHtml(store.name)}"
        type="button"
      >Delete Root CA</button>`;

  const certs = [...store.certificates]
    .sort(compareByNotAfter)
    .map((cert) => {
      const metadata = cert.metadata || {};
      const deleteCertButton = compact
        ? ""
        : `<button
            class="button button-danger button-small"
            data-action="delete-cert"
            data-store="${escapeHtml(store.name)}"
            data-cert="${escapeHtml(cert.name)}"
            type="button"
          >Delete</button>`;
      const downloads = renderDownloadButtons(store.name, cert.name, cert.artifacts);
      const exportCertButton = compact
        ? ""
        : `<button
            class="button button-secondary button-small"
            data-action="export-archive"
            data-scope="certificate"
            data-store="${escapeHtml(store.name)}"
            data-cert="${escapeHtml(cert.name)}"
            type="button"
          >Export TAR</button>`;

      return `
        <div class="cert-row ${expiryRowClass(metadata.notAfter)}">
          <div class="identity-row">
            ${selectionCheckbox("certificate", store.name, cert.name)}
            <div>
              <button
                type="button"
                class="link-button"
                data-action="show-detail"
                data-kind="certificate"
                data-store="${escapeHtml(store.name)}"
                data-cert="${escapeHtml(cert.name)}"
              >${escapeHtml(cert.name)}</button>
              <div class="meta-label">${escapeHtml(formatSubject(metadata.subject))}</div>
              <div class="meta-label">${escapeHtml(metadata.subjectAltName || "No SAN data")}</div>
            </div>
          </div>
          <div class="cert-actions">
            ${renderExpiryBadge(metadata.notAfter)}
            ${downloads}
            ${renderDetailsButton(store.name, cert.name)}
            ${renderToolButtons(store.name, cert.name)}
            ${exportCertButton}
            ${deleteCertButton}
          </div>
        </div>
      `;
    })
    .join("");

  const certSection =
    store.certificates.length > 0
      ? `<div class="cert-list">${certs}</div>`
      : compact
        ? `<p class="empty-state">No signed certificates yet.</p>`
        : `<div class="empty-state empty-cta">
            <p>No signed certificates yet.</p>
            <button
              type="button"
              class="button button-accent button-small"
              data-action="reuse-store"
              data-store="${escapeHtml(store.name)}"
            >Generate a certificate</button>
          </div>`;

  const filesSection = compact
    ? ""
    : `<div class="meta-list">
        <div class="meta-item">
          <span class="meta-label">Files</span>
          <span class="meta-value">${escapeHtml(store.files.join(", "))}</span>
        </div>
      </div>`;

  const hierarchyButton = compact
    ? ""
    : `<button
        class="button button-secondary button-small"
        data-action="show-hierarchy"
        data-store="${escapeHtml(store.name)}"
        type="button"
      >Hierarchy</button>`;

  const rootDownloads = renderDownloadButtons(store.name, null, store.artifacts);

  return `
    <article class="store-card ${rootExpiryClass}">
      <div class="store-header">
        <div class="identity-row">
          ${selectionCheckbox("store", store.name)}
          <div>
            <h3><button
              type="button"
              class="link-button"
              data-action="show-detail"
              data-kind="root"
              data-store="${escapeHtml(store.name)}"
            >${escapeHtml(store.name)}</button></h3>
            <p class="meta-label">${escapeHtml(formatSubject(store.metadata?.subject))}</p>
            <p class="meta-label">${escapeHtml(store.relativePath || `./certs/${store.name}`)}</p>
          </div>
        </div>
        <div class="store-actions">
          ${renderExpiryBadge(store.metadata?.notAfter)}
          <span class="badge">${store.certificates.length} cert(s)</span>
          ${renderDetailsButton(store.name, null)}
          ${renderToolButtons(store.name, null)}
          ${hierarchyButton}
          <button
            class="button button-secondary button-small"
            data-action="export-archive"
            data-scope="store"
            data-store="${escapeHtml(store.name)}"
            type="button"
          >Export TAR</button>
          ${reuseStoreButton}
          ${deleteStoreButton}
        </div>
      </div>
      <div class="meta-list">
        <div class="meta-item">
          <span class="meta-label">Root CA valid until</span>
          <span class="meta-value">${escapeHtml(formatDate(store.metadata?.notAfter))}</span>
        </div>
      </div>
      <div class="download-row">
        <span class="meta-label">Root CA</span>
        ${rootDownloads || `<span class="meta-label">No public artifacts</span>`}
      </div>
      ${filesSection}
      ${certSection}
    </article>
  `;
}

function storeSearchText(store) {
  return [
    store.name,
    store.relativePath,
    store.metadata?.subject,
    store.metadata?.subjectAltName,
    store.metadata?.fingerprint,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function certificateSearchText(cert) {
  return [cert.name, cert.metadata?.subject, cert.metadata?.subjectAltName, cert.metadata?.fingerprint]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function storesForQuery(stores, query) {
  const needle = String(query || "").trim().toLowerCase();
  if (!needle) {
    return stores.map((store) => ({ store, certificates: store.certificates }));
  }

  const matches = [];
  for (const store of stores) {
    if (storeSearchText(store).includes(needle)) {
      matches.push({ store, certificates: store.certificates });
      continue;
    }
    const certificates = store.certificates.filter((cert) =>
      certificateSearchText(cert).includes(needle),
    );
    if (certificates.length > 0) {
      matches.push({ store, certificates });
    }
  }
  return matches;
}

function emptyStoresMarkup() {
  const folder = escapeHtml(state.config.ROOT_CA_NAME || "my-root-ca");
  return `
    <div class="empty-state empty-cta">
      <p>No certificate stores found. Generate your first certificate to create <code>./certs/${folder}/</code>.</p>
      <button type="button" class="button button-primary" data-action="go-generate">Generate a certificate</button>
    </div>
  `;
}

function updateStoreSearchCount(stores) {
  if (!els.storeSearchCount) {
    return;
  }
  const query = state.storeQuery.trim();
  if (stores.length === 0) {
    els.storeSearchCount.textContent = "";
    return;
  }
  if (!query) {
    els.storeSearchCount.textContent = `${stores.length} store${stores.length === 1 ? "" : "s"}`;
    return;
  }
  const visible = storesForQuery(stores, query).length;
  els.storeSearchCount.textContent = `${visible} of ${stores.length} store${stores.length === 1 ? "" : "s"}`;
}

function renderStores() {
  renderExpiring();
  pruneSelection();
  const stores = sortedStores();
  updateStoreSearchCount(stores);

  if (stores.length === 0) {
    const empty = emptyStoresMarkup();
    els.dashboardStores.innerHTML = empty;
    els.storesList.innerHTML = `<article class="panel"><div class="panel-body">${empty}</div></article>`;
    renderHierarchy();
    syncExportSelectedButtons();
    return;
  }

  els.dashboardStores.innerHTML = stores
    .slice(0, 2)
    .map((store) => renderStoreCard(store, true))
    .join("");

  const visible = storesForQuery(stores, state.storeQuery);
  if (visible.length === 0) {
    els.storesList.innerHTML = `<article class="panel"><div class="panel-body">
      <div class="empty-state empty-cta">
        <p>No stores or certificates match “${escapeHtml(state.storeQuery.trim())}”.</p>
        <button type="button" class="button button-secondary" data-action="clear-search">Clear search</button>
      </div>
    </div></article>`;
  } else {
    els.storesList.innerHTML = visible
      .map(({ store, certificates }) => renderStoreCard({ ...store, certificates }))
      .join("");
  }
  renderHierarchy();
  syncExportSelectedButtons();
}

function selectedHierarchyName(stores) {
  const names = new Set(stores.map((store) => store.name));
  if (state.hierarchyStore && names.has(state.hierarchyStore)) {
    return state.hierarchyStore;
  }
  if (state.config.ROOT_CA_NAME && names.has(state.config.ROOT_CA_NAME)) {
    return state.config.ROOT_CA_NAME;
  }
  return stores[0]?.name || "";
}

function renderTreeNode(storeName, kind, name, metadata, extraBadge = "") {
  const role = kind === "root" ? "Root CA" : "Certificate";
  const commonName = metadata?.commonName
    ? metadata.commonName
    : metadata?.subject
      ? formatSubject(metadata.subject)
      : "No common name";
  const certAttr = kind === "certificate" ? ` data-cert="${escapeHtml(name)}"` : "";
  const expiryClass = expiryRowClass(metadata?.notAfter);

  return `
    <button
      type="button"
      class="tree-node ${kind === "root" ? "tree-node-root" : "tree-node-leaf"} ${expiryClass}"
      data-action="show-detail"
      data-kind="${kind}"
      data-store="${escapeHtml(storeName)}"${certAttr}
      aria-label="Open details for ${role} ${escapeHtml(name)}"
    >
      <span class="tree-node-kicker">
        <span class="badge">${role}</span>
        ${renderExpiryBadge(metadata?.notAfter)}
        ${extraBadge}
      </span>
      <span class="tree-node-title">${escapeHtml(name)}</span>
      <span class="tree-node-cn">${escapeHtml(commonName)}</span>
    </button>
  `;
}

function renderHierarchyTree(store) {
  if (!store) {
    els.hierarchySummary.textContent =
      "Choose a Root CA to see the certificates stored under it.";
    els.hierarchyTree.innerHTML = emptyStoresMarkup();
    return;
  }

  const children = [...store.certificates].sort((left, right) => {
    if (Boolean(left.signedByRoot) !== Boolean(right.signedByRoot)) {
      return left.signedByRoot ? -1 : 1;
    }
    return left.name.localeCompare(right.name);
  });
  const signed = children.filter((cert) => cert.signedByRoot).length;
  const other = children.length - signed;
  const location = store.relativePath || `./certs/${store.name}`;

  if (children.length === 0) {
    els.hierarchySummary.textContent = `${store.name} has no certificates in ${location}. Click the Root CA for details and downloads.`;
  } else if (other > 0) {
    els.hierarchySummary.textContent = `${signed} signed by this Root CA, ${other} with a different issuer, in ${location}. A dashed line marks an issuer that does not match. Click a node for details and downloads.`;
  } else {
    els.hierarchySummary.textContent = `${signed} certificate${signed === 1 ? "" : "s"} signed by this Root CA in ${location}. Click a node for details and downloads.`;
  }

  const branches =
    children.length === 0
      ? `<p class="empty-state hierarchy-empty">No signed certificates in this store yet.</p>`
      : `<div class="hierarchy-stem" aria-hidden="true"></div>
        <div class="hierarchy-children">
          ${children
            .map((cert) => {
              const note = !cert.metadata
                ? `<span class="badge warning">Unreadable</span>`
                : cert.signedByRoot
                  ? ""
                  : `<span class="badge warning">Issuer differs</span>`;
              return `
                <div class="hierarchy-branch ${cert.signedByRoot ? "" : "unverified"}">
                  ${renderTreeNode(store.name, "certificate", cert.name, cert.metadata, note)}
                </div>
              `;
            })
            .join("")}
        </div>`;

  els.hierarchyTree.innerHTML = `
    <div class="hierarchy-scroll">
      <div class="hierarchy" aria-label="Hierarchy for ${escapeHtml(store.name)}">
        ${renderTreeNode(store.name, "root", store.name, store.metadata)}
        ${branches}
      </div>
    </div>
  `;
}

function renderHierarchy() {
  if (!els.hierarchySelect || !els.hierarchyTree || !els.hierarchySummary) {
    return;
  }

  const stores = [...state.stores].sort((left, right) => left.name.localeCompare(right.name));
  const selected = selectedHierarchyName(stores);
  state.hierarchyStore = selected;

  if (stores.length === 0) {
    els.hierarchySelect.disabled = true;
    els.hierarchySelect.innerHTML = `<option value="">No Root CAs</option>`;
    renderHierarchyTree(null);
    return;
  }

  els.hierarchySelect.disabled = false;
  els.hierarchySelect.innerHTML = stores
    .map((store) => {
      const label = `${store.name} (${store.certificates.length})`;
      const isSelected = store.name === selected ? " selected" : "";
      return `<option value="${escapeHtml(store.name)}"${isSelected}>${escapeHtml(label)}</option>`;
    })
    .join("");

  renderHierarchyTree(stores.find((store) => store.name === selected) || null);
}

function findDetailRecord(kind, storeName, certName) {
  const store = state.stores.find((entry) => entry.name === storeName);
  if (!store) {
    return null;
  }

  if (kind === "root") {
    return {
      kind: "root",
      kicker: "Root CA",
      title: store.name,
      storeName: store.name,
      certName: null,
      metadata: store.metadata || {},
      artifacts: store.artifacts || {},
      relativeCert: store.relativeCert || `./certs/${store.name}/${store.name}.crt`,
    };
  }

  const cert = store.certificates.find((entry) => entry.name === certName);
  if (!cert) {
    return null;
  }

  return {
    kind: "certificate",
    kicker: `Certificate · ${store.name}`,
    title: cert.name,
    storeName: store.name,
    certName: cert.name,
    metadata: cert.metadata || {},
    artifacts: cert.artifacts || {},
    relativeCert: cert.relativeCert || `./certs/${store.name}/${cert.name}.crt`,
  };
}

function renderDetail() {
  const detail = state.detail;
  if (!detail) {
    return;
  }

  const metadata = detail.metadata || {};
  const san = metadata.subjectAltName || (detail.kind === "root" ? "None" : "No SAN data");
  const fingerprint = metadata.fingerprint || "Unavailable";

  els.detailKicker.textContent = detail.kicker;
  els.detailTitle.textContent = detail.title;
  els.detailBody.innerHTML = `
    <dl class="detail-grid">
      <div class="wide">
        <dt>Subject</dt>
        <dd>${escapeHtml(formatSubject(metadata.subject))}</dd>
      </div>
      <div class="wide">
        <dt>SAN</dt>
        <dd>${escapeHtml(san)}</dd>
      </div>
      <div>
        <dt>Valid from</dt>
        <dd>${escapeHtml(formatDate(metadata.notBefore))}</dd>
      </div>
      <div>
        <dt>Expiry</dt>
        <dd>${renderExpiryBadge(metadata.notAfter)} ${escapeHtml(formatDate(metadata.notAfter))}</dd>
      </div>
      <div class="wide">
        <dt>SHA-256 fingerprint</dt>
        <dd class="fingerprint">${escapeHtml(fingerprint)}</dd>
      </div>
      <div class="wide">
        <dt>Path</dt>
        <dd><code class="path-value">${escapeHtml(detail.relativeCert)}</code></dd>
      </div>
    </dl>
    <div class="download-row">
      <span class="meta-label">Download</span>
      ${renderDownloadButtons(detail.storeName, detail.certName, detail.artifacts) || `<span class="meta-label">No artifacts available</span>`}
    </div>
  `;
  const certAttr = detail.certName ? ` data-cert="${escapeHtml(detail.certName)}"` : "";
  const toolAttrs = `data-store="${escapeHtml(detail.storeName)}"${certAttr}`;
  els.detailFooter.innerHTML = `
    <button type="button" class="button button-secondary" data-action="view-info" ${toolAttrs}>View info</button>
    <button type="button" class="button button-secondary" data-action="open-convert" ${toolAttrs}>Convert</button>
    <button type="button" class="button button-secondary" data-action="open-password" ${toolAttrs}>Change password</button>
    <button type="button" class="button button-secondary" data-action="copy-path">Copy path</button>
    <button type="button" class="button button-secondary" data-action="copy-pem">Copy public PEM</button>
  `;
}

function openDetail(kind, storeName, certName) {
  const record = findDetailRecord(kind, storeName, certName);
  if (!record) {
    showToast("That certificate is no longer available. Refresh and try again.", "error");
    return;
  }

  state.detail = record;
  renderDetail();
  els.detailModal.hidden = false;
}

function closeDetail() {
  state.detail = null;
  els.detailModal.hidden = true;
}

function renderTrustGuide() {
  const stores = [...state.stores].sort((left, right) => left.name.localeCompare(right.name));
  const selected = selectTrustStore(stores, state.trustStore, state.config.ROOT_CA_NAME);
  state.trustStore = selected;
  const store = stores.find((entry) => entry.name === selected);
  const hasCrt = Boolean(selected && store?.artifacts?.crt);

  if (els.trustSelect) {
    if (!hasCrt) {
      els.trustSelect.disabled = true;
      els.trustSelect.innerHTML = `<option value="">No Root CAs</option>`;
    } else {
      els.trustSelect.disabled = false;
      els.trustSelect.innerHTML = stores
        .filter((entry) => entry.artifacts?.crt)
        .map((entry) => {
          const isSelected = entry.name === selected ? " selected" : "";
          return `<option value="${escapeHtml(entry.name)}"${isSelected}>${escapeHtml(entry.name)}</option>`;
        })
        .join("");
    }
  }

  if (els.trustDownload) {
    els.trustDownload.hidden = !hasCrt;
    els.trustDownload.disabled = !hasCrt;
    els.trustDownload.title = hasCrt ? `Download ${selected}.crt` : "";
  }

  if (!hasCrt) {
    els.trustCommands.innerHTML = `
      <div class="empty-state empty-cta trust-empty">
        <p>No Root CA on disk. Generate a certificate to create one under <code>./certs/</code>. Install commands show up here for Root CAs that exist.</p>
        <button type="button" class="button button-primary" data-action="go-generate">Generate a certificate</button>
      </div>
    `;
    return;
  }

  els.trustCommands.innerHTML = trustCommandsFor(selected)
    .map(
      (entry) => `
        <article class="trust-card">
          <div class="trust-card-header">
            <h3>${escapeHtml(entry.title)}</h3>
            <button
              type="button"
              class="button button-secondary button-small"
              data-action="copy-trust"
              data-platform="${escapeHtml(entry.id)}"
            >Copy</button>
          </div>
          <pre class="trust-command">${escapeHtml(entry.command)}</pre>
        </article>
      `,
    )
    .join("");
}

function syncHeaderActions(view) {
  const actions = document.querySelector(".topbar-actions");
  if (!actions) {
    return;
  }
  actions.hidden = view !== "generate" && view !== "config";
}

function switchView(view) {
  state.activeView = view;
  document.querySelectorAll(".nav-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${view}`);
  });

  const meta = viewMeta[view];
  els.viewTitle.textContent = meta.title;
  els.viewDescription.textContent = meta.description;
  syncHeaderActions(view);
  document.querySelector(`.nav-link[data-view="${view}"]`)?.scrollIntoView({
    inline: "nearest",
    block: "nearest",
  });
}

async function refreshAll() {
  const [configPayload, storesPayload, logsPayload, statusPayload] = await Promise.all([
    api("/api/config"),
    api("/api/stores"),
    api("/api/logs"),
    api("/api/status"),
  ]);

  state.config = configPayload.values;
  state.defaults = configPayload.defaults || {};
  state.sections = configPayload.sections;
  state.stores = storesPayload.stores;

  els.webuiUrl.textContent = statusPayload.webuiUrl;
  state.activePreset = "";
  updatePresetChrome();
  renderFormSections(els.generateFields, { collapsible: true, prefix: "generate" });
  renderFormSections(els.configFields, { includeWebUi: true, prefix: "config" });
  renderStats();
  renderStores();
  renderTrustGuide();

  const logText = logsPayload.output || "No operations yet.";
  els.dashboardLog.textContent = logText;
  if (!els.generateLog.dataset.touched) {
    els.generateLog.textContent = logText;
  }
}

async function handleGenerate(event) {
  event.preventDefault();
  const values = readFormValues(els.generateForm);
  const save = document.getElementById("save-before-generate").checked;

  setBusy(true, "Generating certificate...");
  try {
    const result = await api("/api/generate", {
      method: "POST",
      body: JSON.stringify({ values, save }),
    });

    els.generateLog.textContent = result.output || "Generation completed.";
    els.generateLog.dataset.touched = "true";
    els.dashboardLog.textContent = result.output || "Generation completed.";
    state.stores = result.stores || state.stores;
    if (save) {
      state.config = values;
    }
    renderStats();
    renderStores();
    renderTrustGuide();
    if ((result.output || "").includes("already exists")) {
      showToast("Certificate already exists. Set Force Regenerate to yes to overwrite.", "warning");
    } else {
      showToast("Certificate generation completed.");
    }
  } catch (error) {
    els.generateLog.textContent = error.message;
    els.generateLog.dataset.touched = "true";
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleValidate() {
  const values = readFormValues(els.generateForm);
  try {
    const result = await api("/api/config/validate", {
      method: "POST",
      body: JSON.stringify({ values }),
    });

    if (result.valid) {
      showToast("Configuration is valid.");
    } else {
      showToast(result.errors.join(" "), "error");
    }
  } catch (error) {
    showToast(error.message, "error");
  }
}

function applyConfigToForms(values) {
  const open = {};
  els.generateFields?.querySelectorAll("details[data-section]").forEach((node) => {
    open[node.dataset.section] = node.open;
  });
  if (Object.keys(open).length > 0) {
    state.generateOpen = open;
  }

  state.config = { ...values };
  state.activePreset = "";
  updatePresetChrome();
  renderFormSections(els.generateFields, { collapsible: true, prefix: "generate" });
  renderFormSections(els.configFields, { includeWebUi: true, prefix: "config" });
  renderStats();
}

async function handleResetDefaults() {
  setBusy(true, "Loading default values...");
  try {
    const payload = await api("/api/config");
    const defaults = payload.defaults;
    if (!defaults || !String(defaults.ROOT_CA_NAME || "").trim()) {
      throw new Error("Default values from .env.example are unavailable.");
    }

    state.defaults = defaults;
    applyConfigToForms(defaults);
    showToast("Restored default values from .env.example. .env was not changed.", "info");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleSaveConfig(event) {
  event.preventDefault();
  const values = readFormValues(els.configForm);

  setBusy(true, "Saving configuration...");
  try {
    const result = await api("/api/config", {
      method: "PUT",
      body: JSON.stringify({ values }),
    });

    state.config = result.values;
    renderStats();
    renderStores();
    renderTrustGuide();

    if (result.restartRequired) {
      showToast("Configuration saved. Restart the web UI to apply bind/port changes.", "warning");
    } else {
      showToast("Configuration saved.");
    }
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleReuseStore(storeName) {
  setBusy(true, "Loading Root CA...");
  try {
    const result = await api(`/api/stores/${encodeURIComponent(storeName)}/reuse-config`);
    state.config = { ...state.config, ...result.values };
    state.activePreset = "";
    state.generateOpen = { rootCa: false, certificate: true, advanced: false };
    document.getElementById("save-before-generate").checked = false;
    updatePresetChrome();
    renderFormSections(els.generateFields, { collapsible: true, prefix: "generate" });
    switchView("generate");

    let message = `Loaded Root CA '${storeName}'. Update the certificate fields, then generate.`;
    if (result.encryptedKey) {
      message += " This Root CA key is encrypted — enter ROOT_CA_PASSPHRASE before generating.";
    }
    showToast(message, result.encryptedKey ? "warning" : "info");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleDeleteStore(storeName) {
  const confirmed = window.confirm(
    `Delete Root CA '${storeName}' and all certificates in ./certs/${storeName}/? This cannot be undone.`,
  );
  if (!confirmed) {
    return;
  }

  setBusy(true, "Deleting Root CA...");
  try {
    const result = await api(`/api/stores/${encodeURIComponent(storeName)}`, {
      method: "DELETE",
    });
    state.stores = result.stores || [];
    if (state.trustStore === storeName) {
      state.trustStore = "";
    }
    if (state.hierarchyStore === storeName) {
      state.hierarchyStore = "";
    }
    renderStats();
    renderStores();
    renderTrustGuide();
    showToast(result.message || "Root CA deleted.");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleDeleteCertificate(storeName, certName) {
  const confirmed = window.confirm(
    `Delete certificate '${certName}' from '${storeName}'? The Root CA will be kept.`,
  );
  if (!confirmed) {
    return;
  }

  setBusy(true, "Deleting certificate...");
  try {
    const result = await api(
      `/api/stores/${encodeURIComponent(storeName)}/certificates/${encodeURIComponent(certName)}`,
      { method: "DELETE" },
    );
    state.stores = result.stores || [];
    renderStats();
    renderStores();
    showToast(result.message || "Certificate deleted.");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleDownload(storeName, certName, artifact) {
  if (artifact === "key") {
    const label = certName ? `certificate '${certName}'` : `Root CA '${storeName}'`;
    const confirmed = window.confirm(
      `Download the private key for ${label}?\n\nThis file is secret. Anyone with it can impersonate this certificate.`,
    );
    if (!confirmed) {
      return;
    }
  }

  const response = await fetch(downloadUrl(storeName, certName, artifact, artifact === "key"));
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || "Download failed");
  }

  const blob = await response.blob();
  const fileName =
    filenameFromDisposition(response.headers.get("Content-Disposition")) ||
    filenameFor(storeName, certName, artifact);
  saveBlob(blob, fileName);
  showToast(artifact === "key" ? "Private key download started." : `Downloading ${fileName}.`);
}

async function handleCopyPath() {
  if (!state.detail?.relativeCert) {
    return;
  }
  await copyText(state.detail.relativeCert, "Path copied.");
}

async function handleCopyPem() {
  if (!state.detail) {
    return;
  }
  const response = await fetch(
    downloadUrl(state.detail.storeName, state.detail.certName, "crt"),
  );
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || "Could not read the public certificate");
  }
  const pem = await response.text();
  if (!pem.includes("BEGIN CERTIFICATE")) {
    throw new Error("Public certificate PEM was not available");
  }
  await copyText(pem, "Public PEM copied.");
}

function archiveScopeCopy(scope, storeName, certName, items) {
  if (scope === "all") {
    return "Every Root CA store under ./certs.";
  }
  if (scope === "store") {
    return `Full chain / store ./certs/${storeName}/, including the Root CA and the certificates signed under it.`;
  }
  if (scope === "root") {
    return `Root CA only: the public ${storeName}.crt certificate, without the other files in that store.`;
  }
  if (scope === "selection") {
    const stores = (items || []).filter((item) => item.kind === "store").length;
    const certificates = (items || []).filter((item) => item.kind === "certificate").length;
    const parts = [];
    if (stores) {
      parts.push(`${stores} Root CA${stores === 1 ? "" : "s"}`);
    }
    if (certificates) {
      parts.push(`${certificates} certificate${certificates === 1 ? "" : "s"}`);
    }
    return `Export selected: ${parts.join(" and ")}.`;
  }
  return `This certificate: ${certName} from ${storeName}, including its public files and that store's public Root CA.`;
}

function storeScopeField(help) {
  return `
    <div class="field">
      <label for="archive-store-scope">Export scope</label>
      <select id="archive-store-scope">
        <option value="store" selected>Full chain / store</option>
        <option value="root">Root CA only</option>
      </select>
      <span class="meta-label">${help}</span>
    </div>
  `;
}

function certificateScopeField(multiple) {
  const label = multiple ? "These certificates" : "This certificate";
  return `
    <div class="field">
      <label for="archive-cert-scope">Export scope</label>
      <select id="archive-cert-scope" disabled>
        <option>${label}</option>
      </select>
      <span class="meta-label">Public certificate files for the selection, plus each store's public Root CA. The rest of the project stays out.</span>
    </div>
  `;
}

function closeArchive() {
  state.archive = null;
  state.archivePreview = null;
  if (els.archiveModal) {
    els.archiveModal.hidden = true;
    els.archiveBody.innerHTML = "";
    els.archiveFooter.innerHTML = "";
  }
}

function exportDialogTitle(scope) {
  if (scope === "all") {
    return "Export All";
  }
  if (scope === "selection") {
    return "Export selected";
  }
  return "Export TAR";
}

function exportScopeControl(target) {
  if (target.scope === "store") {
    return storeScopeField(
      "Full chain / store includes this Root CA and the certificates under it. Root CA only is the public Root certificate.",
    );
  }
  if (target.scope !== "selection") {
    return "";
  }

  const stores = (target.items || []).filter((item) => item.kind === "store").length;
  const certificates = (target.items || []).filter((item) => item.kind === "certificate").length;
  const parts = [];
  if (stores > 0) {
    parts.push(
      storeScopeField(
        "Applies to each selected Root CA. Checked certificates are still exported as This certificate.",
      ),
    );
  }
  if (certificates > 0 && stores === 0) {
    parts.push(certificateScopeField(certificates > 1));
  }
  return parts.join("");
}

function openExport(target) {
  state.archive = {
    mode: "export",
    scope: target.scope,
    storeName: target.storeName || null,
    certName: target.certName || null,
    items: target.items || null,
  };
  state.archivePreview = null;
  els.archiveKicker.textContent = "Export";
  els.archiveTitle.textContent = exportDialogTitle(target.scope);
  els.archiveBody.innerHTML = `
    <p class="panel-copy" id="archive-scope-copy">${escapeHtml(archiveScopeCopy(target.scope, target.storeName, target.certName, target.items))}</p>
    <div class="callout" id="archive-warning">
      Private keys and PKCS#12 bundles stay out of the TAR unless you include them.
      A TAR that contains <code>.key</code> or <code>.p12</code> files is a bundle of secrets:
      anyone with the file can impersonate these certificates.
      <p id="archive-key-warning" hidden>This download will include private keys.</p>
    </div>
    <div class="archive-options">
      ${exportScopeControl(target)}
      <label class="toggle">
        <input type="checkbox" id="archive-include-keys" />
        <span>Include private keys (.key and .p12)</span>
      </label>
      <label class="toggle">
        <input type="checkbox" id="archive-encrypt" />
        <span>Encrypt with OpenSSL AES-256</span>
      </label>
      <div class="field" id="archive-passphrase-field" hidden>
        <label for="archive-passphrase">Archive passphrase</label>
        <input id="archive-passphrase" type="password" autocomplete="new-password" />
        <span class="meta-label">Used only for this download. It is not stored in the manifest.</span>
      </div>
    </div>
  `;
  els.archiveFooter.innerHTML = `
    <button type="button" class="button button-secondary" data-action="close-archive">Cancel</button>
    <button type="button" class="button button-primary" data-action="confirm-export">Download TAR</button>
  `;
  els.archiveModal.hidden = false;
}

function openImport() {
  state.archive = { mode: "import" };
  state.archivePreview = null;
  els.archiveKicker.textContent = "Import";
  els.archiveTitle.textContent = "Import";
  els.archiveBody.innerHTML = `
    <p class="panel-copy">
      Upload a <code>.tar</code> or <code>.tar.gz</code> archive. Files are extracted only into
      <code>./certs/&lt;store&gt;/</code> after you preview them.
    </p>
    <div class="archive-options">
      <div class="field">
        <label for="archive-file">Archive</label>
        <input id="archive-file" type="file" accept=".tar,.gz,.tgz,.enc,application/gzip,application/x-tar" />
      </div>
      <div class="field">
        <label for="archive-passphrase">Passphrase</label>
        <input id="archive-passphrase" type="password" autocomplete="current-password" />
        <span class="meta-label">Required only when the archive was encrypted.</span>
      </div>
      <div class="field">
        <label for="archive-policy">When a file already exists</label>
        <select id="archive-policy">
          <option value="skip" selected>Skip</option>
          <option value="rename">Rename</option>
          <option value="overwrite">Overwrite</option>
        </select>
      </div>
      <label class="toggle" id="archive-overwrite-wrap" hidden>
        <input type="checkbox" id="archive-overwrite-confirm" />
        <span>Replace existing files in ./certs</span>
      </label>
    </div>
    <div id="archive-preview" class="archive-preview"></div>
  `;
  els.archiveFooter.innerHTML = `
    <button type="button" class="button button-secondary" data-action="close-archive">Cancel</button>
    <button type="button" class="button button-secondary" data-action="preview-import">Preview</button>
    <button type="button" class="button button-primary" data-action="confirm-import" disabled>Import</button>
  `;
  els.archiveModal.hidden = false;
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      const comma = result.indexOf(",");
      resolve(comma === -1 ? result : result.slice(comma + 1));
    };
    reader.onerror = () => reject(new Error("Could not read the archive"));
    reader.readAsDataURL(file);
  });
}

async function readImportFile() {
  const input = document.getElementById("archive-file");
  const file = input?.files?.[0];
  if (!file) {
    throw new Error("Choose a TAR archive to import");
  }
  if (file.size > 32 * 1024 * 1024) {
    throw new Error("Archive is too large");
  }
  return {
    archiveBase64: await fileToBase64(file),
    passphrase: document.getElementById("archive-passphrase")?.value || "",
    policy: document.getElementById("archive-policy")?.value || "skip",
    confirmOverwrite: Boolean(document.getElementById("archive-overwrite-confirm")?.checked),
  };
}

function renderImportPreview(preview) {
  const container = document.getElementById("archive-preview");
  const importButton = els.archiveFooter.querySelector("[data-action='confirm-import']");
  if (!container) {
    return;
  }

  const summary = preview.summary || {};
  const rows = (preview.files || [])
    .map((file) => {
      const secret = file.secret ? `<span class="badge secret">secret</span>` : "";
      const destination =
        file.destination && file.destination !== file.fileName
          ? ` → ${file.destination}`
          : "";
      return `
        <div class="archive-row">
          <span>${escapeHtml(file.path)}${escapeHtml(destination)}</span>
          <span class="cert-actions">
            ${secret}
            <span class="badge">${escapeHtml(file.action)}</span>
          </span>
        </div>
      `;
    })
    .join("");

  const encrypted = preview.encrypted
    ? `<p class="meta-label">Encrypted archive decrypted for preview.</p>`
    : "";
  const secrets = (preview.files || []).some((file) => file.secret)
    ? `<div class="callout danger">This archive contains private keys. Importing it writes those secrets into ./certs.</div>`
    : "";

  container.innerHTML = `
    ${encrypted}
    ${secrets}
    <p class="meta-label">
      ${summary.create || 0} new, ${summary.skip || 0} skipped,
      ${summary.rename || 0} renamed, ${summary.overwrite || 0} overwritten.
    </p>
    <div class="archive-list">${rows}</div>
  `;

  if (importButton) {
    importButton.disabled = !(preview.files || []).some((file) => file.action !== "skip");
  }
}

async function postImport(pathname, fields) {
  const response = await fetch(pathname, {
    method: "POST",
    headers: { "Content-Type": "application/vnd.ssl-gen.import+json" },
    body: JSON.stringify(fields),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.message || "Import failed");
  }
  return payload;
}

async function handleConfirmExport() {
  const archive = state.archive;
  if (!archive || archive.mode !== "export") {
    return;
  }

  const includeKeys = Boolean(document.getElementById("archive-include-keys")?.checked);
  const encrypt = Boolean(document.getElementById("archive-encrypt")?.checked);
  const passphrase = document.getElementById("archive-passphrase")?.value || "";

  if (encrypt && passphrase.length === 0) {
    showToast("Enter a passphrase to encrypt the archive.", "error");
    return;
  }

  if (includeKeys) {
    const confirmed = window.confirm(
      "Include private keys in this TAR?\n\nThe archive will contain .key and .p12 files. Anyone who gets the file can impersonate these certificates.",
    );
    if (!confirmed) {
      return;
    }
  }

  const pickedScope = document.getElementById("archive-store-scope")?.value;
  let scope = archive.scope;
  let items = null;
  if (scope === "store" && pickedScope === "root") {
    scope = "root";
  }
  if (scope === "selection") {
    const storeScope = pickedScope === "root" ? "root" : "store";
    items = (archive.items || []).map((item) =>
      item.kind === "store"
        ? { scope: storeScope, storeName: item.storeName }
        : { scope: "certificate", storeName: item.storeName, certName: item.certName },
    );
  }

  setBusy(true, "Building archive...");
  try {
    const response = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scope,
        storeName: archive.storeName,
        certName: archive.certName,
        items,
        includeKeys,
        confirmKeys: includeKeys,
        encrypt,
        passphrase: encrypt ? passphrase : "",
      }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.message || "Export failed");
    }

    const blob = await response.blob();
    const fileName =
      filenameFromDisposition(response.headers.get("Content-Disposition")) ||
      "ssl-gen-certs.tar.gz";
    const passphraseField = document.getElementById("archive-passphrase");
    if (passphraseField) {
      passphraseField.value = "";
    }
    setBusy(false);
    closeArchive();
    saveBlob(blob, fileName);
    showToast(
      includeKeys
        ? "Archive download started. It contains private keys."
        : `Downloading ${fileName}.`,
    );
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handlePreviewImport() {
  setBusy(true, "Previewing archive...");
  try {
    const fields = await readImportFile();
    const preview = await postImport("/api/import/preview", fields);
    state.archivePreview = preview;
    renderImportPreview(preview);
  } catch (error) {
    state.archivePreview = null;
    const importButton = els.archiveFooter.querySelector("[data-action='confirm-import']");
    if (importButton) {
      importButton.disabled = true;
    }
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function handleConfirmImport() {
  const preview = state.archivePreview;
  if (!preview) {
    showToast("Preview the archive before importing.", "error");
    return;
  }

  let fields;
  try {
    fields = await readImportFile();
  } catch (error) {
    showToast(error.message, "error");
    return;
  }

  if (fields.policy !== preview.policy) {
    showToast("Preview the archive again before importing.", "error");
    return;
  }

  if ((preview.summary?.overwrite || 0) > 0 && !fields.confirmOverwrite) {
    showToast("Confirm overwrite before replacing existing files.", "error");
    return;
  }

  setBusy(true, "Importing archive...");
  try {
    const result = await postImport("/api/import", fields);
    state.stores = result.stores || [];
    renderStats();
    renderStores();
    renderTrustGuide();
    const passphraseField = document.getElementById("archive-passphrase");
    if (passphraseField) {
      passphraseField.value = "";
    }
    closeArchive();
    showToast(result.message || "Import completed.");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

function handleArchiveChange(event) {
  if (event.target.id === "archive-store-scope" && state.archive) {
    const copy = document.getElementById("archive-scope-copy");
    const picked = event.target.value === "root" ? "root" : "store";
    if (copy && state.archive.scope === "store") {
      copy.textContent = archiveScopeCopy(picked, state.archive.storeName, null);
    } else if (copy && state.archive.scope === "selection") {
      const stores = (state.archive.items || []).filter((item) => item.kind === "store").length;
      const certificates = (state.archive.items || []).filter(
        (item) => item.kind === "certificate",
      ).length;
      const storeText =
        picked === "root"
          ? `${stores} Root CA${stores === 1 ? "" : "s"} as Root CA only`
          : `${stores} Root CA${stores === 1 ? "" : "s"} as full chain / store`;
      const certText = certificates
        ? ` and ${certificates} certificate${certificates === 1 ? "" : "s"} as This certificate`
        : "";
      copy.textContent = `Export selected: ${storeText}${certText}.`;
    }
  }

  if (event.target.id === "archive-include-keys") {
    const warning = document.getElementById("archive-warning");
    const extra = document.getElementById("archive-key-warning");
    warning?.classList.toggle("danger", event.target.checked);
    if (extra) {
      extra.hidden = !event.target.checked;
    }
  }

  if (event.target.id === "archive-encrypt") {
    const field = document.getElementById("archive-passphrase-field");
    if (field) {
      field.hidden = !event.target.checked;
    }
  }

  if (event.target.id === "archive-policy") {
    const wrap = document.getElementById("archive-overwrite-wrap");
    if (wrap) {
      wrap.hidden = event.target.value !== "overwrite";
    }
    state.archivePreview = null;
    const preview = document.getElementById("archive-preview");
    if (preview) {
      preview.innerHTML = "";
    }
    const importButton = els.archiveFooter.querySelector("[data-action='confirm-import']");
    if (importButton) {
      importButton.disabled = true;
    }
  }

  if (event.target.id === "archive-file") {
    state.archivePreview = null;
    const preview = document.getElementById("archive-preview");
    if (preview) {
      preview.innerHTML = "";
    }
    const importButton = els.archiveFooter.querySelector("[data-action='confirm-import']");
    if (importButton) {
      importButton.disabled = true;
    }
  }
}

function handleArchiveClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button || !els.archiveModal.contains(button)) {
    return;
  }

  const action = button.dataset.action;
  if (action === "close-archive") {
    closeArchive();
  } else if (action === "confirm-export") {
    handleConfirmExport();
  } else if (action === "preview-import") {
    handlePreviewImport();
  } else if (action === "confirm-import") {
    handleConfirmImport();
  }
}

function entityPath(storeName, certName, action) {
  const store = encodeURIComponent(storeName);
  return certName
    ? `/api/stores/${store}/certificates/${encodeURIComponent(certName)}/${action}`
    : `/api/stores/${store}/${action}`;
}

function closeTool() {
  const body = els.toolBody;
  if (body) {
    body.querySelectorAll("input, textarea").forEach((field) => {
      if (field.type === "password" || field.type === "text" || field.tagName === "TEXTAREA") {
        field.value = "";
      }
      if (field.type === "file") {
        field.value = "";
      }
    });
    body.innerHTML = "";
  }
  if (els.toolFooter) {
    els.toolFooter.innerHTML = "";
  }
  state.tool = null;
  if (els.toolModal) {
    els.toolModal.hidden = true;
  }
}

function infoRow(label, value, wide = false) {
  const text = String(value ?? "").trim();
  return `
    <div class="${wide ? "wide" : ""}">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(text || "None")}</dd>
    </div>
  `;
}

function renderChainCards(chain) {
  if (!chain?.present) {
    return `<p class="meta-label">${escapeHtml(chain?.notes?.[0] || "No full chain file is stored.")}</p>`;
  }

  const badge = chain.orderWrong
    ? `<span class="badge danger">Order looks wrong</span>`
    : chain.incomplete
      ? `<span class="badge warning">Incomplete chain</span>`
      : `<span class="badge success">Chain complete</span>`;
  const notes = (chain.notes || []).map((note) => `<p class="field-help">${escapeHtml(note)}</p>`).join("");
  const cards = (chain.certificates || [])
    .map((certificate) => {
      const link = (chain.links || []).find((item) => item.fromIndex === certificate.index);
      const bad = link && !link.matches;
      const relation = link
        ? `Issuer ${link.matches ? "matches" : "does not match"} the next subject: ${link.nextSubject}`
        : certificate.selfSigned
          ? "Self-signed. This is the trust anchor in the file."
          : "The issuer is not the next certificate in this file.";
      return `
        <article class="chain-card ${bad ? "bad" : chain.incomplete && !link ? "warn" : ""}">
          <strong>${certificate.index}. ${escapeHtml(certificate.commonName || certificate.subject || "Certificate")}</strong>
          <div class="meta-label">Subject: ${escapeHtml(certificate.subject || "Unknown")}</div>
          <div class="meta-label">Issuer: ${escapeHtml(certificate.issuer || "Unknown")}</div>
          <div class="meta-label">${escapeHtml(relation)}</div>
        </article>
      `;
    })
    .join("");

  return `
    <div class="chain-list">
      <div class="download-row">
        <span class="meta-label">${escapeHtml(chain.sourceFile || "Full chain")}</span>
        ${badge}
      </div>
      ${notes}
      ${cards}
    </div>
  `;
}

function renderInspect(info) {
  const certificate = info.certificate || {};
  const fingerprints = certificate.fingerprints || {};
  els.toolBody.innerHTML = `
    <dl class="detail-grid">
      ${infoRow("Subject", certificate.subject, true)}
      ${infoRow("Issuer", certificate.issuer, true)}
      ${infoRow("SAN", certificate.subjectAltName, true)}
      ${infoRow("Valid from", certificate.notBefore)}
      ${infoRow("Valid until", certificate.notAfter)}
      ${infoRow("Serial", certificate.serial)}
      ${infoRow("Key", certificate.key?.summary)}
      <div class="wide">
        <dt>SHA-256 fingerprint</dt>
        <dd class="fingerprint">${escapeHtml(fingerprints.sha256 || "Unavailable")}</dd>
      </div>
      <div class="wide">
        <dt>SHA-1 fingerprint</dt>
        <dd class="fingerprint">${escapeHtml(fingerprints.sha1 || "Unavailable")}</dd>
      </div>
      ${infoRow("Basic constraints", certificate.basicConstraints, true)}
      ${infoRow("Key usage", certificate.keyUsage, true)}
      ${infoRow("Extended key usage", certificate.extendedKeyUsage, true)}
      ${infoRow("Source", certificate.sourceFile)}
    </dl>
    <section>
      <h3>Chain</h3>
      ${renderChainCards(info.chain)}
    </section>
    <details>
      <summary>OpenSSL text</summary>
      <pre class="log-output openssl-text">${escapeHtml(certificate.text || "No OpenSSL text is available.")}</pre>
    </details>
  `;
  els.toolFooter.innerHTML = "";
}

function suggestedConvertName(fileName, to, kind) {
  const extension = to === "der" ? "der" : "pem";
  const source = fileName || `converted.${extension}`;
  if (kind === "key" || /\.key$/i.test(source) || /-key\.(pem|der)$/i.test(source)) {
    return `${source.replace(/(-key)?\.(key|pem|der)$/i, "")}-key.${extension}`;
  }
  if (/-fullchain\.(pem|der)$/i.test(source)) {
    return source.replace(/\.(pem|der)$/i, `.${extension}`);
  }
  return `${source.replace(/\.(crt|pem|der)$/i, "")}.${extension}`;
}

function renderConvert(material) {
  const files = material.files || [];
  const preferred = files.find((file) => file.convertible && file.fileName.endsWith(".crt")) || files.find((file) => file.convertible);
  const options = files
    .map((file) => {
      const selected = file.fileName === preferred?.fileName ? " selected" : "";
      const disabled = file.convertible ? "" : " disabled";
      const note = file.reason ? ` — ${file.reason}` : "";
      return `<option value="${escapeHtml(file.fileName)}"${selected}${disabled}>${escapeHtml(file.fileName + note)}</option>`;
    })
    .join("");
  const initialName = suggestedConvertName(preferred?.fileName || "converted.pem", "der", preferred?.kind);
  els.toolBody.innerHTML = `
    <div class="callout">
      Converts one X.509 certificate between PEM and DER, or an unencrypted private key.
      PKCS#12 files and encrypted keys belong under Change password.
      Saving or downloading a key writes secret key material. This UI is localhost-only and has no login.
    </div>
    <div class="tool-grid">
      <div class="field">
        <label for="convert-source">Source</label>
        <select id="convert-source">
          <option value="store" ${preferred ? "" : "disabled"}>File in this store</option>
          <option value="upload" ${preferred ? "" : "selected"}>Upload or paste</option>
        </select>
      </div>
      <div class="field" id="convert-store-field" ${preferred ? "" : "hidden"}>
        <label for="convert-file">Store file</label>
        <select id="convert-file">${options}</select>
      </div>
      <div class="field" id="convert-upload-field" ${preferred ? "hidden" : ""}>
        <label for="convert-upload">PEM or DER file</label>
        <input id="convert-upload" type="file" accept=".pem,.der,.crt,.cer,.key,application/x-pem-file,application/pkix-cert" />
      </div>
      <div class="field" id="convert-paste-field" ${preferred ? "hidden" : ""}>
        <label for="convert-paste">Or paste PEM</label>
        <textarea id="convert-paste" spellcheck="false" autocomplete="off" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
      </div>
      <div class="field">
        <label for="convert-to">Output format</label>
        <select id="convert-to">
          <option value="der" selected>DER</option>
          <option value="pem">PEM</option>
        </select>
      </div>
      <div class="field">
        <label for="convert-destination">Write result</label>
        <select id="convert-destination">
          <option value="download">Download only</option>
          <option value="store">Save into this store</option>
          <option value="both">Save and download</option>
        </select>
      </div>
      <div class="field">
        <label for="convert-output">File name</label>
        <input id="convert-output" type="text" value="${escapeHtml(initialName)}" autocomplete="off" spellcheck="false" />
        <p class="field-help">Saved next to the certificate as a new name. An existing file is kept unless you confirm overwrite.</p>
      </div>
      <label class="toggle">
        <input id="convert-overwrite" type="checkbox" />
        <span>Overwrite if that file already exists</span>
      </label>
    </div>
  `;
  els.toolFooter.innerHTML = `
    <button type="button" class="button button-primary" data-action="confirm-convert">Convert</button>
  `;
}

function passwordHelp(entry, label) {
  if (!entry?.present) {
    return `No ${label} file is stored for this certificate.`;
  }
  if (entry.passwordRequired) {
    return `A password is set on this ${label}. Enter the current password.`;
  }
  if (entry.encrypted) {
    return `This ${label} uses an empty password. Leave the current password blank.`;
  }
  return `This ${label} is not encrypted. Leave the current password blank to set one.`;
}

function renderPassword(material) {
  const password = material.password || {};
  const choices = [
    password.key?.present ? ["key", "Private key (.key)"] : null,
    password.p12?.present ? ["p12", "PKCS#12 (.p12)"] : null,
  ].filter(Boolean);
  if (choices.length === 0) {
    els.toolBody.innerHTML = `
      <div class="callout">No private key or PKCS#12 file is stored for this certificate.</div>
    `;
    els.toolFooter.innerHTML = "";
    return;
  }
  const options = choices
    .map(([value, label], index) => `<option value="${value}"${index === 0 ? " selected" : ""}>${label}</option>`)
    .join("");
  const initial = choices[0][0];
  const entry = password[initial];
  els.toolBody.innerHTML = `
    <div class="callout danger">
      This rewrites a private key or PKCS#12 file in the store. The password is not shown again and is not written to the operation log.
      This UI is localhost-only and has no login.
    </div>
    <div class="tool-grid">
      <div class="field">
        <label for="password-artifact">File</label>
        <select id="password-artifact">${options}</select>
      </div>
      <p class="field-help" id="password-help">${escapeHtml(passwordHelp(entry, initial === "key" ? "private key" : "PKCS#12 file"))}</p>
      <div class="field">
        <label for="password-current">Current password</label>
        <input id="password-current" type="password" autocomplete="current-password" />
      </div>
      <div class="field">
        <label for="password-new">New password</label>
        <input id="password-new" type="password" autocomplete="new-password" />
      </div>
      <div class="field">
        <label for="password-confirm">Confirm new password</label>
        <input id="password-confirm" type="password" autocomplete="new-password" />
        <p class="field-help">Type the new password twice. Leave both new fields empty only to remove a password that is already set. An empty password cannot replace an empty password.</p>
      </div>
    </div>
  `;
  els.toolFooter.innerHTML = `
    <button type="button" class="button button-primary" data-action="confirm-password">Change password</button>
  `;
}

async function refreshStoreViews() {
  const storesPayload = await api("/api/stores");
  state.stores = storesPayload.stores;
  renderStats();
  renderStores();
  renderHierarchy();
  renderTrustGuide();
  if (!state.detail) {
    return;
  }
  const updated = findDetailRecord(state.detail.kind, state.detail.storeName, state.detail.certName);
  if (!updated) {
    closeDetail();
    return;
  }
  state.detail = updated;
  renderDetail();
}

async function openTool(mode, storeName, certName) {
  if (!storeName || !els.toolModal) {
    return;
  }
  state.tool = { mode, storeName, certName: certName || null, material: null };
  const titles = {
    inspect: ["Certificate info", "OpenSSL fields and chain"],
    convert: ["Convert PEM / DER", "Certificate or unencrypted key"],
    password: ["Change password", "Encrypted key or PKCS#12"],
  };
  const [title, kicker] = titles[mode] || titles.inspect;
  els.toolTitle.textContent = title;
  els.toolKicker.textContent = certName ? `${kicker} · ${certName}` : `${kicker} · ${storeName}`;
  els.toolBody.innerHTML = `<p class="meta-label">Loading…</p>`;
  els.toolFooter.innerHTML = "";
  els.toolModal.hidden = false;

  try {
    if (mode === "inspect") {
      const info = await api(entityPath(storeName, certName, "inspect"));
      if (state.tool?.mode !== "inspect") {
        return;
      }
      renderInspect(info);
      return;
    }
    const material = await api(entityPath(storeName, certName, "material"));
    if (!state.tool || state.tool.mode !== mode) {
      return;
    }
    state.tool.material = material;
    if (mode === "convert") {
      renderConvert(material);
    } else {
      renderPassword(material);
    }
  } catch (error) {
    showToast(error.message, "error");
    closeTool();
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

async function handleConfirmConvert() {
  const tool = state.tool;
  if (!tool) {
    return;
  }
  const source = document.getElementById("convert-source")?.value || "upload";
  const to = document.getElementById("convert-to")?.value === "pem" ? "pem" : "der";
  const destination = document.getElementById("convert-destination")?.value || "download";
  const outputName = document.getElementById("convert-output")?.value.trim() || "";
  const overwrite = document.getElementById("convert-overwrite")?.checked === true;
  const body = {
    source,
    storeName: tool.storeName,
    certName: tool.certName,
    to,
    destination,
    outputName,
    overwrite,
    confirmSecret: false,
  };

  if (source === "store") {
    const fileName = document.getElementById("convert-file")?.value || "";
    if (!fileName) {
      showToast("Choose a file in the store.", "error");
      return;
    }
    body.fileName = fileName;
    const selected = (tool.material?.files || []).find((file) => file.fileName === fileName);
    if (selected?.kind === "key") {
      const confirmed = window.confirm(
        "This conversion reads and can write an unencrypted private key. The key is secret. Continue?",
      );
      if (!confirmed) {
        return;
      }
      body.confirmSecret = true;
    }
  } else {
    const file = document.getElementById("convert-upload")?.files?.[0];
    const paste = document.getElementById("convert-paste")?.value || "";
    if (!file && paste.trim().length === 0) {
      showToast("Upload a PEM or DER file, or paste PEM text.", "error");
      return;
    }
    if (file && file.size > 512 * 1024) {
      showToast("That file is too large to convert.", "error");
      return;
    }
    if (paste.includes("PRIVATE KEY")) {
      const confirmed = window.confirm(
        "This conversion reads and can write an unencrypted private key. The key is secret. Continue?",
      );
      if (!confirmed) {
        return;
      }
      body.confirmSecret = true;
    }
    if (file) {
      const hint = file.name.split(/[/\\]/).pop();
      if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(hint)) {
        body.fileName = hint;
      }
      body.contentBase64 = bytesToBase64(new Uint8Array(await file.arrayBuffer()));
    } else {
      body.contentBase64 = bytesToBase64(new TextEncoder().encode(paste));
    }
  }

  setBusy(true, "Converting…");
  try {
    const response = await postConvert(body);
    if (!response) {
      return;
    }
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const payload = await response.json();
      showToast(payload.message || "Saved the converted file.");
    } else {
      const blob = await response.blob();
      const fileName =
        filenameFromDisposition(response.headers.get("Content-Disposition")) || outputName || `converted.${to}`;
      saveBlob(blob, fileName);
      const stored = response.headers.get("X-Ssl-Gen-Stored");
      showToast(stored ? `Saved ${stored} and started the download.` : `Downloading ${fileName}.`);
    }
    if (destination !== "download") {
      await refreshStoreViews();
    }
    closeTool();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function postConvert(body) {
  const response = await fetch("/api/convert", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.status === 409 && body.overwrite !== true) {
    const payload = await response.json().catch(() => ({}));
    const confirmed = window.confirm(`${payload.message || "That file already exists."}\n\nOverwrite it?`);
    if (!confirmed) {
      return null;
    }
    return postConvert({ ...body, overwrite: true });
  }
  if (response.status === 400) {
    const payload = await response.json().catch(() => ({}));
    if (body.confirmSecret !== true && /requires confirmation/i.test(payload.message || "")) {
      const confirmed = window.confirm(
        "This conversion reads and can write an unencrypted private key. The key is secret. Continue?",
      );
      if (!confirmed) {
        return null;
      }
      return postConvert({ ...body, confirmSecret: true });
    }
    throw new Error(payload.message || "Conversion failed");
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.message || "Conversion failed");
  }
  return response;
}

async function handleConfirmPassword() {
  const tool = state.tool;
  if (!tool) {
    return;
  }
  const artifact = document.getElementById("password-artifact")?.value;
  const currentPassword = document.getElementById("password-current")?.value ?? "";
  const newPassword = document.getElementById("password-new")?.value ?? "";
  const confirmPassword = document.getElementById("password-confirm")?.value ?? "";
  const entry = tool.material?.password?.[artifact];
  if (!artifact || !entry?.present) {
    showToast("Choose a private key or PKCS#12 file.", "error");
    return;
  }
  if (newPassword !== confirmPassword) {
    showToast("New password and confirmation do not match.", "error");
    return;
  }
  if (entry.passwordRequired && currentPassword.length === 0) {
    showToast("Current password is required.", "error");
    return;
  }
  if (!entry.passwordRequired && newPassword.length === 0) {
    showToast("This file already has no password. Enter a new one.", "error");
    return;
  }

  setBusy(true, "Updating password…");
  try {
    const result = await api(entityPath(tool.storeName, tool.certName, "password"), {
      method: "POST",
      body: JSON.stringify({ artifact, currentPassword, newPassword, confirmPassword }),
    });
    showToast(result.message || "Password updated.");
    await refreshStoreViews();
    closeTool();
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    const current = document.getElementById("password-current");
    const next = document.getElementById("password-new");
    const confirm = document.getElementById("password-confirm");
    if (current) current.value = "";
    if (next) next.value = "";
    if (confirm) confirm.value = "";
    setBusy(false);
  }
}

function syncConvertFields() {
  const source = document.getElementById("convert-source")?.value;
  const storeField = document.getElementById("convert-store-field");
  const uploadField = document.getElementById("convert-upload-field");
  const pasteField = document.getElementById("convert-paste-field");
  const upload = source === "upload";
  if (storeField) storeField.hidden = upload;
  if (uploadField) uploadField.hidden = !upload;
  if (pasteField) pasteField.hidden = !upload;

  const to = document.getElementById("convert-to")?.value === "pem" ? "pem" : "der";
  const output = document.getElementById("convert-output");
  if (!output || output.dataset.touched === "true") {
    return;
  }
  if (upload) {
    const fileName = document.getElementById("convert-upload")?.files?.[0]?.name || `converted.${to}`;
    output.value = suggestedConvertName(fileName, to);
    return;
  }
  const fileName = document.getElementById("convert-file")?.value || "";
  const selected = (state.tool?.material?.files || []).find((file) => file.fileName === fileName);
  output.value = suggestedConvertName(fileName, to, selected?.kind);
}

function syncPasswordHelp() {
  const artifact = document.getElementById("password-artifact")?.value || "key";
  const help = document.getElementById("password-help");
  const entry = state.tool?.material?.password?.[artifact];
  if (help) {
    help.textContent = passwordHelp(entry, artifact === "key" ? "private key" : "PKCS#12 file");
  }
  ["password-current", "password-new", "password-confirm"].forEach((id) => {
    const field = document.getElementById(id);
    if (field) field.value = "";
  });
}

function handleToolChange(event) {
  if (event.target.id === "convert-output") {
    event.target.dataset.touched = "true";
    return;
  }
  if (event.target.id === "convert-source" || event.target.id === "convert-file" || event.target.id === "convert-to" || event.target.id === "convert-upload") {
    if (event.target.id !== "convert-output") {
      const output = document.getElementById("convert-output");
      if (output && event.target.id !== "convert-source") {
        delete output.dataset.touched;
      }
    }
    syncConvertFields();
  }
  if (event.target.id === "password-artifact") {
    syncPasswordHelp();
  }
}

function handleToolClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button || !els.toolModal?.contains(button)) {
    return;
  }
  const action = button.dataset.action;
  if (action === "close-tool") {
    closeTool();
  } else if (action === "confirm-convert") {
    handleConfirmConvert();
  } else if (action === "confirm-password") {
    handleConfirmPassword();
  }
}

function handleStoreAction(event) {
  const button = event.target.closest("[data-action]");
  if (!button) {
    return;
  }

  const action = button.dataset.action;
  const storeName = button.dataset.store;
  const certName = button.dataset.cert;

  if (action === "reuse-store" && storeName) {
    handleReuseStore(storeName);
  } else if (action === "delete-store" && storeName) {
    handleDeleteStore(storeName);
  } else if (action === "delete-cert" && storeName && certName) {
    handleDeleteCertificate(storeName, certName);
  } else if (action === "show-detail" && storeName) {
    openDetail(button.dataset.kind || (certName ? "certificate" : "root"), storeName, certName);
  } else if (action === "show-hierarchy" && storeName) {
    state.hierarchyStore = storeName;
    renderHierarchy();
    switchView("hierarchy");
  } else if (action === "go-generate") {
    switchView("generate");
  } else if (action === "clear-search") {
    state.storeQuery = "";
    if (els.storeSearch) {
      els.storeSearch.value = "";
    }
    renderStores();
  } else if (action === "export-archive" && button.dataset.scope) {
    openExport({
      scope: button.dataset.scope,
      storeName,
      certName: certName || null,
    });
  } else if (action === "download" && storeName && button.dataset.artifact) {
    handleDownload(storeName, certName || null, button.dataset.artifact).catch((error) => {
      showToast(error.message, "error");
    });
  } else if (action === "view-info" && storeName) {
    openTool("inspect", storeName, certName || null);
  } else if (action === "open-convert" && storeName) {
    openTool("convert", storeName, certName || null);
  } else if (action === "open-password" && storeName) {
    openTool("password", storeName, certName || null);
  } else if (action === "copy-path") {
    handleCopyPath().catch((error) => showToast(error.message, "error"));
  } else if (action === "copy-pem") {
    handleCopyPem().catch((error) => showToast(error.message, "error"));
  } else if (action === "close-detail") {
    closeDetail();
  }
}

async function handleRunTests() {
  setBusy(true, "Running tests...");
  try {
    const result = await api("/api/test", { method: "POST" });
    els.testLog.textContent = result.output || "Tests completed.";
    showToast(result.success ? "All tests passed." : "Tests failed.", result.success ? "success" : "error");
  } catch (error) {
    els.testLog.textContent = error.message;
    showToast(error.message, "error");
  } finally {
    setBusy(false);
  }
}

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => switchView(button.dataset.view));
});

document.getElementById("refresh-button").addEventListener("click", async () => {
  try {
    await refreshAll();
    showToast("Refreshed.", "info");
  } catch (error) {
    showToast(error.message, "error");
  }
});

document.getElementById("quick-generate-button").addEventListener("click", () => {
  switchView("generate");
});

document.getElementById("validate-button").addEventListener("click", handleValidate);
document.getElementById("reload-config-button").addEventListener("click", refreshAll);
document.getElementById("run-tests-button").addEventListener("click", handleRunTests);
els.storesList.addEventListener("click", handleStoreAction);
els.dashboardStores.addEventListener("click", handleStoreAction);
els.hierarchyTree.addEventListener("click", handleStoreAction);
els.hierarchySelect.addEventListener("change", () => {
  state.hierarchyStore = els.hierarchySelect.value;
  renderHierarchy();
});
els.dashboardExpiring.addEventListener("click", handleStoreAction);
els.detailModal.addEventListener("click", handleStoreAction);
function handleSelectionChange(event) {
  const box = event.target;
  if (!(box instanceof HTMLInputElement) || !box.dataset.select) {
    return;
  }
  const key = selectionKey(box.dataset.select, box.dataset.store, box.dataset.cert);
  if (box.checked) {
    state.selection.add(key);
  } else {
    state.selection.delete(key);
  }
  syncSelectionChecks();
}

function openSelectedExport() {
  const items = [...state.selection].map(parseSelectionKey);
  if (items.length === 0) {
    showToast("Select a Root CA or a certificate to export.", "info");
    return;
  }
  openExport({ scope: "selection", items });
}

function handleKeyTypeChange(event) {
  if (event.target?.name !== "KEY_TYPE" || !event.target.form) {
    return;
  }
  syncKeySizeField(event.target.form);
  if (event.target.form === els.generateForm) {
    refreshSectionSummaries();
  }
}

document.getElementById("dashboard-export-all-button").addEventListener("click", () => {
  openExport({ scope: "all" });
});
document.getElementById("dashboard-export-selected-button").addEventListener("click", openSelectedExport);
document.getElementById("dashboard-import-button").addEventListener("click", openImport);
document.getElementById("stores-export-all-button").addEventListener("click", () => {
  openExport({ scope: "all" });
});
document.getElementById("stores-export-selected-button").addEventListener("click", openSelectedExport);
document.getElementById("stores-import-button").addEventListener("click", openImport);
els.dashboardStores.addEventListener("change", handleSelectionChange);
els.storesList.addEventListener("change", handleSelectionChange);
els.archiveModal.addEventListener("click", handleArchiveClick);
els.archiveModal.addEventListener("change", handleArchiveChange);
els.toolModal?.addEventListener("click", handleToolClick);
els.toolModal?.addEventListener("change", handleToolChange);
els.toolModal?.addEventListener("input", handleToolChange);
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  if (els.toolModal && !els.toolModal.hidden) {
    closeTool();
    return;
  }
  if (els.archiveModal && !els.archiveModal.hidden) {
    closeArchive();
    return;
  }
  if (!els.detailModal.hidden) {
    closeDetail();
  }
});
els.generateForm.addEventListener("submit", handleGenerate);
els.generateForm.addEventListener("change", handleKeyTypeChange);
els.configForm.addEventListener("change", handleKeyTypeChange);
els.generateForm.addEventListener("input", (event) => {
  if (event.target?.name === "KEY_TYPE") {
    syncKeySizeField(els.generateForm);
  }
  refreshSectionSummaries();
  if (applyingPreset) {
    return;
  }
  const presetFields = new Set([
    "CERT_NAME",
    "CERT_COMMON_NAME",
    "CERT_DNS_NAMES",
    "CERT_IP_ADDRESSES",
  ]);
  if (presetFields.has(event.target?.name) && state.activePreset) {
    state.activePreset = "";
    updatePresetChrome();
  }
});
els.generateFields.addEventListener(
  "toggle",
  (event) => {
    const details = event.target;
    if (!details?.dataset?.section) {
      return;
    }
    state.generateOpen = {
      ...(state.generateOpen || defaultGenerateOpen()),
      [details.dataset.section]: details.open,
    };
  },
  true,
);
document.querySelectorAll(".preset-chip").forEach((button) => {
  button.addEventListener("click", () => applyPreset(button.dataset.preset));
});
document.getElementById("preset-lan-ip")?.addEventListener("input", () => {
  if (state.activePreset !== "lan") {
    return;
  }
  const ip = document.getElementById("preset-lan-ip").value.trim();
  if (ip && !isIpAddress(ip)) {
    return;
  }
  applyPreset("lan", { quiet: true });
});
document.getElementById("preset-lan-ip")?.addEventListener("focusout", (event) => {
  if (event.relatedTarget?.dataset?.preset || state.activePreset !== "lan") {
    return;
  }
  applyPreset("lan");
});
document.getElementById("preset-wildcard-base")?.addEventListener("input", () => {
  if (state.activePreset !== "wildcard") {
    return;
  }
  applyPreset("wildcard", { quiet: true });
});
document.getElementById("preset-wildcard-base")?.addEventListener("focusout", (event) => {
  if (event.relatedTarget?.dataset?.preset || state.activePreset !== "wildcard") {
    return;
  }
  applyPreset("wildcard");
});
els.storeSearch?.addEventListener("input", () => {
  state.storeQuery = els.storeSearch.value;
  renderStores();
});
document.getElementById("reset-defaults-button")?.addEventListener("click", () => {
  handleResetDefaults();
});
els.trustSelect?.addEventListener("change", () => {
  const next = els.trustSelect.value;
  if (!state.stores.some((entry) => entry.name === next && entry.artifacts?.crt)) {
    return;
  }
  state.trustStore = next;
  renderTrustGuide();
});
els.trustDownload?.addEventListener("click", () => {
  const store = state.stores.find((entry) => entry.name === state.trustStore && entry.artifacts?.crt);
  if (!store) {
    showToast("That Root CA is not on disk.", "warning");
    return;
  }
  handleDownload(store.name, null, "crt").catch((error) => showToast(error.message, "error"));
});
els.trustCommands.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) {
    return;
  }
  if (button.dataset.action === "go-generate") {
    switchView("generate");
    return;
  }
  if (button.dataset.action !== "copy-trust") {
    return;
  }
  const store = state.stores.find((entry) => entry.name === state.trustStore && entry.artifacts?.crt);
  if (!store) {
    return;
  }
  const command = trustCommandsFor(store.name).find(
    (entry) => entry.id === button.dataset.platform,
  );
  if (!command) {
    return;
  }
  copyText(command.command, `${command.title} command copied.`).catch((error) => {
    showToast(error.message, "error");
  });
});
els.configForm.addEventListener("submit", handleSaveConfig);

syncHeaderActions(state.activeView);
syncExportSelectedButtons();

refreshAll().catch((error) => {
  showToast(error.message, "error");
});