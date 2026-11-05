const state = {
  config: {},
  sections: {},
  stores: [],
  activeView: "dashboard",
  detail: null,
  archive: null,
  archivePreview: null,
  hierarchyStore: "",
};

const viewMeta = {
  dashboard: {
    title: "Dashboard",
    description: "Overview of your local certificate stores.",
  },
  generate: {
    title: "Generate Certificate",
    description: "Create or reuse a Root CA and sign a new server certificate.",
  },
  stores: {
    title: "Certificates",
    description: "Browse Root CAs, export a TAR, or import an archive into ./certs.",
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
    description: "Install your Root CA locally and run the automated test suite.",
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
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
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

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  els.toastStack.appendChild(toast);
  setTimeout(() => toast.remove(), 4200);
}

function setBusy(active, message = "Working...") {
  els.overlay.hidden = !active;
  els.overlayMessage.textContent = message;
  document.body.style.pointerEvents = active ? "none" : "";
}

function formatSubject(subject = "") {
  return subject.replace(/^subject=/, "").trim() || "Unknown";
}

function renderField(key, prefix) {
  const meta = fieldMeta[key] || { label: key };
  const value = state.config[key] ?? "";
  const id = `${prefix}-${key}`;
  const fieldClass = meta.full ? "field full" : "field";

  let control = `<input id="${id}" name="${key}" value="${escapeHtml(value)}" />`;

  if (meta.type === "textarea") {
    control = `<textarea id="${id}" name="${key}">${escapeHtml(value)}</textarea>`;
  } else if (meta.type === "select") {
    control = `<select id="${id}" name="${key}">
      ${meta.options
        .map(
          (option) =>
            `<option value="${option}" ${option === value ? "selected" : ""}>${option}</option>`,
        )
        .join("")}
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

function renderFormSections(container, includeWebUi = false) {
  const sections = Object.entries(state.sections)
    .filter(([name]) => includeWebUi || name !== "webui")
    .map(([name, section]) => {
      const fields = section.keys.map((key) => renderField(key, name)).join("");
      return `
        <section class="form-section">
          <h3>${section.title}</h3>
          <div class="field-grid">${fields}</div>
        </section>
      `;
    });

  container.innerHTML = sections.join("");
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
          </div>
        </div>
      `;
    })
    .join("")}</div>`;
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
          <div class="cert-actions">
            ${renderExpiryBadge(metadata.notAfter)}
            ${downloads}
            ${renderDetailsButton(store.name, cert.name)}
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
      : `<p class="empty-state">No signed certificates yet.</p>`;

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
        <div class="store-actions">
          ${renderExpiryBadge(store.metadata?.notAfter)}
          <span class="badge">${store.certificates.length} cert(s)</span>
          ${renderDetailsButton(store.name, null)}
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

function renderStores() {
  renderExpiring();
  const stores = sortedStores();

  if (stores.length === 0) {
    const empty = `<p class="empty-state">No certificate stores found. Generate your first certificate to create <code>./certs/${escapeHtml(state.config.ROOT_CA_NAME || "my-root-ca")}/</code>.</p>`;
    els.dashboardStores.innerHTML = empty;
    els.storesList.innerHTML = `<article class="panel"><div class="panel-body">${empty}</div></article>`;
    renderHierarchy();
    return;
  }

  els.dashboardStores.innerHTML = stores
    .slice(0, 2)
    .map((store) => renderStoreCard(store, true))
    .join("");

  els.storesList.innerHTML = stores.map((store) => renderStoreCard(store)).join("");
  renderHierarchy();
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
    els.hierarchyTree.innerHTML = `<p class="empty-state">No Root CA stores found. Generate a certificate to create one under <code>./certs/</code>.</p>`;
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
  els.detailFooter.innerHTML = `
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
  const rootCaName = state.config.ROOT_CA_NAME || "my-root-ca";
  const relativeCert = `./certs/${rootCaName}/${rootCaName}.crt`;

  els.trustCommands.innerHTML = `
    <article class="trust-card">
      <h3>macOS</h3>
      <pre class="trust-command">sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${relativeCert}</pre>
    </article>
    <article class="trust-card">
      <h3>Linux (Debian/Ubuntu)</h3>
      <pre class="trust-command">sudo cp ${relativeCert} /usr/local/share/ca-certificates/${rootCaName}.crt
sudo update-ca-certificates</pre>
    </article>
    <article class="trust-card">
      <h3>Windows</h3>
      <pre class="trust-command">Import ${relativeCert} into Trusted Root Certification Authorities via certmgr.msc</pre>
    </article>
  `;
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
}

async function refreshAll() {
  const [configPayload, storesPayload, logsPayload, statusPayload] = await Promise.all([
    api("/api/config"),
    api("/api/stores"),
    api("/api/logs"),
    api("/api/status"),
  ]);

  state.config = configPayload.values;
  state.sections = configPayload.sections;
  state.stores = storesPayload.stores;

  els.webuiUrl.textContent = statusPayload.webuiUrl;
  renderFormSections(els.generateFields, false);
  renderFormSections(els.configFields, true);
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
      showToast("Certificate already exists. Set Force Regenerate to yes to overwrite.", "error");
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
      showToast("Configuration saved. Restart the web UI to apply bind/port changes.", "error");
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
    document.getElementById("save-before-generate").checked = false;
    renderFormSections(els.generateFields, false);
    switchView("generate");

    let message = `Loaded Root CA '${storeName}'. Update the certificate fields, then generate.`;
    if (result.encryptedKey) {
      message += " This Root CA key is encrypted — enter ROOT_CA_PASSPHRASE before generating.";
    }
    showToast(message);
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

function archiveScopeCopy(scope, storeName, certName) {
  if (scope === "all") {
    return "Every Root CA store under ./certs.";
  }
  if (scope === "store") {
    return `Root CA store ./certs/${storeName}/.`;
  }
  return `Certificate ${certName} from ${storeName}, plus that store's public Root CA certificate.`;
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

function openExport(target) {
  state.archive = {
    mode: "export",
    scope: target.scope,
    storeName: target.storeName || null,
    certName: target.certName || null,
  };
  state.archivePreview = null;
  els.archiveKicker.textContent = "Export";
  els.archiveTitle.textContent = "Export TAR";
  els.archiveBody.innerHTML = `
    <p class="panel-copy">${escapeHtml(archiveScopeCopy(target.scope, target.storeName, target.certName))}</p>
    <div class="callout" id="archive-warning">
      Private keys and PKCS#12 bundles stay out of the TAR unless you include them.
      A TAR that contains <code>.key</code> or <code>.p12</code> files is a bundle of secrets:
      anyone with the file can impersonate these certificates.
      <p id="archive-key-warning" hidden>This download will include private keys.</p>
    </div>
    <div class="archive-options">
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
  els.archiveTitle.textContent = "Import TAR";
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

  setBusy(true, "Building archive...");
  try {
    const response = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scope: archive.scope,
        storeName: archive.storeName,
        certName: archive.certName,
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
    showToast("Refreshed.");
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
document.getElementById("dashboard-export-all-button").addEventListener("click", () => {
  openExport({ scope: "all" });
});
document.getElementById("dashboard-import-button").addEventListener("click", openImport);
document.getElementById("stores-export-all-button").addEventListener("click", () => {
  openExport({ scope: "all" });
});
document.getElementById("stores-import-button").addEventListener("click", openImport);
els.archiveModal.addEventListener("click", handleArchiveClick);
els.archiveModal.addEventListener("change", handleArchiveChange);
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
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
els.configForm.addEventListener("submit", handleSaveConfig);

refreshAll().catch((error) => {
  showToast(error.message, "error");
});