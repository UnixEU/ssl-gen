const state = {
  config: {},
  sections: {},
  stores: [],
  activeView: "dashboard",
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
    description: "Browse generated Root CAs and signed certificates.",
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
  trustCommands: document.getElementById("trust-commands"),
  toastStack: document.getElementById("toast-stack"),
  overlay: document.getElementById("overlay"),
  overlayMessage: document.getElementById("overlay-message"),
};

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
  const expiringSoon = state.stores
    .flatMap((store) => store.certificates)
    .filter((cert) => {
      const end = cert.metadata?.notAfter;
      if (!end) return false;
      const expiry = new Date(end);
      const days = (expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      return days <= 30;
    }).length;

  const cards = [
    ["Root CAs", state.stores.length],
    ["Certificates", totalCerts],
    ["Current CA", state.config.ROOT_CA_NAME || "—"],
    ["Expiring Soon", expiringSoon],
  ];

  els.statsGrid.innerHTML = cards
    .map(
      ([label, value]) => `
        <article class="stat-card">
          <p class="stat-label">${label}</p>
          <p class="stat-value">${escapeHtml(String(value))}</p>
        </article>
      `,
    )
    .join("");
}

function renderStoreCard(store, compact = false) {
  const reuseStoreButton = compact
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

  const certs = store.certificates
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

      return `
        <div class="cert-row">
          <div>
            <strong>${escapeHtml(cert.name)}</strong>
            <div class="meta-label">${escapeHtml(formatSubject(metadata.subject))}</div>
            <div class="meta-label">${escapeHtml(metadata.subjectAltName || "No SAN data")}</div>
          </div>
          <div class="cert-actions">
            <div class="badge ${cert.hasKey ? "success" : ""}">
              ${escapeHtml(metadata.notAfter || "Unknown expiry")}
            </div>
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

  return `
    <article class="store-card">
      <div class="store-header">
        <div>
          <h3>${escapeHtml(store.name)}</h3>
          <p class="meta-label">${escapeHtml(formatSubject(store.metadata?.subject))}</p>
          <p class="meta-label">${escapeHtml(store.relativePath || `./certs/${store.name}`)}</p>
        </div>
        <div class="store-actions">
          <span class="badge">${store.certificates.length} cert(s)</span>
          ${reuseStoreButton}
          ${deleteStoreButton}
        </div>
      </div>
      <div class="meta-list">
        <div class="meta-item">
          <span class="meta-label">Root CA valid until</span>
          <span class="meta-value">${escapeHtml(store.metadata?.notAfter || "Unknown")}</span>
        </div>
      </div>
      ${filesSection}
      ${certSection}
    </article>
  `;
}

function renderStores() {
  if (state.stores.length === 0) {
    const empty = `<p class="empty-state">No certificate stores found. Generate your first certificate to create <code>./certs/${escapeHtml(state.config.ROOT_CA_NAME || "my-root-ca")}/</code>.</p>`;
    els.dashboardStores.innerHTML = empty;
    els.storesList.innerHTML = `<article class="panel"><div class="panel-body">${empty}</div></article>`;
    return;
  }

  els.dashboardStores.innerHTML = state.stores
    .slice(0, 2)
    .map((store) => renderStoreCard(store, true))
    .join("");

  els.storesList.innerHTML = state.stores
    .map((store) => renderStoreCard(store))
    .join("");
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
els.generateForm.addEventListener("submit", handleGenerate);
els.configForm.addEventListener("submit", handleSaveConfig);

refreshAll().catch((error) => {
  showToast(error.message, "error");
});