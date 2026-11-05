const fs = require("fs");
const https = require("https");
const path = require("path");
const express = require("express");
const {
  ENV_SECTIONS,
  readEnvFile,
  writeEnvFile,
  validateConfig,
} = require("./lib/env");
const {
  discoverStores,
  deleteStore,
  deleteCertificate,
  buildReuseConfig,
  resolveDownloadArtifact,
} = require("./lib/certs");
const { runScript, getLastOutput, isRunning } = require("./lib/runner");

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/project";
const ENV_PATH = path.join(PROJECT_ROOT, ".env");
const RUN_ENV_PATH = path.join(PROJECT_ROOT, ".env.run");
const GENERATE_SCRIPT = path.join(PROJECT_ROOT, "scripts", "generate-certs.sh");
const TEST_SCRIPT = path.join(PROJECT_ROOT, "scripts", "test-inline.sh");
const UI_SSL_KEY = path.join(PROJECT_ROOT, "ui-ssl", "server.key");
const UI_SSL_CERT = path.join(PROJECT_ROOT, "ui-ssl", "server.crt");
const INTERNAL_PORT = Number(process.env.WEBUI_INTERNAL_PORT || "8443");
const PUBLIC_DIR = path.join(__dirname, "public");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(PUBLIC_DIR));

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function getWebUiUrl(values) {
  const bind = (values.WEBUI_BIND || "127.0.0.1").trim();
  const port = (values.WEBUI_PORT || "8443").trim();
  return `https://${bind}:${port}`;
}

app.get(
  "/api/status",
  asyncHandler(async (_req, res) => {
    const config = readEnvFile(ENV_PATH);
    res.json({
      running: isRunning(),
      webuiUrl: getWebUiUrl(config),
      projectRoot: PROJECT_ROOT,
    });
  }),
);

app.get(
  "/api/config",
  asyncHandler(async (_req, res) => {
    const values = readEnvFile(ENV_PATH);
    res.json({
      values,
      sections: ENV_SECTIONS,
    });
  }),
);

app.put(
  "/api/config",
  asyncHandler(async (req, res) => {
    const current = readEnvFile(ENV_PATH);
    const next = { ...current, ...(req.body?.values || {}) };
    const errors = validateConfig(next);

    if (errors.length > 0) {
      res.status(400).json({ errors });
      return;
    }

    writeEnvFile(ENV_PATH, next);
    res.json({
      values: next,
      message: "Configuration saved",
      restartRequired:
        next.WEBUI_PORT !== current.WEBUI_PORT ||
        next.WEBUI_BIND !== current.WEBUI_BIND,
    });
  }),
);

app.post(
  "/api/config/validate",
  asyncHandler(async (req, res) => {
    const current = readEnvFile(ENV_PATH);
    const candidate = { ...current, ...(req.body?.values || {}) };
    const errors = validateConfig(candidate);
    res.json({ valid: errors.length === 0, errors });
  }),
);

app.get(
  "/api/stores",
  asyncHandler(async (_req, res) => {
    res.json({
      stores: discoverStores(PROJECT_ROOT),
    });
  }),
);

app.get(
  "/api/stores/:storeName/reuse-config",
  asyncHandler(async (req, res) => {
    const current = readEnvFile(ENV_PATH);
    const result = buildReuseConfig(PROJECT_ROOT, req.params.storeName, current);
    res.json(result);
  }),
);

app.delete(
  "/api/stores/:storeName",
  asyncHandler(async (req, res) => {
    const result = deleteStore(PROJECT_ROOT, req.params.storeName);
    res.json({
      message: `Deleted Root CA store '${result.storeName}'`,
      stores: discoverStores(PROJECT_ROOT),
    });
  }),
);

function sendArtifact(res, artifact) {
  res.setHeader("Content-Type", artifact.contentType);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${artifact.fileName}"; filename*=UTF-8''${encodeURIComponent(artifact.fileName)}`,
  );
  res.sendFile(artifact.filePath, { dotfiles: "deny" }, (error) => {
    if (!error || res.headersSent) {
      return;
    }

    console.error(error);
    res.status(404).json({ message: "Artifact was not found" });
  });
}

function downloadHandler(readCertName) {
  return asyncHandler(async (req, res) => {
    const confirmed = req.query.confirm === "1";
    const artifact = resolveDownloadArtifact(
      PROJECT_ROOT,
      req.params.storeName,
      readCertName ? req.params.certName : null,
      req.params.artifact,
      { confirm: confirmed },
    );
    sendArtifact(res, artifact);
  });
}

app.get("/api/stores/:storeName/download/:artifact", downloadHandler(false));

app.get(
  "/api/stores/:storeName/certificates/:certName/download/:artifact",
  downloadHandler(true),
);

app.delete(
  "/api/stores/:storeName/certificates/:certName",
  asyncHandler(async (req, res) => {
    const result = deleteCertificate(
      PROJECT_ROOT,
      req.params.storeName,
      req.params.certName,
    );
    res.json({
      message: `Deleted certificate '${result.certName}' from '${result.storeName}'`,
      removed: result.removed,
      stores: discoverStores(PROJECT_ROOT),
    });
  }),
);

app.get(
  "/api/logs",
  asyncHandler(async (_req, res) => {
    res.json({
      running: isRunning(),
      output: getLastOutput(),
    });
  }),
);

app.post(
  "/api/generate",
  asyncHandler(async (req, res) => {
    if (isRunning()) {
      res.status(409).json({ message: "Another operation is already running" });
      return;
    }

    const current = readEnvFile(ENV_PATH);
    const next = { ...current, ...(req.body?.values || {}) };
    const errors = validateConfig(next);

    if (errors.length > 0) {
      res.status(400).json({ errors });
      return;
    }

    writeEnvFile(RUN_ENV_PATH, next);

    if (req.body?.save !== false) {
      writeEnvFile(ENV_PATH, next);
    }

    let result;

    try {
      result = await runScript(GENERATE_SCRIPT, {
        cwd: PROJECT_ROOT,
        env: {
          ...process.env,
          ENV_FILE: RUN_ENV_PATH,
        },
      });
    } finally {
      if (fs.existsSync(RUN_ENV_PATH)) {
        fs.unlinkSync(RUN_ENV_PATH);
      }
    }

    res.status(result.success ? 200 : 500).json({
      success: result.success,
      output: result.output,
      stores: discoverStores(PROJECT_ROOT),
    });
  }),
);

app.post(
  "/api/test",
  asyncHandler(async (_req, res) => {
    if (isRunning()) {
      res.status(409).json({ message: "Another operation is already running" });
      return;
    }

    const result = await runScript(TEST_SCRIPT, {
      cwd: PROJECT_ROOT,
      env: process.env,
    });

    res.status(result.success ? 200 : 500).json({
      success: result.success,
      output: result.output,
    });
  }),
);

app.use((error, _req, res, _next) => {
  const status = error.statusCode || 500;
  if (status >= 500) {
    console.error(error);
  }
  if (res.headersSent) {
    return;
  }
  res.status(status).json({
    message: error.message || "Internal server error",
  });
});

app.use((_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

function start() {
  if (!fs.existsSync(UI_SSL_KEY) || !fs.existsSync(UI_SSL_CERT)) {
    console.error("UI SSL certificate not found. Run scripts/generate-ui-ssl.sh first.");
    process.exit(1);
  }

  https
    .createServer(
      {
        key: fs.readFileSync(UI_SSL_KEY),
        cert: fs.readFileSync(UI_SSL_CERT),
      },
      app,
    )
    .listen(INTERNAL_PORT, "0.0.0.0", () => {
      const config = readEnvFile(ENV_PATH);
      console.log(`ssl-gen web UI listening on port ${INTERNAL_PORT}`);
      console.log(`Open ${getWebUiUrl(config)} from the Docker host`);
    });
}

if (require.main === module) {
  start();
}

module.exports = { app };