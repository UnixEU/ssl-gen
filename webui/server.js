const fs = require("fs");
const https = require("https");
const path = require("path");
const express = require("express");
const {
  ENV_SECTIONS,
  readMergedEnv,
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
const { exportArchive, previewImport, applyImport } = require("./lib/archive");
const {
  changeMaterialPassword,
  convertMaterial,
  describeMaterial,
  inspectMaterial,
  publicConversion,
} = require("./lib/material");
const { runScript, getLastOutput, isRunning } = require("./lib/runner");

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/project";
const ENV_PATH = path.join(PROJECT_ROOT, ".env");
const EXAMPLE_PATH = path.join(PROJECT_ROOT, ".env.example");
const RUN_ENV_PATH = path.join(PROJECT_ROOT, ".env.run");
const GENERATE_SCRIPT = path.join(PROJECT_ROOT, "scripts", "generate-certs.sh");
const TEST_SCRIPT = path.join(PROJECT_ROOT, "scripts", "test-inline.sh");
const UI_SSL_KEY = path.join(PROJECT_ROOT, "ui-ssl", "server.key");
const UI_SSL_CERT = path.join(PROJECT_ROOT, "ui-ssl", "server.crt");
const INTERNAL_PORT = Number(process.env.WEBUI_INTERNAL_PORT || "8443");
const PUBLIC_DIR = path.join(__dirname, "public");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.static(PUBLIC_DIR));

function loadConfig() {
  return readMergedEnv(ENV_PATH, EXAMPLE_PATH);
}

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
    const { values: config } = loadConfig();
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
    const { values, defaults } = loadConfig();
    res.json({
      values,
      defaults,
      sections: ENV_SECTIONS,
    });
  }),
);

app.put(
  "/api/config",
  asyncHandler(async (req, res) => {
    const { values: current } = loadConfig();
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
    const { values: current } = loadConfig();
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
    const { values: current } = loadConfig();
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

const importParser = express.raw({
  type: "application/vnd.ssl-gen.import+json",
  limit: "48mb",
});

function readImportPayload(req) {
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
    const error = new Error("Import request is empty");
    error.statusCode = 400;
    throw error;
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    const error = new Error("Import request is not valid JSON");
    error.statusCode = 400;
    throw error;
  }

  if (!payload || typeof payload.archiveBase64 !== "string" || payload.archiveBase64.length === 0) {
    const error = new Error("Archive upload is required");
    error.statusCode = 400;
    throw error;
  }

  const buffer = Buffer.from(payload.archiveBase64, "base64");
  if (buffer.length === 0) {
    const error = new Error("Archive upload is empty");
    error.statusCode = 400;
    throw error;
  }

  return { payload, buffer };
}

function importOptions(payload) {
  return {
    policy: payload.policy,
    passphrase: typeof payload.passphrase === "string" ? payload.passphrase : "",
    confirmOverwrite: payload.confirmOverwrite === true,
  };
}

app.post(
  "/api/export",
  asyncHandler(async (req, res) => {
    const archive = exportArchive(PROJECT_ROOT, {
      scope: req.body?.scope,
      storeName: req.body?.storeName,
      certName: req.body?.certName,
      items: req.body?.items,
      includeKeys: req.body?.includeKeys === true,
      confirmKeys: req.body?.confirmKeys === true,
      encrypt: req.body?.encrypt === true,
      passphrase: typeof req.body?.passphrase === "string" ? req.body.passphrase : "",
    });

    res.setHeader(
      "Content-Type",
      archive.encrypted ? "application/octet-stream" : "application/gzip",
    );
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${archive.fileName}"; filename*=UTF-8''${encodeURIComponent(archive.fileName)}`,
    );
    res.send(archive.data);
  }),
);

app.post(
  "/api/import/preview",
  importParser,
  asyncHandler(async (req, res) => {
    const { payload, buffer } = readImportPayload(req);
    res.json(previewImport(PROJECT_ROOT, buffer, importOptions(payload)));
  }),
);

app.post(
  "/api/import",
  importParser,
  asyncHandler(async (req, res) => {
    const { payload, buffer } = readImportPayload(req);
    const result = applyImport(PROJECT_ROOT, buffer, importOptions(payload));
    const written = result.summary.create + result.summary.rename + result.summary.overwrite;
    res.json({
      ...result,
      message: `Imported ${written} file(s). Skipped ${result.summary.skip}.`,
    });
  }),
);

function certNameFrom(req) {
  return req.params.certName || null;
}

app.get(
  "/api/stores/:storeName/material",
  asyncHandler(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json(describeMaterial(PROJECT_ROOT, req.params.storeName, null));
  }),
);

app.get(
  "/api/stores/:storeName/certificates/:certName/material",
  asyncHandler(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json(describeMaterial(PROJECT_ROOT, req.params.storeName, certNameFrom(req)));
  }),
);

app.get(
  "/api/stores/:storeName/inspect",
  asyncHandler(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json(inspectMaterial(PROJECT_ROOT, req.params.storeName, null));
  }),
);

app.get(
  "/api/stores/:storeName/certificates/:certName/inspect",
  asyncHandler(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json(inspectMaterial(PROJECT_ROOT, req.params.storeName, certNameFrom(req)));
  }),
);

app.post(
  "/api/convert",
  asyncHandler(async (req, res) => {
    const result = convertMaterial(PROJECT_ROOT, req.body || {});
    const download = (req.body?.destination || "download") !== "store";
    if (download) {
      res.setHeader("Content-Type", result.contentType);
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");
      if (result.stored) {
        res.setHeader("X-Ssl-Gen-Stored", result.fileName);
      }
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${result.fileName}"; filename*=UTF-8''${encodeURIComponent(result.fileName)}`,
      );
      res.send(result.data);
      return;
    }

    res.setHeader("Cache-Control", "no-store");
    res.json(publicConversion(result));
  }),
);

function passwordHandler(readCertName) {
  return asyncHandler(async (req, res) => {
    const result = changeMaterialPassword(
      PROJECT_ROOT,
      req.params.storeName,
      readCertName ? req.params.certName : null,
      req.body || {},
    );
    res.setHeader("Cache-Control", "no-store");
    res.json(result);
  });
}

app.post("/api/stores/:storeName/password", passwordHandler(false));
app.post("/api/stores/:storeName/certificates/:certName/password", passwordHandler(true));

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

    const { values: current } = loadConfig();
    const next = { ...current, ...(req.body?.values || {}) };
    const errors = validateConfig(next);

    if (errors.length > 0) {
      res.status(400).json({ errors });
      return;
    }

    writeEnvFile(RUN_ENV_PATH, next);

    // Persist only when the user explicitly opts in. Leaving this off must not
    // create, rewrite, or delete an existing .env.
    if (req.body?.save === true) {
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
  const status = error.statusCode || error.status || 500;
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
      const { values: config } = loadConfig();
      console.log(`ssl-gen web UI listening on port ${INTERNAL_PORT}`);
      console.log(`Open ${getWebUiUrl(config)} from the Docker host`);
    });
}

if (require.main === module) {
  start();
}

module.exports = { app };