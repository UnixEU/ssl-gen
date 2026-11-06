# SSL Certificate Generator

A Docker-based tool for creating self-signed SSL certificates with a reusable local Root CA. Configure everything through a single `.env` file and run one command to generate certificates.

## Goal

Provide one place to create and manage self-signed SSL certificates for local development. The project generates a private Root CA, uses it to sign server certificates, and stores all artifacts under `./certs/<ROOT_CA_NAME>/`. When you need more certificates later, it reuses the existing Root CA instead of creating a new one. A local web UI can edit the same `.env` file and generate certificates into that folder.

## Table of Contents

1. [Requirements](#1-requirements)
2. [Project Structure](#2-project-structure)
3. [Setup](#3-setup)
4. [Configuration](#4-configuration)
5. [Generating Your First Certificate](#5-generating-your-first-certificate)
6. [Generating Additional Certificates](#6-generating-additional-certificates)
7. [Web UI](#7-web-ui)
8. [Using the Certificates](#8-using-the-certificates)
9. [Trusting the Root CA Locally](#9-trusting-the-root-ca-locally)
10. [Security Notes](#10-security-notes)
11. [Testing](#11-testing)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Requirements

Install these before generating certificates:

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- `make` (optional, for convenience commands)

Ensure Docker is running before you generate certificates.

---

## 2. Project Structure

```
.
├── Dockerfile             # Alpine image with OpenSSL for certificate generation
├── docker-compose.yaml    # ssl-gen and webui services; project bind-mounted at /project
├── Makefile               # Convenience commands (setup, certs, webui, test, reset)
├── .env.example           # Configuration template (committed to git)
├── .env                   # Your local configuration (not committed)
├── certs/                 # Generated output: ./certs/<ROOT_CA_NAME>/
├── README.md
├── scripts/
│   ├── generate-certs.sh  # Certificate generation logic
│   ├── generate.sh        # Wrapper for docker compose run --rm ssl-gen generate
│   ├── generate-ui-ssl.sh # Self-signed TLS certificate for the web UI
│   ├── test.sh            # Wrapper for docker compose run --rm ssl-gen test
│   └── reset-project.sh   # Restore the project to template defaults
└── webui/                 # Local HTTPS UI (separate Node image)
    ├── Dockerfile
    ├── server.js
    └── public/
```

Generated certificates are written to `./certs/<ROOT_CA_NAME>/` (for example, `./certs/my-root-ca/`). Each Root CA has its own directory inside `certs/`. The `ssl-gen` and `webui` services both bind-mount the project directory, so files created in the container stay in that folder on the host.

---

## 3. Setup

Copy the template configuration to create your local `.env`:

```bash
make setup
```

Or manually:

```bash
cp .env.example .env
```

Edit `.env` with your Root CA and certificate details before generating.

---

## 4. Configuration

All settings live in `.env`. File and folder names are taken directly from `ROOT_CA_NAME` and `CERT_NAME`.

### Root CA Settings

| Variable | Description |
|----------|-------------|
| `ROOT_CA_NAME` | Folder name and base filename for the Root CA |
| `ROOT_CA_COUNTRY` | Two-letter country code (e.g. `US`) |
| `ROOT_CA_STATE` | State or province |
| `ROOT_CA_LOCALITY` | City or locality |
| `ROOT_CA_ORGANIZATION` | Organization name |
| `ROOT_CA_ORGANIZATIONAL_UNIT` | Department or unit |
| `ROOT_CA_COMMON_NAME` | Common Name (CN) for the Root CA |
| `ROOT_CA_VALIDITY_DAYS` | Root CA validity period in days |
| `ROOT_CA_PASSPHRASE` | Optional passphrase to encrypt the Root CA private key |

### SSL Certificate Settings

| Variable | Description |
|----------|-------------|
| `CERT_NAME` | Base filename for the server certificate, key, and CSR |
| `CERT_COUNTRY` | Two-letter country code |
| `CERT_STATE` | State or province |
| `CERT_LOCALITY` | City or locality |
| `CERT_ORGANIZATION` | Organization name |
| `CERT_ORGANIZATIONAL_UNIT` | Department or unit |
| `CERT_COMMON_NAME` | Common Name (CN), typically the primary hostname |
| `CERT_DNS_NAMES` | SAN entries, separated by commas (IPs are auto-detected) |
| `CERT_IP_ADDRESSES` | Optional extra IP SAN entries, separated by commas |
| `CERT_VALIDITY_DAYS` | Certificate validity period in days |

### Advanced Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `KEY_TYPE` | `ec` | Key algorithm: `ec` or `rsa` |
| `KEY_SIZE` | `256` | EC `256`, `384`, or `521`, or RSA `2048`, `3072`, or `4096`. See field notes |
| `FORCE_REGENERATE` | `no` | Set to `yes` to overwrite an existing `CERT_NAME` |
| `EXPORT_P12` | `yes` | Export a PKCS#12 (`.p12`) bundle |
| `P12_PASSWORD` | `changeit` | Password for the exported `.p12` file |

### Web UI Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBUI_BIND` | `127.0.0.1` | Host address published for the web UI. Must be `127.0.0.1` |
| `WEBUI_PORT` | `8443` | Host port published for the web UI |

### Sample `.env`

```dotenv
ROOT_CA_NAME=my-root-ca
ROOT_CA_COUNTRY=US
ROOT_CA_STATE=California
ROOT_CA_LOCALITY=San Francisco
ROOT_CA_ORGANIZATION=My Company
ROOT_CA_ORGANIZATIONAL_UNIT=IT Department
ROOT_CA_COMMON_NAME=My Local Root CA
ROOT_CA_VALIDITY_DAYS=3650
ROOT_CA_PASSPHRASE=

CERT_NAME=my-local-cert
CERT_COUNTRY=US
CERT_STATE=California
CERT_LOCALITY=San Francisco
CERT_ORGANIZATION=My Company
CERT_ORGANIZATIONAL_UNIT=Web Services
CERT_COMMON_NAME=localhost
CERT_DNS_NAMES=localhost,*.localhost,127.0.0.1
CERT_IP_ADDRESSES=
CERT_VALIDITY_DAYS=365

KEY_TYPE=ec
KEY_SIZE=256
FORCE_REGENERATE=no
EXPORT_P12=yes
P12_PASSWORD=changeit

WEBUI_BIND=127.0.0.1
WEBUI_PORT=8443
```

### Field Notes

- **ROOT_CA_NAME** — Controls the output directory (`./certs/my-root-ca/`) and Root CA filenames.
- **CERT_NAME** — Controls server certificate filenames (`my-local-cert.key`, `.csr`, `.crt`, etc.).
- **CERT_DNS_NAMES** — Hostnames and IP addresses, comma-separated. IPs like `127.0.0.1` are automatically added as IP SAN entries.
- **CERT_COMMON_NAME** — Must appear in `CERT_DNS_NAMES`.
- **Values with spaces** — Work without quotes (e.g. `IT Department`). Quoting is optional.
- **KEY_SIZE** — For `KEY_TYPE=ec`, `256` is P-256 (`prime256v1`), `384` is P-384 (`secp384r1`), and `521` is P-521 (`secp521r1`). For `KEY_TYPE=rsa`, use `2048`, `3072`, or `4096`. The web UI dropdown follows the key type, and saving Configuration writes `KEY_SIZE` so `make certs` uses the same size. An explicit size applies to the certificate and to a Root CA created in that run. Existing Root CA keys are reused and are not resized.
- **FORCE_REGENERATE** — When `no`, re-running with the same `CERT_NAME` skips generation and prints a message.
- **WEBUI_BIND / WEBUI_PORT** — Host address and port used by `make webui`. `WEBUI_BIND` must stay `127.0.0.1`.

---

## 5. Generating Your First Certificate

Once `.env` is configured:

```bash
make certs
```

Or:

```bash
./scripts/generate.sh
```

Or:

```bash
docker compose run --rm ssl-gen
```

The tool creates a new Root CA and signs your first certificate. On success it prints validity dates and platform-specific trust commands.

Output in `./certs/<ROOT_CA_NAME>/`:

```
certs/my-root-ca/
├── my-root-ca.key
├── my-root-ca.crt
├── my-local-cert.key
├── my-local-cert.csr
├── my-local-cert.crt
├── my-local-cert.pem
├── my-local-cert-fullchain.pem
├── my-local-cert.p12
└── my-local-cert-extensions.cnf
```

---

## 6. Generating Additional Certificates

When you need another certificate under an existing Root CA:

1. Keep `ROOT_CA_NAME` unchanged.
2. Update `CERT_NAME` and certificate-specific fields.
3. Run `make certs` again.

If a certificate with the same `CERT_NAME` already exists, generation is skipped unless `FORCE_REGENERATE=yes`.

Example — add a certificate for an API service:

```dotenv
ROOT_CA_NAME=my-root-ca
CERT_NAME=api-local-cert
CERT_COMMON_NAME=api.localhost
CERT_DNS_NAMES=api.localhost,*.api.localhost
FORCE_REGENERATE=no
```

---

## 7. Web UI

The web UI is a separate container. It edits `.env`, runs certificate generation, and lists stores under `./certs/`. Start it with:

```bash
make webui
```

Or:

```bash
docker compose up --build -d webui
```

Open `https://127.0.0.1:8443` by default. The host address and port come from `WEBUI_BIND` and `WEBUI_PORT` in `.env` (see [Web UI Settings](#web-ui-settings)). `WEBUI_BIND` must be `127.0.0.1`. After changing either value, recreate the container so Docker republishes the port:

```bash
docker compose up --build -d webui
```

Stop the UI with:

```bash
make webui-down
```

On startup the UI creates its own self-signed HTTPS certificate in `ui-ssl/`. Accept that certificate in the browser to open the UI. To trust certificates you generate, install the Root CA from `./certs/<ROOT_CA_NAME>/`.

Generated files still land in `./certs/<ROOT_CA_NAME>/` because the web UI bind-mounts the project directory at `/project`, the same way the `ssl-gen` service does. The dashboard lists Root CAs and certificates that are expired or within 30 days of `notAfter`.

Screen recordings and screenshots — TAR export and import, hierarchy, presets, Trust Guide, and search — are in [docs/media](docs/media/).

### Downloads

On the Certificates page, or from a node on Hierarchy, download the files that exist for a Root CA or a signed certificate:

- `.crt` — the public certificate
- **Full chain** — `<name>-fullchain.pem`, when the generator wrote one
- `.p12` — the PKCS#12 bundle, when `EXPORT_P12` produced one
- `.key` — the private key, after you confirm the prompt

The `.key` button is marked secret. The prompt tells you that anyone with the file can impersonate the certificate. The detail dialog also copies the path under `./certs/<ROOT_CA_NAME>/` and the public PEM.

### Export and import

Dashboard and Certificates offer **Import**, **Export selected**, and **Export All**. Check a Root CA, a certificate, or both, then **Export selected**. If nothing is checked, **Export selected** stays disabled. A checked Root CA can be the full store or only the public Root CA. A checked certificate exports that certificate (and the public Root CA a relying party needs) without the rest of the project. Each Root CA card still has **Export TAR**, with the same full-store or Root-CA-only choice. On the Certificates page, each signed certificate still has **Export TAR**.

| Scope | Default contents | File name |
|-------|------------------|-----------|
| Full chain / store | Public files in `./certs/<ROOT_CA_NAME>/` | `ssl-gen-<ROOT_CA_NAME>.tar.gz` |
| Root CA only | That store's public Root CA `.crt` | `ssl-gen-<ROOT_CA_NAME>-root.tar.gz` |
| This certificate | That certificate's public files, plus the public Root CA `.crt` from the same store | `ssl-gen-<ROOT_CA_NAME>-<CERT_NAME>.tar.gz` |
| Selected | The stores and certificates you checked. One item uses that item's file name | `ssl-gen-selected.tar.gz` when more than one item is selected |
| All stores | Public files from every store under `./certs` | `ssl-gen-certs.tar.gz` |

Public files are the `.crt`, `.csr`, `.pem`, full chain, and extensions file when they are on disk. **Root CA only** is just the public Root `.crt`. Check **Include private keys** and confirm to add `.key` and `.p12` for the certificates in that scope, including Root CA keys on a store or all-stores export. On a Root-CA-only export, that option adds the Root CA `.key` and not the other keys in the store. A certificate export adds the key files for the selected certificate and still includes the store's public Root CA `.crt`. Exports stay public-only unless you opt in. Read [Private keys in a TAR](#private-keys-in-a-tar) before you move an archive that contains keys.

Exports include `manifest.json` at the top of the archive. It records `exportedAt`, the scope (`store`, `root`, `certificate`, `selection`, or `all`), the store and certificate name when those apply, and one entry per name with its file paths and `notAfter`. A selection also lists each chosen item. Passphrases and PKCS#12 passwords stay out of it. When an imported archive contains `manifest.json`, import uses it for names and expiry and leaves that file out of `./certs`.

**Encrypt with OpenSSL AES-256** is optional. The download is then named `.tar.gz.enc`, and import asks for that passphrase. The passphrase is used for that download only.

**Import** takes a `.tar`, `.tar.gz`, or encrypted archive from this UI. Pick the file you want. Preview it first. Extraction stays inside `./certs/<store>/`. When a file is already there, choose:

- **Skip** — leave the existing file. This is the default.
- **Rename** — write the incoming file beside it, with an `-imported` suffix.
- **Overwrite** — replace the existing file. Confirm **Replace existing files in ./certs** before the import runs.

### Hierarchy

Open **Hierarchy** and select a Root CA. The page draws that CA above the certificates stored in `./certs/<ROOT_CA_NAME>/`. A solid line means the certificate issuer matches the selected Root CA. A dashed line means the issuer is different. Click a node for the same details and downloads as the Certificates page.

### Generate presets and Trust Guide

**Generate** can start from a preset. Presets fill the certificate name and SAN list and leave the Root CA fields unchanged. Artifacts are still written to `./certs/<ROOT_CA_NAME>/`.

- **localhost** — `localhost`, `*.localhost`, `127.0.0.1`, and `::1`
- **\*.local / LAN IP** — `host.local` and `*.local`, plus an optional LAN address as an IP SAN
- **Wildcard** — `*.<apex>` and the apex name. The field starts at `dev.local`.

Root CA, certificate, and advanced settings stay in collapsible sections. Collapsed sections are still included when you generate.

**Trust Guide** copies the macOS, Linux, and Windows install commands for the Root CA you select. **Download Root .crt** saves only the public certificate at `./certs/<ROOT_CA_NAME>/<ROOT_CA_NAME>.crt`.

The Certificates page filters the list by name, subject, or SAN.

### Certificate info, conversion, and passwords

From a certificate on the Certificates page, the dashboard, or the detail dialog:

- **Info** shows OpenSSL-style fields for the `.crt` and, when `<name>-fullchain.pem` is present, each certificate in that file: subject, issuer, SANs, validity, serial, SHA-1 and SHA-256 fingerprints, key type and size, and basic constraints, key usage, and extended key usage. The chain is marked incomplete when the last certificate is not self-signed, and the order is marked wrong when an issuer does not match the next subject or the file does not start with this certificate.
- **Convert** turns one X.509 certificate between PEM and DER. An unencrypted PEM or DER private key can be converted as well. Download the result, save it in the same store (`name.der` / `name.pem`, or `name-key.der` / `name-key.pem` for a key), or both. An existing file is kept until you confirm overwrite. PKCS#12 and encrypted keys are refused here; change those passwords instead.
- **Change password** rewrites a private key or `.p12` that is already in the store. The current password is required when one is set. An unencrypted key, or a file with an empty password, can take a new password with the current field left blank. Type the new password twice. An empty password cannot replace an empty password.

These actions stay inside `./certs`. Password changes and private-key conversion rewrite secret material. The UI remains localhost-only.

---

## 8. Using the Certificates

### nginx

```nginx
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     /path/to/ssl-gen/certs/my-root-ca/my-local-cert-fullchain.pem;
    ssl_certificate_key /path/to/ssl-gen/certs/my-root-ca/my-local-cert.key;
}
```

### Traefik (file provider)

```yaml
tls:
  certificates:
    - certFile: /path/to/ssl-gen/certs/my-root-ca/my-local-cert.crt
      keyFile: /path/to/ssl-gen/certs/my-root-ca/my-local-cert.key
```

### Node.js (HTTPS)

```javascript
import { readFileSync } from "fs";
import { createServer } from "https";

createServer(
  {
    key: readFileSync("./certs/my-root-ca/my-local-cert.key"),
    cert: readFileSync("./certs/my-root-ca/my-local-cert-fullchain.pem"),
  },
  (req, res) => res.end("ok"),
).listen(443);
```

### Python (HTTPS)

```python
import ssl
from http.server import HTTPServer, SimpleHTTPRequestHandler

httpd = HTTPServer(("localhost", 443), SimpleHTTPRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="./certs/my-root-ca/my-local-cert-fullchain.pem",
    keyfile="./certs/my-root-ca/my-local-cert.key",
)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

Use the `-fullchain.pem` file when a service expects the server certificate bundled with the Root CA.

---

## 9. Trusting the Root CA Locally

Browsers and tools will not trust self-signed certificates until you install the Root CA. The generator prints exact commands after each run; these are the defaults:

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./certs/my-root-ca/my-root-ca.crt
```

**Linux (Debian/Ubuntu):**

```bash
sudo cp ./certs/my-root-ca/my-root-ca.crt /usr/local/share/ca-certificates/my-root-ca.crt
sudo update-ca-certificates
```

**Windows:** Import `my-root-ca.crt` into *Trusted Root Certification Authorities* via `certmgr.msc`.

The web UI [Trust Guide](#generate-presets-and-trust-guide) copies these commands for the Root CA you select and downloads the public `.crt` only.

---

## 10. Security Notes

Private keys (`.key`) and `.p12` files are created with `chmod 600`.

### Private keys in a TAR

A TAR that includes private keys is a secrets backup. Treat it like a password-vault dump: anyone who has the file can impersonate those certificates. Prefer the default public-only export unless you need the keys to restore a machine. Do not email the archive, paste it into chat, commit it, or leave it in a shared folder. An encrypted archive is still that backup; keep its passphrase apart from the file. `manifest.json` lists certificate names, file names, `notAfter`, and `exportedAt`. Import refuses paths that leave `./certs`.

- Root CA and server keys are stored in plain files on disk. Restrict filesystem access to `./certs/<ROOT_CA_NAME>/`.
- Set `ROOT_CA_PASSPHRASE` to encrypt the Root CA private key. You will need it when signing new certificates.
- Self-signed certificates are intended for **local development and testing**, not production use.
- Do not commit `.env`, generated keys, or certificate archives to version control. The web UI listens on localhost (`WEBUI_BIND` must stay `127.0.0.1`) and has no login.
- PEM/DER conversion and password changes stay inside `./certs` and refuse paths or symlinks that leave it. Passphrases go to OpenSSL through the environment, not command-line arguments. API responses and toasts report success or failure only. Converting a private key, or changing a `.key` or `.p12` password, rewrites secret material on disk. PKCS#12 bundles and encrypted keys are outside the converter.

---

## 11. Testing

Run the automated test suite locally:

```bash
make test
```

Tests build the Docker image, generate certificates using an isolated `.env.test`, verify the chain with `openssl verify`, confirm IP SAN entries, and check skip-on-existing behavior.

CI runs the same tests on push and pull requests via GitHub Actions (`.github/workflows/test.yml`).

---

## 12. Troubleshooting

| Issue | Solution |
|-------|----------|
| `.env file not found` | Run `make setup` or `cp .env.example .env` |
| `required variable 'X' is not set` | Add the missing variable to `.env` |
| `CERT_COMMON_NAME must appear in CERT_DNS_NAMES` | Add the CN to `CERT_DNS_NAMES` |
| `At least one SAN entry is required` | Provide DNS or IP entries in `CERT_DNS_NAMES` or `CERT_IP_ADDRESSES` |
| `Certificate already exists` | Change `CERT_NAME` or set `FORCE_REGENERATE=yes` |
| `Could not unlock existing Root CA key` | Set the correct `ROOT_CA_PASSPHRASE` for an encrypted CA |
| Permission errors on output folder | Ensure the project directory is writable by Docker |
| Browser still shows untrusted cert | Install the Root CA certificate in your system trust store |