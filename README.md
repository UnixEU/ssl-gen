# SSL Certificate Generator

A Docker-based tool for creating self-signed SSL certificates with a reusable local Root CA. Configure everything through a single `.env` file and run one command to generate certificates.

## Goal

Provide one place to create and manage self-signed SSL certificates for local development. The project generates a private Root CA, uses it to sign server certificates, and stores all artifacts in a dedicated folder. When you need more certificates later, it reuses the existing Root CA instead of creating a new one.

## Table of Contents

1. [Requirements](#1-requirements)
2. [Project Structure](#2-project-structure)
3. [Setup](#3-setup)
4. [Configuration](#4-configuration)
5. [Generating Your First Certificate](#5-generating-your-first-certificate)
6. [Generating Additional Certificates](#6-generating-additional-certificates)
7. [Using the Certificates](#7-using-the-certificates)
8. [Trusting the Root CA Locally](#8-trusting-the-root-ca-locally)
9. [Security Notes](#9-security-notes)
10. [Testing](#10-testing)
11. [Troubleshooting](#11-troubleshooting)

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
├── Dockerfile             # Alpine image with OpenSSL pre-installed
├── docker-compose.yaml    # Runs the generator container
├── Makefile               # Convenience commands (setup, certs, test)
├── .env.example           # Configuration template (committed to git)
├── .env                   # Your local configuration (not committed)
├── README.md
└── scripts/
    ├── generate-certs.sh  # Certificate generation logic
    ├── generate.sh        # Wrapper for docker compose run --rm
    └── test.sh            # Automated verification tests
```

After generation, a new folder appears in the project root named after `ROOT_CA_NAME` (for example, `my-root-ca/`). Certificate files are written there, not in a separate `workspace` folder.

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
| `KEY_TYPE` | `ec` | Key algorithm: `ec` (P-256) or `rsa` |
| `FORCE_REGENERATE` | `no` | Set to `yes` to overwrite an existing `CERT_NAME` |
| `EXPORT_P12` | `yes` | Export a PKCS#12 (`.p12`) bundle |
| `P12_PASSWORD` | `changeit` | Password for the exported `.p12` file |

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
FORCE_REGENERATE=no
EXPORT_P12=yes
P12_PASSWORD=changeit
```

### Field Notes

- **ROOT_CA_NAME** — Controls the output directory (`./my-root-ca/`) and Root CA filenames.
- **CERT_NAME** — Controls server certificate filenames (`my-local-cert.key`, `.csr`, `.crt`, etc.).
- **CERT_DNS_NAMES** — Hostnames and IP addresses, comma-separated. IPs like `127.0.0.1` are automatically added as IP SAN entries.
- **CERT_COMMON_NAME** — Must appear in `CERT_DNS_NAMES`.
- **Values with spaces** — Work without quotes (e.g. `IT Department`). Quoting is optional.
- **FORCE_REGENERATE** — When `no`, re-running with the same `CERT_NAME` skips generation and prints a message.

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

Output in `./<ROOT_CA_NAME>/`:

```
my-root-ca/
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

## 7. Using the Certificates

### nginx

```nginx
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     /path/to/ssl-gen/my-root-ca/my-local-cert-fullchain.pem;
    ssl_certificate_key /path/to/ssl-gen/my-root-ca/my-local-cert.key;
}
```

### Traefik (file provider)

```yaml
tls:
  certificates:
    - certFile: /path/to/ssl-gen/my-root-ca/my-local-cert.crt
      keyFile: /path/to/ssl-gen/my-root-ca/my-local-cert.key
```

### Node.js (HTTPS)

```javascript
import { readFileSync } from "fs";
import { createServer } from "https";

createServer(
  {
    key: readFileSync("./my-root-ca/my-local-cert.key"),
    cert: readFileSync("./my-root-ca/my-local-cert-fullchain.pem"),
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
    certfile="./my-root-ca/my-local-cert-fullchain.pem",
    keyfile="./my-root-ca/my-local-cert.key",
)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

Use the `-fullchain.pem` file when a service expects the server certificate bundled with the Root CA.

### Web UI

`make webui` serves a localhost-only interface (default `https://127.0.0.1:8443`). Open a Root CA or certificate to download its public `.crt`, full chain, and `.p12` when those files exist. Private `.key` downloads are opt-in: the button is marked secret and asks for confirmation before the file is saved. The dashboard lists Root CAs and certificates that are expired or within 30 days of `notAfter`.

---

## 8. Trusting the Root CA Locally

Browsers and tools will not trust self-signed certificates until you install the Root CA. The generator prints exact commands after each run; these are the defaults:

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./my-root-ca/my-root-ca.crt
```

**Linux (Debian/Ubuntu):**

```bash
sudo cp ./my-root-ca/my-root-ca.crt /usr/local/share/ca-certificates/my-root-ca.crt
sudo update-ca-certificates
```

**Windows:** Import `my-root-ca.crt` into *Trusted Root Certification Authorities* via `certmgr.msc`.

---

## 9. Security Notes

- Private keys (`.key`) and `.p12` files are created with `chmod 600`.
- Root CA and server keys are stored in plain files on disk — restrict filesystem access to the output folder.
- Set `ROOT_CA_PASSPHRASE` to encrypt the Root CA private key; you will need it when signing new certificates.
- Self-signed certificates are intended for **local development and testing**, not production use.
- Do not commit `.env` or generated keys and certificates to version control.

---

## 10. Testing

Run the automated test suite locally:

```bash
make test
```

Tests build the Docker image, generate certificates using an isolated `.env.test`, verify the chain with `openssl verify`, confirm IP SAN entries, and check skip-on-existing behavior.

CI runs the same tests on push and pull requests via GitHub Actions (`.github/workflows/test.yml`).

---

## 11. Troubleshooting

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