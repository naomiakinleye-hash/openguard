# 🛡️ OpenGuard v5 — Build Guide

Step-by-step instructions to install prerequisites, clone, build, and run OpenGuard v5 on **Windows**, **macOS**, and **Ubuntu**.

---

## 📋 Prerequisites Overview

| Tool | Version | Windows | macOS | Ubuntu |
|---|---|---|---|---|
| **Git** | Latest | ✅ | ✅ | ✅ |
| **Go** | 1.24+ | ✅ | ✅ | ✅ |
| **Node.js** | 18+ | ✅ | ✅ | ✅ |
| **NATS Server** | 2.10+ | ✅ | ✅ | ✅ |
| **Docker** (optional) | Latest | ✅ | ✅ | ✅ |
| **Make** (optional) | Latest | via Chocolatey | built-in | built-in |

---

## 🖥️ Frontend (Console UI)

The console UI is a React + TypeScript single-page application built with [Vite](https://vitejs.dev/).  
The compiled static assets are embedded directly into the Go binary at build time via `go:embed`.

### Build the Frontend

```bash
cd frontend
npm install
npm run build
```

This outputs the compiled assets to `services/console-api/ui/`, where they are embedded by the Go build.

> ⚠️ **You must build the frontend before building the Go backend** (or commit the built `services/console-api/ui/` directory).

### Frontend Development Server

To iterate on the UI with hot-reload while running the backend on `:8080`:

```bash
cd frontend
npm install
npm run dev
```

The dev server starts on `http://localhost:5173` and proxies `/api` and `/health` requests to `http://localhost:8080`.

---

## 🪟 Windows

### Step 1 — Install Git
```powershell
# Option A: winget
winget install Git.Git

# Option B: Download from https://git-scm.com/download/win
```

### Step 2 — Install Go 1.24+
```powershell
# Option A: winget
winget install GoLang.Go

# Option B: Download installer from https://go.dev/dl/
```
Verify:
```powershell
go version
# Expected: go version go1.24.x windows/amd64
```

### Step 3 — Install NATS Server
```powershell
# Option A: winget
winget install nats-io.nats-server

# Option B: Download binary from
# https://github.com/nats-io/nats-server/releases
# Extract nats-server.exe to a folder in your PATH
```

### Step 4 — Clone the Repository
```powershell
git clone https://github.com/DiniMuhd7/openguard.git
cd openguard
```

### Step 5 — Download Dependencies
```powershell
go mod download
go mod tidy
```

### Step 6 — Build
```powershell
go build ./...

# Or build the binary explicitly:
go build -o openguard.exe .
```

### Step 7 — Create Required Directories
```powershell
mkdir data
```

### Step 8 — Start NATS Server
Open a **new terminal** and run:
```powershell
nats-server
```

### Step 9 — Set Environment Variables & Run OpenGuard
Back in your original terminal:
```powershell
$env:NATS_URL            = "nats://localhost:4222"
$env:POLICY_DIR          = "./policies"
$env:RULES_DIR           = "./rules"
$env:SCHEMA_PATH         = "./schemas/unified-event.schema.json"
$env:LISTEN_ADDR         = ":8080"
$env:JWT_SECRET          = "dev-secret-change-in-prod"
$env:AUDIT_STORAGE_PATH  = "./data/audit.ndjson"

go run main.go
```

### Step 10 — Run Tests
```powershell
go test ./...

# With race detector:
go test -race ./...
```

### Step 11 — Verify the API is Running
```powershell
curl http://localhost:8080/health
```

---

## 🍎 macOS

### Step 1 — Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2 — Install Go, Git & NATS
```bash
brew install go git nats-server
```
Verify:
```bash
go version
# Expected: go version go1.24.x darwin/arm64 (or amd64)
```

### Step 3 — Clone the Repository
```bash
git clone https://github.com/DiniMuhd7/openguard.git
cd openguard
```

### Step 4 — Download Dependencies
```bash
go mod download
go mod tidy
```

### Step 5 — Build
```bash
go build ./...

# Or build the binary explicitly:
go build -o openguard .
```

### Step 6 — Create Required Directories
```bash
mkdir -p data
```

### Step 7 — Start NATS Server
Open a **new terminal tab**:
```bash
nats-server
```

### Step 8 — Run OpenGuard
Back in your original terminal:
```bash
export NATS_URL="nats://localhost:4222"
export POLICY_DIR="./policies"
export RULES_DIR="./rules"
export SCHEMA_PATH="./schemas/unified-event.schema.json"
export LISTEN_ADDR=":8080"
export JWT_SECRET="dev-secret-change-in-prod"
export AUDIT_STORAGE_PATH="./data/audit.ndjson"

go run main.go
```

### Step 9 — Run Tests
```bash
go test ./...

# With race detector and coverage:
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Step 10 — Verify the API is Running
```bash
curl http://localhost:8080/health
```

---

## 🐧 Ubuntu (20.04 / 22.04 / 24.04)

### Step 1 — Update System & Install Git
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential unzip
```

### Step 2 — Install Go 1.24+
```bash
# Download the latest Go tarball
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz

# Remove any previous Go installation and extract
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz

# Add Go to your PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```
Verify:
```bash
go version
# Expected: go version go1.24.x linux/amd64
```

### Step 3 — Install NATS Server
```bash
# Download latest NATS server binary
wget https://github.com/nats-io/nats-server/releases/latest/download/nats-server-v2.10.24-linux-amd64.zip
unzip nats-server-v2.10.24-linux-amd64.zip
sudo mv nats-server /usr/local/bin/
```
Verify:
```bash
nats-server --version
```

### Step 4 — Clone the Repository
```bash
git clone https://github.com/DiniMuhd7/openguard.git
cd openguard
```

### Step 5 — Download Dependencies
```bash
go mod download
go mod tidy
```

### Step 6 — Build
```bash
go build ./...

# Or build the binary explicitly:
go build -o openguard .
```

### Step 7 — Create Required Directories
```bash
mkdir -p data
```

### Step 8 — Start NATS Server
Open a **new terminal** or run in the background:
```bash
# In a new terminal:
nats-server

# Or in the background:
nats-server &
```

### Step 9 — Run OpenGuard
```bash
export NATS_URL="nats://localhost:4222"
export POLICY_DIR="./policies"
export RULES_DIR="./rules"
export SCHEMA_PATH="./schemas/unified-event.schema.json"
export LISTEN_ADDR=":8080"
export JWT_SECRET="dev-secret-change-in-prod"
export AUDIT_STORAGE_PATH="./data/audit.ndjson"

go run main.go
```

### Step 10 — Run Tests
```bash
go test ./...

# With race detector and coverage:
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Step 11 — Verify the API is Running
```bash
curl http://localhost:8080/health
```

---

## 🐳 All Platforms — Docker Compose (Easiest)

Run the **full stack** with one command on any platform (requires Docker Desktop or Docker Engine):

```bash
# Clone and enter the repo
git clone https://github.com/DiniMuhd7/openguard.git
cd openguard

# Start everything: OpenGuard + NATS + Postgres + Prometheus + Grafana
docker compose up --build

# Stop everything
docker compose down
```

| Service | URL |
|---|---|
| OpenGuard API | http://localhost:8080/health |
| Prometheus Metrics | http://localhost:9091 |
| Grafana Dashboard | http://localhost:3000 (admin/admin) |
| NATS Monitoring | http://localhost:8222 |

---

## ✅ Expected Output on Successful Start

```json
{"level":"info","msg":"OpenGuard v5 starting","version":"5.0.0","module":"github.com/DiniMuhd7/openguard"}
{"level":"info","msg":"OpenGuard v5 running","listen":":8080","nats":"nats://localhost:4222"}
```

---

## 🌍 Environment Variable Reference

| Variable | Default | Description |
|---|---|---|
| `NATS_URL` | `nats://localhost:4222` | NATS server connection URL |
| `POLICY_DIR` | `./policies` | Path to policy YAML files |
| `RULES_DIR` | `./rules` | Path to detection rule YAML files |
| `SCHEMA_PATH` | `./schemas/unified-event.schema.json` | Path to unified event JSON schema |
| `LISTEN_ADDR` | `:8080` | Console API listen address |
| `JWT_SECRET` | `change-me-in-production` | JWT signing secret (**change in production**) |
| `AUDIT_STORAGE_PATH` | `./data/audit.ndjson` | Audit ledger NDJSON file path |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `METRICS_PORT` | `9090` | Prometheus metrics port |

---

## 🔑 Important Notes

> ⚠️ **JWT Secret:** Always set a strong `JWT_SECRET` in production. The default `change-me-in-production` is for local development only.

> 📁 **Data Directory:** The audit ledger writes to `./data/audit.ndjson`. Make sure the `data/` directory exists before running.

> 🔒 **Security:** Never commit real API keys or secrets. Use environment variables or a secrets manager in production.

> 🐳 **Docker Compose:** Requires Docker Desktop (Windows/macOS) or Docker Engine + Docker Compose plugin (Ubuntu).

---

## 🆘 Troubleshooting

### `go: command not found`
Go is not in your PATH. Re-run the PATH setup step and restart your terminal.

### `nats-server: command not found`
NATS server binary is not in your PATH. Move it to `/usr/local/bin` (Linux/macOS) or a directory in `%PATH%` (Windows).

### `failed to initialize ingest service: nats: no servers available`
NATS server is not running. Start it with `nats-server` in a separate terminal.

### `failed to initialize policy engine`
The `POLICY_DIR` path does not exist or contains invalid YAML. Ensure `./policies/` exists and contains valid `constitution.yaml` and `openguard-v5.yaml`.

### Port `:8080` already in use
Change the listen address: `export LISTEN_ADDR=":9080"` (or `$env:LISTEN_ADDR=":9080"` on Windows).

---

*OpenGuard v5 — DSHub Ltd. All rights reserved*.
