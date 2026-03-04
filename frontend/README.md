# OpenGuard v5 — Security Operations Console

A React + TypeScript + Vite single-page application that provides the operator interface for the OpenGuard v5 platform.

## Features

- **Dashboard** — live stat cards, tier breakdown bar charts, risk score distribution, and recent events/incidents tables with auto-refresh every 30 seconds
- **Events** — full events table with type/tier/source filtering, pagination (50 per page), and 30-second auto-refresh
- **Incidents** — incidents table with status/tier filtering, pagination, action buttons (Approve / Deny / Override), 30-second auto-refresh, and drill-down detail view
- **Audit Log** — immutable SHA-256 chained audit ledger with event ID filtering
- **Sensors** — sensor adapter cards with configuration tables
- **Authentication** — JWT-based login with protected routes and logout
- **Toast notifications** — success/error/info/warning toasts with auto-dismiss after 5 seconds
- **404 page** — catch-all not-found route

## Development Setup

```bash
# Install dependencies
npm install

# Start the dev server (proxies /api and /health to localhost:8080)
npm run dev
```

## Build

```bash
npm run build
```

The build output is placed in `../services/console-api/ui` so the Go binary can embed it.

## Tests

```bash
# Run all tests once
npm test

# Watch mode
npm run test:watch

# UI mode
npm run test:ui
```

## Lint

```bash
npm run lint
```

## Colour Palette

| Token | Hex |
|-------|-----|
| Background | `#0f172a` |
| Surface | `#1e293b` |
| Border | `#334155` |
| Muted | `#64748b` |
| Subtle | `#94a3b8` |
| Primary | `#60a5fa` |
| Foreground | `#f1f5f9` |

