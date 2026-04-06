# pageguard-mcp

MCP (Model Context Protocol) server that exposes PageGuard privacy compliance scanning as tools for AI coding assistants. Works with Claude Code, Cursor, Windsurf, ChatGPT, and any MCP-compatible environment.

## What it does

- **Local scan** — Detects tracking technologies, cookies, and third-party data collection from your project's `package.json`, config files, and `.env` files. No API key needed, no network requests.
- **URL scan** — Scans a live website for privacy compliance issues including risk scoring and compliance gap analysis.
- **Document generation** — Generates AI-written legal documents (privacy policy, terms of service, cookie policy, etc.) tailored to your detected technologies.

## Installation

### Claude Code

Add to your project's `.mcp.json` or global MCP config:

```json
{
  "mcpServers": {
    "pageguard": {
      "command": "npx",
      "args": ["pageguard-mcp"]
    }
  }
}
```

### Cursor

Add to Cursor Settings > MCP Servers:

```json
{
  "mcpServers": {
    "pageguard": {
      "command": "npx",
      "args": ["pageguard-mcp"]
    }
  }
}
```

### Windsurf

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "pageguard": {
      "command": "npx",
      "args": ["pageguard-mcp"]
    }
  }
}
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PAGEGUARD_API_KEY` | No (local scan) / Yes (URL scan, doc gen) | API key from [getpageguard.com](https://getpageguard.com/#pricing) |
| `PAGEGUARD_API_URL` | No | Override API base URL (default: `https://www.getpageguard.com`) |

## Tools

### `pageguard_scan_local`

Scan a local project directory for privacy-relevant technologies.

**Input:**
- `path` (optional) — Absolute path to project directory. Defaults to current working directory.

**Output:** ComplianceReport JSON with detected technologies, data types, cookies, and third-party processors.

### `pageguard_scan_url`

Scan a live website URL for privacy compliance issues.

**Input:**
- `url` (required) — Full URL to scan, e.g. `https://example.com`

**Output:** ComplianceReport JSON with risk score, detected technologies, and compliance gaps.

### `pageguard_generate_docs`

Generate AI-written legal compliance documents for a scanned site.

**Input:**
- `scanId` (required) — Scan ID from a prior `pageguard_scan_url` result
- `documentType` (optional) — One of: `single` ($29), `bundle` ($49), `addon_security` ($19), `addon_a11y` ($19), `addon_schema` ($19), `app_bundle` ($39), `submission_guide` ($19). Defaults to `bundle`.

**Output:** Generated document content.

## Pricing

Scanning is free. Document generation requires credits:

- **Privacy Docs** ($29) — Privacy Policy + Terms of Service + Cookie Policy
- **Fix Everything** ($49) — All docs + Security Guide + Accessibility Report + Schema Markup
- **App Bundle** ($39) — Privacy docs + App Store Submission Guide
- **Add-ons** ($19 each) — Security Guide, Accessibility Report, Schema Markup, Submission Guide
- **Bulk packs** — 5 for $79, 15 for $149, 50 for $349

Get an API key at [getpageguard.com/#pricing](https://getpageguard.com/#pricing).

## License

MIT
