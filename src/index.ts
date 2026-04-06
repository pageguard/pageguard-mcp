#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = "1.0.0";
const API_BASE =
  process.env.PAGEGUARD_API_URL || "https://www.getpageguard.com";

// ---------------------------------------------------------------------------
// Signatures — loaded once at startup
// ---------------------------------------------------------------------------

interface Signature {
  name: string;
  patterns: string[];
  dependencies: string[];
  category: string;
  categoryLabel: string;
  summary: string;
  dataTypeCount: number;
  cookieNames: string[];
  thirdPartyName: string;
  thirdPartyCountry: string;
}

const signaturesPath = resolve(__dirname, "..", "signatures.json");
const signatures: Signature[] = JSON.parse(
  readFileSync(signaturesPath, "utf-8")
);

// ---------------------------------------------------------------------------
// ComplianceReport type
// ---------------------------------------------------------------------------

interface ComplianceReport {
  version: "1.0";
  scanId?: string;
  source: string;
  scannedAt: string;
  scanMode: "local" | "url";
  status: "pass" | "warn" | "fail";
  exitCode: 0 | 1 | 2;
  riskScore?: { score: number; level: string };
  technologies: Array<{
    name: string;
    category: string;
    categoryLabel: string;
    dataTypeCount: number;
    cookieNames: string[];
    thirdPartyName: string;
    thirdPartyCountry: string;
  }>;
  complianceGaps?: Array<{
    severity: string;
    title: string;
    detail?: string;
  }>;
  summary: {
    totalTechnologies: number;
    totalDataTypes: number;
    totalCookies: number;
    thirdParties: string[];
  };
  reportUrl?: string;
}

// ---------------------------------------------------------------------------
// Local scanner — reimplements CLI's scanDependencies logic in TypeScript
// ---------------------------------------------------------------------------

function scanLocal(projectPath: string): ComplianceReport {
  const files: Record<string, string> = {};

  // Read package.json
  const pkgPath = resolve(projectPath, "package.json");
  if (existsSync(pkgPath)) {
    try {
      files["package.json"] = readFileSync(pkgPath, "utf-8");
    } catch {
      // ignore read errors
    }
  }

  // Read common config files
  const configFiles = [
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "nuxt.config.ts",
    "nuxt.config.js",
    "gatsby-config.js",
    "astro.config.mjs",
    "vite.config.ts",
    "vite.config.js",
    "app.json",
    "app.config.js",
    "angular.json",
    ".env",
    ".env.local",
  ];

  for (const f of configFiles) {
    const fPath = resolve(projectPath, f);
    if (existsSync(fPath)) {
      try {
        files[f] = readFileSync(fPath, "utf-8");
      } catch {
        // ignore read errors
      }
    }
  }

  // Parse dependencies from package.json
  const deps: Record<string, string> = files["package.json"]
    ? (() => {
        try {
          const pkg = JSON.parse(files["package.json"]);
          return { ...pkg.dependencies, ...pkg.devDependencies };
        } catch {
          return {};
        }
      })()
    : {};

  const allContent = Object.values(files).join("\n");
  const detected: Signature[] = [];

  for (const sig of signatures) {
    let matched = false;

    // Check dependency names
    for (const dep of sig.dependencies) {
      if (deps[dep]) {
        matched = true;
        break;
      }
    }

    // Check string patterns in content
    if (!matched) {
      for (const pattern of sig.patterns) {
        if (allContent.includes(pattern)) {
          matched = true;
          break;
        }
      }
    }

    if (matched) {
      detected.push(sig);
    }
  }

  return buildComplianceReport(detected, projectPath, { scanMode: "local" });
}

// ---------------------------------------------------------------------------
// Report builder — mirrors CLI's buildComplianceReport
// ---------------------------------------------------------------------------

function deriveStatus(
  techs: Signature[],
  complianceGaps?: Array<{ severity: string }>
): { status: "pass" | "warn" | "fail"; exitCode: 0 | 1 | 2 } {
  const hasCriticalGap =
    Array.isArray(complianceGaps) &&
    complianceGaps.some((g) => g.severity === "critical");
  if (techs.length === 0) return { status: "pass", exitCode: 0 };
  if (techs.length >= 6 || hasCriticalGap)
    return { status: "fail", exitCode: 2 };
  return { status: "warn", exitCode: 1 };
}

function buildComplianceReport(
  techs: Signature[],
  source: string,
  opts?: {
    scanMode?: "local" | "url";
    scanId?: string;
    riskScore?: { score: number; level: string };
    complianceGaps?: Array<{
      severity: string;
      title: string;
      detail?: string;
    }>;
    reportUrl?: string;
  }
): ComplianceReport {
  const {
    scanMode = "local",
    scanId,
    riskScore,
    complianceGaps,
    reportUrl,
  } = opts || {};
  const { status, exitCode } = deriveStatus(techs, complianceGaps);

  return {
    version: "1.0",
    ...(scanId ? { scanId } : {}),
    source,
    scannedAt: new Date().toISOString(),
    scanMode,
    status,
    exitCode,
    ...(riskScore ? { riskScore } : {}),
    technologies: techs.map((t) => ({
      name: t.name,
      category: t.category,
      categoryLabel: t.categoryLabel,
      dataTypeCount: t.dataTypeCount,
      cookieNames: t.cookieNames || [],
      thirdPartyName: t.thirdPartyName || "Unknown",
      thirdPartyCountry: t.thirdPartyCountry || "Unknown",
    })),
    ...(Array.isArray(complianceGaps) && complianceGaps.length > 0
      ? {
          complianceGaps: complianceGaps.map((g) => ({
            severity: g.severity,
            title: g.title,
            ...(g.detail ? { detail: g.detail } : {}),
          })),
        }
      : {}),
    summary: {
      totalTechnologies: techs.length,
      totalDataTypes: techs.reduce((sum, t) => sum + (t.dataTypeCount || 0), 0),
      totalCookies: techs.reduce(
        (sum, t) => sum + (t.cookieNames || []).length,
        0
      ),
      thirdParties: [
        ...new Set(
          techs
            .map((t) => t.thirdPartyName)
            .filter((n) => n && n !== "Unknown")
        ),
      ],
    },
    ...(reportUrl ? { reportUrl } : {}),
  };
}

// ---------------------------------------------------------------------------
// Remote API helpers
// ---------------------------------------------------------------------------

function getApiKey(): string | undefined {
  return process.env.PAGEGUARD_API_KEY || undefined;
}

async function scanUrl(url: string): Promise<{
  id: string;
  scanMode?: string;
  technologies: Signature[];
  riskScore?: { score: number; level: string };
  complianceGaps?: Array<{ severity: string; title: string; detail?: string }>;
}> {
  const apiKey = getApiKey();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": `PageGuard-MCP/${PKG_VERSION}`,
  };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  const res = await fetch(`${API_BASE}/api/v1/scan`, {
    method: "POST",
    headers,
    body: JSON.stringify({ url }),
  });

  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as Record<string, string>;
    throw new Error(data.error || `HTTP ${res.status}`);
  }

  return res.json() as Promise<{
    id: string;
    scanMode?: string;
    technologies: Signature[];
    riskScore?: { score: number; level: string };
    complianceGaps?: Array<{
      severity: string;
      title: string;
      detail?: string;
    }>;
  }>;
}

async function generateDocs(
  scanId: string,
  documentType: string
): Promise<Record<string, unknown>> {
  const apiKey = getApiKey();
  if (!apiKey) {
    throw new Error(
      "PAGEGUARD_API_KEY environment variable is required for document generation. " +
        "Get an API key at https://getpageguard.com/#pricing"
    );
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": `PageGuard-MCP/${PKG_VERSION}`,
    Authorization: `Bearer ${apiKey}`,
  };

  const res = await fetch(`${API_BASE}/api/v1/generate`, {
    method: "POST",
    headers,
    body: JSON.stringify({ scanId, productType: documentType }),
  });

  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as Record<string, string>;
    throw new Error(data.error || `HTTP ${res.status}`);
  }

  return res.json() as Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer(
  { name: "pageguard", version: PKG_VERSION },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool 1: pageguard_scan_local
server.tool(
  "pageguard_scan_local",
  "Scan a local project directory for privacy-relevant technologies by checking package.json dependencies, config files, and .env files against known tracking/analytics signatures. No API key or network access needed. Returns a ComplianceReport with detected technologies, data types collected, cookies, and third-party processors.",
  { path: z.string().optional().describe("Absolute path to the project directory. Defaults to the current working directory.") },
  async ({ path: projectPath }) => {
    try {
      const targetPath = projectPath || process.cwd();
      const report = scanLocal(targetPath);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text" as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  }
);

// Tool 2: pageguard_scan_url
server.tool(
  "pageguard_scan_url",
  "Scan a live website URL for privacy compliance issues. Detects tracking technologies, cookies, third-party data collection, and compliance gaps by analyzing the actual deployed site. Returns a ComplianceReport with risk score, detected technologies, and compliance gaps. Optionally uses PAGEGUARD_API_KEY env var for authenticated requests.",
  { url: z.string().describe("The full URL to scan, e.g. https://example.com") },
  async ({ url }) => {
    try {
      const result = await scanUrl(url);
      const reportUrl = `${API_BASE}/report?id=${result.id}`;
      const report = buildComplianceReport(
        result.technologies,
        url,
        {
          scanMode: "url",
          scanId: result.id,
          riskScore: result.riskScore,
          complianceGaps: result.complianceGaps,
          reportUrl,
        }
      );

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text" as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  }
);

// Tool 3: pageguard_generate_docs
server.tool(
  "pageguard_generate_docs",
  "Generate AI-written legal compliance documents (privacy policy, terms of service, cookie policy, etc.) for a previously scanned site. Requires a scanId from a prior URL scan and a PAGEGUARD_API_KEY with available credits. Document types: 'single' ($29 — privacy + terms + cookie), 'bundle' ($49 — everything), 'addon_security' ($19), 'addon_a11y' ($19), 'addon_schema' ($19), 'app_bundle' ($39), 'submission_guide' ($19).",
  {
    scanId: z.string().describe("The scan ID from a previous pageguard_scan_url result"),
    documentType: z
      .string()
      .optional()
      .describe(
        "Product type to generate. One of: single, bundle, addon_security, addon_a11y, addon_schema, app_bundle, submission_guide. Defaults to 'bundle'."
      ),
  },
  async ({ scanId, documentType }) => {
    try {
      const docType = documentType || "bundle";
      const result = await generateDocs(scanId, docType);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text" as const, text: `Error: ${message}` }],
        isError: true,
      };
    }
  }
);

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Server is now running, listening on stdin/stdout
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
