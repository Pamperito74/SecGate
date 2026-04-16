#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

const target = process.argv[2] || ".";
const DEBUG = process.argv.includes("--debug");
const outputFile = "secgate-v4-report.json";

/* -----------------------------
   STATE
------------------------------*/

const findings = [];

const report = {
  version: "4.1-stable",
  timestamp: new Date().toISOString(),
  target,
  mode: DEBUG ? "debug" : "report",
  status: "PASS",
  summary: { critical: 0, high: 0, medium: 0, low: 0 },
  findings: [],
  intelligence: {
    riskScore: 0,
    attackSurface: [],
    recommendations: []
  },
  actions: []
};

/* -----------------------------
   UTILS
------------------------------*/

function toolExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function run(cmd) {
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
  } catch (e) {
    return ((e.stdout || "") + (e.stderr || "")).toString();
  }
}

function logDebug(title, data) {
  if (DEBUG) {
    console.log(`\n[DEBUG] ${title}`);
    console.log(data.slice(0, 1500));
  }
}

/* -----------------------------
   FINDINGS MODEL
------------------------------*/

function addFinding(f) {
  findings.push({
    tool: f.tool,
    type: f.type,
    severity: f.severity,
    signature: f.signature,
    message: f.message,
    fixable: f.fixable || false
  });
}

/* -----------------------------
   SEMGREP (FIXED PARSING)
------------------------------*/

function semgrepScan() {
  if (!toolExists("semgrep")) return;

  const out = run(`semgrep --config=auto ${target}`);
  logDebug("semgrep raw output", out);

  const lower = out.toLowerCase();

  const hasSignal =
    lower.includes("error") ||
    lower.includes("warning") ||
    lower.includes("rule") ||
    lower.includes("finding") ||
    lower.includes("severity");

  if (hasSignal) {
    addFinding({
      tool: "semgrep",
      type: "code",
      severity: lower.includes("error") ? "HIGH" : "MEDIUM",
      signature: "static-analysis",
      message: out.slice(0, 1500),
      fixable: true
    });
  }
}

/* -----------------------------
   GITLEAKS (FIXED PARSING)
------------------------------*/

function gitleaksScan() {
  if (!toolExists("gitleaks")) return;

  const out = run(`gitleaks detect --source ${target}`);
  logDebug("gitleaks raw output", out);

  const lower = out.toLowerCase();

  const hasLeakSignal =
    lower.includes("leak") ||
    lower.includes("secret") ||
    lower.includes("finding") ||
    lower.includes("detected");

  if (hasLeakSignal) {
    addFinding({
      tool: "gitleaks",
      type: "secret",
      severity: "CRITICAL",
      signature: "secret-exposure",
      message: out.slice(0, 1500),
      fixable: false
    });
  }
}

/* -----------------------------
   TRIVY
------------------------------*/

function trivyScan() {
  if (!toolExists("trivy")) return;

  const out = run(`trivy fs ${target}`);
  logDebug("trivy raw output", out);

  const lower = out.toLowerCase();

  if (lower.includes("critical")) {
    addFinding({
      tool: "trivy",
      type: "dependency",
      severity: "CRITICAL",
      signature: "infra-critical",
      message: out.slice(0, 1500),
      fixable: false
    });
  } else if (lower.includes("high")) {
    addFinding({
      tool: "trivy",
      type: "dependency",
      severity: "HIGH",
      signature: "infra-high",
      message: out.slice(0, 1500),
      fixable: false
    });
  }
}

/* -----------------------------
   NPM AUDIT (SAFE)
------------------------------*/

function npmAudit() {
  if (!fs.existsSync(`${target}/package.json`)) return;

  const out = run(`cd ${target} && npm audit --json`);
  logDebug("npm audit raw", out);

  try {
    const json = JSON.parse(out);
    const vulns = json.vulnerabilities || {};

    for (const k in vulns) {
      const v = vulns[k];

      addFinding({
        tool: "npm",
        type: "dependency",
        severity:
          v.severity === "critical"
            ? "CRITICAL"
            : v.severity === "high"
            ? "HIGH"
            : v.severity === "moderate"
            ? "MEDIUM"
            : "LOW",
        signature: k,
        message: k,
        fixable: true
      });
    }
  } catch {
    if (out.toLowerCase().includes("eno lock")) {
      if (DEBUG) console.log("[SKIP] npm lockfile missing");
    }
  }
}

/* -----------------------------
   INTELLIGENCE ENGINE (v4 CORE)
------------------------------*/

function analyze(findings) {
  const weights = {
    CRITICAL: 10,
    HIGH: 5,
    MEDIUM: 2,
    LOW: 1
  };

  let score = 0;
  const attackSurface = new Set();
  const recommendations = [];

  for (const f of findings) {
    score += weights[f.severity] || 0;
    attackSurface.add(f.type);

    if (f.severity === "CRITICAL") {
      recommendations.push(`Immediate action required: ${f.tool}`);
    }

    if (f.type === "secret") {
      recommendations.push("Rotate exposed credentials immediately");
    }

    if (f.type === "dependency") {
      recommendations.push("Update vulnerable dependencies");
    }
  }

  return {
    riskScore: score,
    attackSurface: [...attackSurface],
    recommendations: [...new Set(recommendations)]
  };
}

/* -----------------------------
   ACTION ENGINE
------------------------------*/

function buildActions(findings) {
  return findings
    .filter(f => f.fixable)
    .map(f => ({
      tool: f.tool,
      severity: f.severity,
      command:
        f.tool === "npm"
          ? "npm audit fix"
          : f.tool === "semgrep"
          ? "review code pattern"
          : "manual remediation required"
    }));
}

/* -----------------------------
   PIPELINE
------------------------------*/

console.log("\nSEC GATE v4.1 AUTONOMOUS ENGINE");
console.log("Target:", target);
console.log("Debug:", DEBUG);
console.log("--------------------------------");

semgrepScan();
gitleaksScan();
trivyScan();
npmAudit();

/* -----------------------------
   PROCESS RESULTS
------------------------------*/

report.findings = findings;

/* summary */
for (const f of findings) {
  report.summary[f.severity.toLowerCase()]++;
}

report.intelligence = analyze(findings);
report.actions = buildActions(findings);

/* -----------------------------
   FINAL DECISION
------------------------------*/

const hasCritical = findings.some(f => f.severity === "CRITICAL");
const hasHigh = findings.some(f => f.severity === "HIGH");

report.status = hasCritical || hasHigh ? "FAIL" : "PASS";

/* -----------------------------
   OUTPUT
------------------------------*/

console.log("\n--------------------------------");
console.log("SEC GATE v4 COMPLETE");
console.log("STATUS:", report.status);

console.log("\nSUMMARY:", report.summary);
console.log("RISK SCORE:", report.intelligence.riskScore);

console.log("\nRECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r => console.log("-", r));

console.log("\nACTIONS:");
report.actions.forEach(a => console.log("-", a.command));

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

console.log("\nReport saved:", outputFile);

process.exit(report.status === "PASS" ? 0 : 1);