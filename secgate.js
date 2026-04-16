#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

/* -----------------------------
   CONFIG
------------------------------*/

const target = process.argv[2] || ".";
const APPLY = process.argv.includes("--apply");
const DEBUG = process.argv.includes("--debug");

const outputFile = "secgate-v7-report.json";

/* -----------------------------
   STATE
------------------------------*/

const findings = [];

const report = {
  version: "7.0",
  timestamp: new Date().toISOString(),
  target,
  mode: APPLY ? "apply" : "dry-run",
  status: "PASS",

  summary: { critical: 0, high: 0, medium: 0, low: 0 },

  findings: [],

  intelligence: {
    riskScore: 0,
    attackSurface: [],
    reasoning: [],
    recommendations: []
  },

  remediation: {
    plan: [],
    stagedChanges: [],
    executed: [],
    blocked: [],
    confidence: 100
  }
};

/* -----------------------------
   UTILS
------------------------------*/

function run(cmd) {
  try {
    return execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
  } catch (e) {
    return ((e.stdout || "") + (e.stderr || "")).toString();
  }
}

function toolExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function debug(label, data) {
  if (DEBUG) {
    console.log(`\n[DEBUG] ${label}`);
    console.log(data.slice(0, 1000));
  }
}

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
   SCANNERS (REAL JSON PARSING)
------------------------------*/

function gitleaks() {
  if (!toolExists("gitleaks")) return;

  const out = run(`gitleaks detect --source ${target} --report-format json`);
  debug("gitleaks", out);

  try {
    const data = JSON.parse(out);

    data.forEach(item => {
      addFinding({
        tool: "gitleaks",
        type: "secret",
        severity: "CRITICAL",
        signature: item.RuleID,
        message: item.Description,
        fixable: false
      });
    });
  } catch {}
}

function semgrep() {
  if (!toolExists("semgrep")) return;

  const out = run(`semgrep --config=auto --json ${target}`);
  debug("semgrep", out);

  try {
    const data = JSON.parse(out);

    data.results.forEach(r => {
      addFinding({
        tool: "semgrep",
        type: "code",
        severity: r.extra.severity === "ERROR" ? "HIGH" : "MEDIUM",
        signature: r.check_id,
        message: r.extra.message,
        fixable: true
      });
    });
  } catch {}
}

function npmAudit() {
  if (!fs.existsSync(`${target}/package.json`)) return;

  const out = run(`cd ${target} && npm audit --json`);
  debug("npm audit", out);

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
            : "MEDIUM",
        signature: k,
        message: v.title,
        fixable: true
      });
    }
  } catch {}
}

/* -----------------------------
   INTELLIGENCE ENGINE
------------------------------*/

function analyze(findings) {
  let risk = 0;
  const surface = new Set();
  const reasoning = [];
  const recs = [];

  for (const f of findings) {
    const weight =
      f.severity === "CRITICAL"
        ? 10
        : f.severity === "HIGH"
        ? 6
        : 3;

    risk += weight;
    surface.add(f.type);

    reasoning.push({
      issue: f.signature,
      why:
        f.type === "secret"
          ? "Credential exposure enables immediate compromise"
          : f.type === "dependency"
          ? "Known CVEs can be exploited"
          : "Unsafe code pattern"
    });

    if (f.type === "secret") recs.push("Rotate credentials immediately");
    if (f.type === "dependency") recs.push("Run npm audit fix");
    if (f.type === "code") recs.push("Refactor insecure code");
  }

  return {
    riskScore: risk,
    attackSurface: [...surface],
    reasoning,
    recommendations: [...new Set(recs)]
  };
}

/* -----------------------------
   REMEDIATION ENGINE
------------------------------*/

function patch(f) {
  if (f.tool === "npm") {
    return {
      action: "npm audit fix",
      cmd: `cd ${target} && npm audit fix`
    };
  }

  if (f.tool === "semgrep") {
    return {
      action: "manual code fix",
      cmd: null
    };
  }

  if (f.tool === "gitleaks") {
    return {
      action: "remove + rotate secret",
      cmd: null
    };
  }

  return { action: "manual", cmd: null };
}

function remediate(findings) {
  let confidence = 100;
  const plan = [];
  const staged = [];
  const executed = [];
  const blocked = [];

  for (const f of findings) {
    const p = patch(f);

    plan.push({ issue: f.signature, patch: p });

    if (f.severity === "CRITICAL") {
      blocked.push(p);
      confidence -= 30;
      continue;
    }

    if (f.fixable && p.cmd) {
      staged.push(p);

      if (APPLY) {
        try {
          run(p.cmd);
          executed.push(p.action);
        } catch {
          blocked.push(p);
        }
      }
    }
  }

  return {
    plan,
    stagedChanges: staged,
    executed,
    blocked,
    confidence: Math.max(confidence, 0)
  };
}

/* -----------------------------
   PIPELINE
------------------------------*/

console.log("\nSEC GATE v7 - AI SOC ENGINE");
console.log("Target:", target);
console.log("Mode:", APPLY ? "APPLY" : "DRY RUN");
console.log("--------------------------------");

semgrep();
gitleaks();
npmAudit();

/* -----------------------------
   PROCESS
------------------------------*/

report.findings = findings;

for (const f of findings) {
  report.summary[f.severity.toLowerCase()]++;
}

report.intelligence = analyze(findings);
report.remediation = remediate(findings);

/* -----------------------------
   DECISION
------------------------------*/

const hasCritical = findings.some(f => f.severity === "CRITICAL");
const hasHigh = findings.some(f => f.severity === "HIGH");

report.status = hasCritical || hasHigh ? "FAIL" : "PASS";

/* -----------------------------
   OUTPUT
------------------------------*/

console.log("\n--------------------------------");
console.log("STATUS:", report.status);
console.log("RISK SCORE:", report.intelligence.riskScore);
console.log("CONFIDENCE:", report.remediation.confidence + "%");

console.log("\nTOP ISSUES:");
findings.slice(0, 5).forEach(f =>
  console.log("-", f.signature, "|", f.severity)
);

console.log("\nRECOMMENDATIONS:");
report.intelligence.recommendations.forEach(r =>
  console.log("-", r)
);

if (APPLY) {
  console.log("\nEXECUTED FIXES:");
  report.remediation.executed.forEach(e => console.log("-", e));
}

fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));

console.log("\nReport saved:", outputFile);

process.exit(report.status === "PASS" ? 0 : 1);