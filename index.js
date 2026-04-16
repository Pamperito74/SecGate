#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

const target = process.argv[2] || ".";
const reportFile = "soc-report.json";

let FAIL = 0;

const report = {
  timestamp: new Date().toISOString(),
  target,
  status: "PASS",
  checks: {}
};

function exists(path) {
  return fs.existsSync(path);
}

function toolExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function safeRun(name, cmd, critical = false) {
  console.log(`\n[RUN] ${name}`);
  console.log(`$ ${cmd}`);

  try {
    const out = execSync(cmd, {
      encoding: "utf-8",
      stdio: "pipe"
    });

    report.checks[name] = {
      ok: true,
      output: out?.toString()?.slice(0, 1500) || ""
    };

    console.log(`[OK] ${name}`);
  } catch (err) {
    const msg =
      (err.stdout || "").toString() +
      (err.stderr || "").toString() +
      (err.message || "");

    report.checks[name] = {
      ok: false,
      error: msg.slice(0, 2000)
    };

    console.log(`[FAIL] ${name}`);
    console.log(msg.slice(0, 400));

    if (critical) FAIL = 1;
  }
}

/* ---------------------------
   SOC SCAN PIPELINE
----------------------------*/

console.log("SOC SCAN START");
console.log("Target:", target);
console.log("-------------------------");

/* [1] STATIC ANALYSIS */
console.log("[1] Static Analysis (Semgrep)");

if (toolExists("semgrep")) {
  safeRun("semgrep", `semgrep --config=auto ${target}`, true);
} else {
  console.log("[SKIP] semgrep not installed");
}

/* ------------------------- */

console.log("-------------------------");

/* [2] SECRETS SCAN */
console.log("[2] Secrets Scan (Gitleaks)");

if (toolExists("gitleaks")) {
  safeRun("gitleaks", `gitleaks detect --source ${target}`);
} else {
  console.log("[SKIP] gitleaks not installed");
}

/* ------------------------- */

console.log("-------------------------");

/* [3] DEPENDENCY SCAN */
console.log("[3] Dependency Scan");

if (exists(`${target}/package.json`)) {
  console.log("Node project detected");

  safeRun(
    "npm-audit",
    `cd ${target} && npm audit --json`,
    false
  );
}

if (exists(`${target}/requirements.txt`)) {
  console.log("Python project detected");

  safeRun(
    "pip-audit",
    `pip-audit -r ${target}/requirements.txt`,
    false
  );
}

/* ------------------------- */

console.log("-------------------------");

/* [4] INFRA / FS SCAN */
console.log("[4] Filesystem / IaC Scan (Trivy)");

if (toolExists("trivy")) {
  safeRun("trivy", `trivy fs ${target}`);
} else {
  console.log("[SKIP] trivy not installed");
}

/* ------------------------- */

/* [5] LINTING (optional) */
console.log("[5] Lint Scan");

if (exists(`${target}/package.json`) && toolExists("eslint")) {
  safeRun("eslint", `npx eslint ${target}`);
} else {
  console.log("[SKIP] eslint not available or no node project");
}

/* ------------------------- */

/* FINALIZE */
report.status = FAIL === 0 ? "PASS" : "FAIL";

console.log("-------------------------");
console.log("SOC SCAN END");
console.log("RESULT:", report.status);

/* write report */
fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));

console.log(`Report saved -> ${reportFile}`);

/* exit code for CI / git hooks */
process.exit(FAIL);