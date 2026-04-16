#!/usr/bin/env node

import { execSync } from "child_process";
import fs from "fs";

const target = process.argv[2] || ".";
const report = {
  timestamp: new Date().toISOString(),
  target,
  status: "PASS",
  checks: {}
};

function run(name, cmd) {
  try {
    const out = execSync(cmd, { encoding: "utf-8", stdio: "pipe" });
    report.checks[name] = { ok: true };
  } catch (err) {
    report.checks[name] = {
      ok: false,
      error: (err.stdout || err.message || "").toString().slice(0, 500)
    };
    report.status = "FAIL";
  }
}

function exists(path) {
  return fs.existsSync(path);
}

function checkBranch() {
  try {
    const branch = execSync("git rev-parse --abbrev-ref HEAD", { encoding: "utf-8" }).trim();
    const ok = /^(feature|fix|chore|hotfix)\/[a-z0-9-_]+$/.test(branch);
    report.checks["branch"] = { ok, branch };
    if (!ok) report.status = "FAIL";
  } catch {
    report.checks["branch"] = { ok: false };
    report.status = "FAIL";
  }
}

function checkCommit() {
  try {
    const msg = execSync("git log -1 --pretty=%B", { encoding: "utf-8" }).trim();
    const ok = msg.length >= 10;
    report.checks["commit"] = { ok, msg };
    if (!ok) report.status = "FAIL";
  } catch {
    report.checks["commit"] = { ok: false };
    report.status = "FAIL";
  }
}

console.log("soc-scan start");

// security scanners
run("semgrep", `semgrep --config=auto ${target}`);
run("gitleaks", `gitleaks detect --source ${target}`);
run("trivy", `trivy fs ${target}`);

// dependency checks
if (exists(`${target}/package.json`)) {
  run("npm-audit", `cd ${target} && npm audit --json`);
}

if (exists(`${target}/requirements.txt`)) {
  run("pip-audit", `pip-audit -r ${target}/requirements.txt`);
}

// lint (optional but useful)
if (exists(`${target}/package.json`)) {
  run("eslint", `npx eslint ${target}`);
}

// git checks
checkBranch();
checkCommit();

// output
fs.writeFileSync("soc-report.json", JSON.stringify(report, null, 2));

console.log("soc-scan done");
console.log("status:", report.status);

// exit for hooks
process.exit(report.status === "PASS" ? 0 : 1);