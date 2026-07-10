#!/usr/bin/env node

import fs from "fs";

const forbidden = /^(file:|link:|workspace:)/;
const manifests = ["package.json", "package-lock.json"];
const failures = [];

function checkObject(obj, where) {
  for (const key of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = obj?.[key] || {};
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec === "string" && forbidden.test(spec)) {
        failures.push(`${where}.${key}.${name} = ${spec}`);
      }
    }
  }
}

for (const file of manifests) {
  if (!fs.existsSync(file)) continue;
  const json = JSON.parse(fs.readFileSync(file, "utf8"));
  checkObject(json, file);

  for (const [pkgPath, pkg] of Object.entries(json.packages || {})) {
    checkObject(pkg, `${file}.packages["${pkgPath}"]`);
    if (
      pkg &&
      typeof pkg.resolved === "string" &&
      /(^|\/)\.\.(\/|$)|^(file:|link:|workspace:)/.test(pkg.resolved)
    ) {
      failures.push(`${file}.packages["${pkgPath}"].resolved = ${pkg.resolved}`);
    }
    if (pkg?.link === true) {
      failures.push(`${file}.packages["${pkgPath}"].link = true`);
    }
  }
}

if (failures.length) {
  console.error("Local dependency references are not publish-safe:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Dependency guard passed: no file:/link:/workspace: dependencies.");
