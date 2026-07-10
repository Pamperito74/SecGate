#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import {
  DEFAULT_WALK_LIMITS,
  WalkLimitError,
  scanTargetTree
} from "../lib/walk.mjs";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "secgate-walk-"));

try {
  fs.mkdirSync(path.join(tmp, "project-a", "src"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "project-a", "node_modules", "dep"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "project-a", ".git", "objects"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "project-a", "dist"), { recursive: true });

  fs.writeFileSync(path.join(tmp, "project-a", "package.json"), "{}");
  fs.writeFileSync(path.join(tmp, "project-a", "src", "index.js"), "console.log('ok')\n");
  fs.writeFileSync(path.join(tmp, "project-a", "Dockerfile"), "FROM scratch\n");
  fs.writeFileSync(path.join(tmp, "project-a", "node_modules", "dep", "package.json"), "{}");
  fs.writeFileSync(path.join(tmp, "project-a", ".git", "objects", "blob"), "ignored");
  fs.writeFileSync(path.join(tmp, "project-a", "dist", "bundle.js"), "ignored");
  fs.writeFileSync(path.join(tmp, "project-a", "huge.js"), Buffer.alloc(64));

  try {
    fs.symlinkSync(tmp, path.join(tmp, "project-a", "src", "cycle"));
  } catch {
    // Some filesystems disallow symlink creation; the rest of the test still
    // exercises bounded walking and vendor excludes.
  }

  const stats = scanTargetTree(tmp, {
    limits: { ...DEFAULT_WALK_LIMITS, maxFileSizeBytes: 32 }
  });

  assert.equal(stats.packageJsonFiles, 1, "package.json under node_modules must be excluded");
  assert.equal(stats.dockerfiles.length, 1, "Dockerfile should be discovered outside excluded dirs");
  assert.equal(stats.skippedDirs >= 3, true, "node_modules, .git, and dist should be skipped");
  assert.equal(stats.skippedLargeFiles, 1, "large files should be counted and skipped for parsing");

  assert.throws(
    () => scanTargetTree(tmp, { limits: { ...DEFAULT_WALK_LIMITS, maxFiles: 1 } }),
    WalkLimitError,
    "maxFiles should abort pathological walks"
  );

  console.log("✓ bounded target walk excludes vendor/build dirs and enforces limits");
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
