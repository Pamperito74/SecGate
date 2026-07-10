import fs from "fs";
import path from "path";

export const DEFAULT_WALK_LIMITS = {
  maxFiles: 25_000,
  maxDepth: 24,
  maxFileSizeBytes: 2 * 1024 * 1024,
  timeoutMs: 30_000
};

export const DEFAULT_EXCLUDED_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "bower_components",
  ".pnpm",
  ".yarn",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  "out",
  "target",
  "Pods"
]);

const SOURCE_FILE_RE = /\.(cjs|css|go|html|java|js|json|jsx|mjs|php|py|rb|rs|ts|tsx|xml|yaml|yml)$/i;
const LOCK_OR_MANIFEST_RE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|package\.json|go\.mod|Cargo\.lock|requirements\.txt|Pipfile\.lock|poetry\.lock|Gemfile\.lock|composer\.lock)$/;
const DOCKERFILE_RE = /^(Dockerfile|.+\.Dockerfile)$/;

export class WalkLimitError extends Error {
  constructor(message, stats) {
    super(message);
    this.name = "WalkLimitError";
    this.stats = stats;
  }
}

export function parsePositiveInt(value, fallback, label) {
  if (value == null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return n;
}

export function scanTargetTree(target, opts = {}) {
  const limits = { ...DEFAULT_WALK_LIMITS, ...(opts.limits || {}) };
  const excludedDirs = new Set([...(opts.excludedDirs || DEFAULT_EXCLUDED_DIRS)]);
  const onProgress = typeof opts.onProgress === "function" ? opts.onProgress : null;
  const progressEvery = opts.progressEvery || 2_000;
  const startedAt = Date.now();
  const root = path.resolve(target);
  const rootHasPackageJson = fs.existsSync(path.join(root, "package.json"));

  const stats = {
    files: 0,
    dirs: 0,
    sourceFiles: 0,
    packageJsonFiles: 0,
    dockerfiles: [],
    skippedDirs: 0,
    skippedSymlinks: 0,
    skippedLargeFiles: 0,
    maxDepthSeen: 0
  };
  const packageJsonDirs = [];
  const seenDirs = new Set();

  function checkLimits(depth) {
    const elapsed = Date.now() - startedAt;
    if (elapsed > limits.timeoutMs) {
      throw new WalkLimitError(
        `Scan preflight exceeded ${limits.timeoutMs}ms while walking ${root}. ` +
          `Point SecGate at a smaller project or raise --walk-timeout-ms.`,
        stats
      );
    }
    if (depth > limits.maxDepth) {
      throw new WalkLimitError(
        `Scan preflight exceeded max depth ${limits.maxDepth} at ${root}. ` +
          `Point SecGate at a smaller project or raise --max-depth.`,
        stats
      );
    }
    if (stats.files > limits.maxFiles) {
      throw new WalkLimitError(
        `Scan preflight exceeded max files ${limits.maxFiles} under ${root}. ` +
          `Point SecGate at a single project or raise --max-files.`,
        stats
      );
    }
  }

  function maybeProgress(currentPath) {
    if (!onProgress || stats.files === 0 || stats.files % progressEvery !== 0) return;
    onProgress({ ...stats, currentPath });
  }

  function walk(dir, depth) {
    checkLimits(depth);
    let realDir;
    try {
      realDir = fs.realpathSync(dir);
    } catch {
      return;
    }
    if (seenDirs.has(realDir)) {
      stats.skippedSymlinks++;
      return;
    }
    seenDirs.add(realDir);
    stats.dirs++;
    stats.maxDepthSeen = Math.max(stats.maxDepthSeen, depth);

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        stats.skippedSymlinks++;
        continue;
      }
      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name)) {
          stats.skippedDirs++;
          continue;
        }
        walk(full, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;

      stats.files++;
      checkLimits(depth);
      maybeProgress(full);

      let size = 0;
      try {
        size = fs.statSync(full).size;
      } catch {
        continue;
      }
      if (size > limits.maxFileSizeBytes) {
        stats.skippedLargeFiles++;
      }

      const rel = path.relative(root, full).replaceAll(path.sep, "/");
      if (entry.name === "package.json") {
        stats.packageJsonFiles++;
        packageJsonDirs.push(path.dirname(full));
      }
      if (DOCKERFILE_RE.test(entry.name) && size <= limits.maxFileSizeBytes) {
        stats.dockerfiles.push(full);
      }
      if (
        size <= limits.maxFileSizeBytes &&
        (SOURCE_FILE_RE.test(entry.name) || LOCK_OR_MANIFEST_RE.test(rel) || DOCKERFILE_RE.test(entry.name))
      ) {
        stats.sourceFiles++;
      }
    }
  }

  walk(root, 0);

  return {
    ...stats,
    rootHasPackageJson,
    packageJsonDirs
  };
}
