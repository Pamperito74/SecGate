import { execFileSync, execFile } from "child_process";

// Default ceiling for any single scanner invocation. A hung or wedged scanner
// binary must not stall SecGate (or the CI job) indefinitely. Individual
// callers may override `timeout` (e.g. Trivy image scans use a tighter budget).
export const DEFAULT_TOOL_TIMEOUT_MS = 180_000;

function isTimeoutError(err) {
  return Boolean(
    err &&
      (err.killed === true ||
        err.code === "ETIMEDOUT" ||
        /timed out|timeout/i.test(String(err.message || "")))
  );
}

export function runTool(binary, args, opts = {}) {
  const timeout = opts.timeout ?? DEFAULT_TOOL_TIMEOUT_MS;
  try {
    const stdout = execFileSync(binary, args, {
      encoding: "utf-8",
      stdio: "pipe",
      maxBuffer: 64 * 1024 * 1024,
      timeout,
      ...opts
    });
    return { stdout: stdout || "", stderr: "", timedOut: false, error: null, timeoutMs: timeout };
  } catch (e) {
    return {
      stdout: (e.stdout || "").toString(),
      stderr: (e.stderr || "").toString(),
      timedOut: isTimeoutError(e),
      error: e,
      timeoutMs: timeout
    };
  }
}

export function runToolAsync(binary, args, opts = {}) {
  const timeout = opts.timeout ?? DEFAULT_TOOL_TIMEOUT_MS;
  return new Promise((resolve) => {
    execFile(binary, args, {
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
      timeout,
      ...opts
    }, (err, stdout, stderr) => {
      resolve({
        stdout: (stdout || "").toString(),
        stderr: (stderr || "").toString(),
        timedOut: isTimeoutError(err),
        error: err || null,
        timeoutMs: timeout
      });
    });
  });
}

/**
 * JSON.parse a scanner's stdout. On failure, surface the reason (and a short
 * head of the raw output) via `debugFn` if one is set, then rethrow — the
 * caller's existing catch turns it into a `{ status: "error" }` result, but
 * now `--debug` shows *why* instead of swallowing it silently.
 */
export function parseToolJson(label, raw, debugFn) {
  try {
    return JSON.parse(raw);
  } catch (err) {
    if (typeof debugFn === "function") {
      const head = String(raw ?? "").slice(0, 200).replace(/\n/g, "\\n");
      debugFn(`${label}: JSON parse failed — ${String((err && err.message) || err)} | first 200 bytes: ${head}`, raw);
    }
    throw err;
  }
}

export function toolExists(cmd) {
  try {
    execFileSync("which", [cmd], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const SEVERITY_TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export function normalizeSeverity(raw) {
  if (raw == null) return "UNKNOWN";
  const v = String(raw).trim().toUpperCase();
  if (v === "MODERATE") return "MEDIUM";
  if (v === "WARNING") return "MEDIUM";
  if (v === "ERROR") return "HIGH";
  if (v === "INFO" || v === "NOTE" || v === "INFORMATIONAL") return "LOW";
  if (v === "NEGLIGIBLE") return "LOW";
  return SEVERITY_TIERS.includes(v) ? v : "UNKNOWN";
}

export function matchPattern(pattern, value) {
  if (!pattern.includes("*")) return pattern === value;
  if (pattern.length > 256) return false;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  // secgate:ignore javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
  return new RegExp(`^${escaped}$`).test(value);
}

export function matchesAny(patterns, value) {
  return patterns.some(p => matchPattern(p, value));
}
