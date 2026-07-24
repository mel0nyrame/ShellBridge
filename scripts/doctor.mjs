import { access, constants } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const checks = [];
const record = (name, ok, detail) => checks.push({ name, ok, detail });

record("platform", process.platform === "linux" && process.arch === "x64", `${process.platform} ${process.arch}; requires linux x64`);
record("Node.js", Number(process.versions.node.split(".")[0]) >= 22, `${process.versions.node}; requires 22+`);

for (const [name, command] of [["C compiler", "cc"], ["Bubblewrap", process.env.SHELLBRIDGE_BWRAP_PATH ?? "/usr/bin/bwrap"]]) {
  const result = spawnSync(command, name === "C compiler" ? ["--version"] : ["--version"], { encoding: "utf8", timeout: 2_000 });
  record(name, result.status === 0, result.status === 0 ? (result.stdout || result.stderr).split("\n")[0] : `${command} unavailable`);
}

let cgroupDetail = "cgroup v2 unavailable";
let cgroupOk = false;
try {
  await access("/sys/fs/cgroup/cgroup.controllers", constants.R_OK);
  cgroupOk = true;
  cgroupDetail = "cgroup v2 controllers detected";
} catch {}
record("cgroup v2", cgroupOk, cgroupDetail);

const userNamespace = spawnSync("unshare", ["--user", "--map-root-user", "true"], { encoding: "utf8", timeout: 2_000 });
record("user namespace", userNamespace.status === 0, userNamespace.status === 0 ? "available" : "unprivileged user namespace probe failed");

const helper = path.resolve(process.env.SHELLBRIDGE_NATIVE_HELPER_PATH ?? "dist/native/shellbridge-helper");
try {
  await access(helper, constants.X_OK);
  record("native helper", true, helper);
} catch {
  record("native helper", false, `${helper} is not built; run npm run build:native`);
}

const databasePath = path.resolve(process.env.SHELLBRIDGE_DATABASE_PATH ?? "/var/lib/shellbridge/shellbridge.db");
try {
  await access(path.dirname(databasePath), constants.W_OK);
  record("database directory", true, path.dirname(databasePath));
} catch {
  record("database directory", false, `${path.dirname(databasePath)} is not writable`);
}

for (const name of ["SHELLBRIDGE_BEARER_TOKEN", "SHELLBRIDGE_DATA_KEY", "SHELLBRIDGE_OAUTH_OWNER_SECRET"]) {
  record(name, Boolean(process.env[name]), process.env[name] ? "set" : "missing");
}

for (const name of [
  "SHELLBRIDGE_WRITE_ACTIONS_ENABLED",
  "SHELLBRIDGE_DOCUMENT_WRITES_ENABLED",
  "SHELLBRIDGE_LOCAL_GIT_WRITES_ENABLED",
  "SHELLBRIDGE_EXISTING_SCRIPT_RUNS_ENABLED",
]) {
  const enabled = ["1", "true"].includes((process.env[name] ?? "false").toLowerCase());
  record(name, !enabled, enabled ? "ENABLED" : "disabled");
}

for (const check of checks) {
  console.log(`${check.ok ? "PASS" : "FAIL"}  ${check.name}: ${check.detail}`);
}
process.exitCode = checks.every((check) => check.ok) ? 0 : 1;
