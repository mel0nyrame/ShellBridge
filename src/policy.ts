import fs from "node:fs";
import path from "node:path";
import type { GatewayConfig } from "./config.js";

export function canonicalDirectory(raw: string): string {
  const canonical = fs.realpathSync(raw);
  if (!fs.statSync(canonical).isDirectory()) throw new Error("cwd_not_directory");
  return canonical;
}

export interface SmokeState {
  directory: string;
  enabled_file: string;
  enabled_dev: number;
  enabled_ino: number;
  enabled_mtime_ms: number;
}

export function getApprovalSmokeState(config: GatewayConfig): SmokeState {
  const directory = canonicalDirectory(config.approvalSmokeDirectory);
  const enabledFile = fs.realpathSync(config.approvalSmokeEnabledFile);
  if (path.dirname(enabledFile) !== directory) throw new Error("approval_smoke_disabled");
  const directoryStat = fs.statSync(directory);
  const enabledStat = fs.statSync(enabledFile);
  if (!enabledStat.isFile() || directoryStat.uid !== 0 || enabledStat.uid !== 0 || (directoryStat.mode & 0o022) !== 0 || (enabledStat.mode & 0o022) !== 0) {
    throw new Error("approval_smoke_disabled");
  }
  return {
    directory,
    enabled_file: enabledFile,
    enabled_dev: enabledStat.dev,
    enabled_ino: enabledStat.ino,
    enabled_mtime_ms: enabledStat.mtimeMs,
  };
}
