import { execFile } from "node:child_process";
import fs from "node:fs";

interface HostObservationOptions {
  helperPath: string;
  observerUid: number;
  observerGid: number;
  commandPaths: { claude: string[] };
  timeoutMs: number;
  maxOutputBytes: number;
}

export type CommandObservation =
  | { installed: false }
  | { installed: true; path: string; version: string };

function observe(
  helperPath: string,
  uid: number,
  gid: number,
  executable: string,
  timeoutMs: number,
  maxOutputBytes: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      helperPath,
      ["observe-command", String(uid), String(gid), executable, "--version"],
      { shell: false, env: {}, cwd: "/", timeout: timeoutMs, maxBuffer: maxOutputBytes, encoding: "utf8" },
      (error, stdout) => error ? reject(new Error("command_observation_unavailable")) : resolve(stdout),
    );
  });
}

export class HostObservation {
  constructor(private readonly options: HostObservationOptions) {
    if (options.observerUid <= 0 || options.observerGid <= 0) throw new Error("invalid_observer_identity");
  }

  async inspectCommand(request: { commandId: "claude" }): Promise<CommandObservation> {
    if (request.commandId !== "claude") throw new Error("unsupported_command_id");
    let executable: string | undefined;
    for (const candidate of this.options.commandPaths.claude) {
      try {
        const canonical = fs.realpathSync(candidate);
        const metadata = fs.statSync(canonical);
        if (metadata.isFile()) {
          executable = canonical;
          break;
        }
      } catch {
        // A missing registered candidate means "not installed", not a broader path search.
      }
    }
    if (!executable) return { installed: false };
    const output = await observe(
      this.options.helperPath,
      this.options.observerUid,
      this.options.observerGid,
      executable,
      this.options.timeoutMs,
      this.options.maxOutputBytes,
    );
    const version = /\b\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?\b/.exec(output)?.[0];
    if (!version) throw new Error("command_version_unrecognized");
    return { installed: true, path: executable, version };
  }
}
