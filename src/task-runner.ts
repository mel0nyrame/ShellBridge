import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PROJECT_TASK_OUTPUT_DEFAULT_BYTES, PROJECT_TASK_TIMEOUT_DEFAULT_MS } from "./domain.js";
import { ManagedPathPolicy, isInside } from "./path-policy.js";
import type { SandboxedShell } from "./sandboxed-shell.js";

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function validateArguments(args: string[] | undefined): string[] {
  if (args === undefined) return [];
  if (!Array.isArray(args) || args.length > 100 || args.some((item) => typeof item !== "string" || item.length > 4096 || item.includes("\0"))) {
    throw new Error("invalid_script_arguments");
  }
  return args;
}

function sha256(target: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
}

function existingRegularFile(policy: ManagedPathPolicy, requested: string): string {
  const target = policy.resolve(requested);
  const metadata = fs.lstatSync(target);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("script_not_regular_file");
  return target;
}

function scriptInvocation(relativeScript: string, extension: string, args: string[]): string[] {
  if (extension === ".sh" || extension === ".bash") return ["/bin/bash", relativeScript, ...args];
  if (extension === ".py") return ["/usr/bin/python3", relativeScript, ...args];
  if ([".js", ".mjs", ".cjs"].includes(extension)) return [process.execPath, relativeScript, ...args];
  if (extension === ".ts") return ["/usr/bin/env", "tsx", relativeScript, ...args];
  if (extension === ".go") return ["/usr/bin/env", "go", "run", relativeScript, ...args];
  return [`./${relativeScript}`, ...args];
}

export class ProjectTaskRunner {
  private readonly policy: ManagedPathPolicy;

  constructor(
    root: string,
    blockedPaths: string[],
    private readonly sandbox: Pick<SandboxedShell, "run">,
  ) {
    this.policy = new ManagedPathPolicy(root, blockedPaths);
  }

  async run(input: {
    cwd: string;
    package_script?: string;
    script_path?: string;
    args?: string[];
    timeout_ms?: number;
    max_output_bytes?: number;
  }) {
    const cwd = this.policy.resolve(input.cwd);
    if (!fs.lstatSync(cwd).isDirectory()) throw new Error("task_cwd_not_directory");
    if (Boolean(input.package_script) === Boolean(input.script_path)) throw new Error("specify_package_script_or_script_path");
    const args = validateArguments(input.args);
    let invocation: string[];
    let integrityTarget: string;
    let task: Record<string, unknown>;
    if (input.package_script) {
      if (!/^[A-Za-z0-9:_-]{1,128}$/.test(input.package_script)) throw new Error("invalid_package_script");
      const packageJson = existingRegularFile(this.policy, path.join(cwd, "package.json"));
      const parsed = JSON.parse(fs.readFileSync(packageJson, "utf8")) as { scripts?: Record<string, unknown> };
      if (!parsed.scripts || typeof parsed.scripts[input.package_script] !== "string") throw new Error("package_script_not_found");
      const manager = fs.existsSync(path.join(cwd, "pnpm-lock.yaml")) ? "pnpm"
        : fs.existsSync(path.join(cwd, "yarn.lock")) ? "yarn"
          : "npm";
      invocation = [manager, "run", input.package_script, ...(args.length > 0 ? ["--", ...args] : [])];
      integrityTarget = packageJson;
      task = { type: "package_script", package_manager: manager, script: input.package_script };
    } else {
      const script = existingRegularFile(this.policy, input.script_path!);
      if (!isInside(script, cwd)) throw new Error("script_outside_task_cwd");
      const relative = path.relative(cwd, script);
      invocation = scriptInvocation(relative, path.extname(script).toLowerCase(), args);
      integrityTarget = script;
      task = { type: "existing_script", script_path: script };
    }
    const relativeIntegrityTarget = path.relative(cwd, integrityTarget);
    const expectedHash = sha256(integrityTarget);
    const workspace = "/tmp/shellbridge-project";
    const copy = `(cd ${shellQuote(cwd)} && tar --ignore-failed-read -cf - . 2>/dev/null) | (mkdir -p ${workspace} && cd ${workspace} && tar -xf -)`;
    const check = `test "$(sha256sum ${shellQuote(path.join(workspace, relativeIntegrityTarget))} | cut -d' ' -f1)" = ${shellQuote(expectedHash)}`;
    const temporaryEnvironment = "mkdir -p /tmp/shellbridge-home/.cache /tmp/shellbridge-home/.npm /tmp/shellbridge-go/cache /tmp/shellbridge-go/path; export HOME=/tmp/shellbridge-home XDG_CACHE_HOME=/tmp/shellbridge-home/.cache npm_config_cache=/tmp/shellbridge-home/.npm GOCACHE=/tmp/shellbridge-go/cache GOPATH=/tmp/shellbridge-go/path SHELLBRIDGE_SANDBOXED_PROJECT_TASK=1";
    const execute = `cd ${workspace} && exec ${invocation.map(shellQuote).join(" ")}`;
    const command = `set -eu; ${temporaryEnvironment}; ${copy}; ${check}; ${execute}`;
    const started = Date.now();
    const result = await this.sandbox.run({
      command,
      cwd,
      timeoutMs: input.timeout_ms ?? PROJECT_TASK_TIMEOUT_DEFAULT_MS,
      maxOutputBytes: input.max_output_bytes ?? PROJECT_TASK_OUTPUT_DEFAULT_BYTES,
      profile: "project_task",
    });
    return {
      classification: "read_only",
      execution_channel: "sandboxed_project_task",
      status: result.exitCode === 0 ? "completed" : result.exitCode === 124 ? "timed_out" : "failed",
      task,
      cwd,
      integrity_hash: expectedHash,
      exit_code: result.exitCode,
      duration_ms: Date.now() - started,
      stdout: result.stdout,
      stderr: result.stderr,
      truncated: result.truncated,
      summary: {
        outcome: result.exitCode === 0 ? "passed" : result.exitCode === 124 ? "timed_out" : "failed",
        stdout_bytes: Buffer.byteLength(result.stdout),
        stderr_bytes: Buffer.byteLength(result.stderr),
      },
      host_changes_persisted: false,
    };
  }
}
