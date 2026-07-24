import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { SCRIPT_RUN_OUTPUT_MAX_BYTES, SCRIPT_RUN_TIMEOUT_MAX_MS } from "./domain.js";
import { ManagedPathPolicy } from "./path-policy.js";
import { redactUntrustedExecutionOutput } from "./redactor.js";

export interface ExistingScriptProposal {
  kind: "existing_script_run";
  script_path: string;
  script_dev: number;
  script_ino: number;
  script_mode: number;
  script_hash: string;
  interpreter: string;
  args: string[];
  cwd: string;
  cwd_dev: number;
  cwd_ino: number;
  environment_profile: "minimal_host";
  impact_summary: string;
  timeout_ms: number;
  max_output_bytes: number;
}

function validateArgs(args: string[] | undefined): string[] {
  if (args === undefined) return [];
  if (!Array.isArray(args) || args.length > 100 || args.some((item) => typeof item !== "string" || item.length > 4096 || item.includes("\0"))) {
    throw new Error("invalid_script_arguments");
  }
  return args;
}

function interpreterFor(script: string, mode: number): string {
  const extension = path.extname(script).toLowerCase();
  if (extension === ".sh" || extension === ".bash") return "/bin/bash";
  if (extension === ".py") return "/usr/bin/python3";
  if ([".js", ".mjs", ".cjs"].includes(extension)) return process.execPath;
  if ((mode & 0o111) !== 0) return script;
  throw new Error("unsupported_script_interpreter");
}

function hashScript(script: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(script)).digest("hex");
}

function snapshotScript(sourceDescriptor: number, expectedHash: string): { descriptor: number; path: string } {
  const temporary = path.join("/tmp", `.shellbridge-script-${crypto.randomUUID()}`);
  const snapshotDescriptor = fs.openSync(
    temporary,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
    0o700,
  );
  try {
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    for (;;) {
      const count = fs.readSync(sourceDescriptor, buffer, 0, buffer.length, position);
      if (count === 0) break;
      const chunk = buffer.subarray(0, count);
      digest.update(chunk);
      fs.writeSync(snapshotDescriptor, chunk);
      position += count;
    }
    if (digest.digest("hex") !== expectedHash) throw new Error("script_changed");
    fs.fsyncSync(snapshotDescriptor);
    fs.fchmodSync(snapshotDescriptor, 0o700);
    return { descriptor: snapshotDescriptor, path: temporary };
  } catch (error) {
    fs.closeSync(snapshotDescriptor);
    try { fs.unlinkSync(temporary); } catch { /* cleanup best effort */ }
    throw error;
  }
}

function killGroup(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
}

export class ExistingScriptRunner {
  private readonly policy: ManagedPathPolicy;

  constructor(root: string, blockedPaths: string[]) {
    this.policy = new ManagedPathPolicy(root, blockedPaths);
  }

  prepare(input: {
    script_path: string;
    args?: string[];
    cwd?: string;
    impact_summary: string;
    timeout_ms?: number;
    max_output_bytes?: number;
  }): ExistingScriptProposal {
    const script = this.policy.resolve(input.script_path);
    const metadata = fs.lstatSync(script);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("script_not_regular_file");
    const cwd = this.policy.resolve(input.cwd ?? path.dirname(script));
    const cwdMetadata = fs.lstatSync(cwd);
    if (cwdMetadata.isSymbolicLink() || !cwdMetadata.isDirectory()) throw new Error("script_cwd_not_directory");
    if (typeof input.impact_summary !== "string" || input.impact_summary.trim().length < 4 || input.impact_summary.length > 1000 || input.impact_summary.includes("\0")) {
      throw new Error("invalid_impact_summary");
    }
    const timeout = input.timeout_ms ?? 5 * 60_000;
    const output = input.max_output_bytes ?? 256 * 1024;
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > SCRIPT_RUN_TIMEOUT_MAX_MS) throw new Error("invalid_timeout");
    if (!Number.isInteger(output) || output < 1 || output > SCRIPT_RUN_OUTPUT_MAX_BYTES) throw new Error("invalid_output_limit");
    return {
      kind: "existing_script_run",
      script_path: script,
      script_dev: metadata.dev,
      script_ino: metadata.ino,
      script_mode: metadata.mode,
      script_hash: hashScript(script),
      interpreter: interpreterFor(script, metadata.mode),
      args: validateArgs(input.args),
      cwd,
      cwd_dev: cwdMetadata.dev,
      cwd_ino: cwdMetadata.ino,
      environment_profile: "minimal_host",
      impact_summary: input.impact_summary,
      timeout_ms: timeout,
      max_output_bytes: output,
    };
  }

  validate(proposal: ExistingScriptProposal): void {
    const script = this.policy.resolve(proposal.script_path);
    if (script !== proposal.script_path) throw new Error("script_path_changed");
    const metadata = fs.lstatSync(script);
    if (!metadata.isFile() || metadata.isSymbolicLink()
        || metadata.dev !== proposal.script_dev || metadata.ino !== proposal.script_ino
        || metadata.mode !== proposal.script_mode || hashScript(script) !== proposal.script_hash
        || interpreterFor(script, metadata.mode) !== proposal.interpreter) {
      throw new Error("script_changed");
    }
    const cwd = this.policy.resolve(proposal.cwd);
    const cwdMetadata = fs.lstatSync(cwd);
    if (cwd !== proposal.cwd || cwdMetadata.isSymbolicLink() || !cwdMetadata.isDirectory()
        || cwdMetadata.dev !== proposal.cwd_dev || cwdMetadata.ino !== proposal.cwd_ino) throw new Error("script_cwd_changed");
    if (proposal.environment_profile !== "minimal_host") throw new Error("script_environment_changed");
  }

  async execute(proposal: ExistingScriptProposal) {
    this.validate(proposal);
    const sourceDescriptor = fs.openSync(proposal.script_path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const cwdDescriptor = fs.openSync(proposal.cwd, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const openedScript = fs.fstatSync(sourceDescriptor);
    const openedCwd = fs.fstatSync(cwdDescriptor);
    if (openedScript.dev !== proposal.script_dev || openedScript.ino !== proposal.script_ino
        || openedScript.mode !== proposal.script_mode || openedCwd.dev !== proposal.cwd_dev || openedCwd.ino !== proposal.cwd_ino) {
      fs.closeSync(sourceDescriptor);
      fs.closeSync(cwdDescriptor);
      throw new Error("script_changed");
    }
    let scriptDescriptor: number;
    let snapshotPath: string;
    try {
      const snapshot = snapshotScript(sourceDescriptor, proposal.script_hash);
      scriptDescriptor = snapshot.descriptor;
      snapshotPath = snapshot.path;
    } finally {
      fs.closeSync(sourceDescriptor);
    }
    const fixedScriptPath = "/proc/self/fd/3";
    const executable = proposal.interpreter === proposal.script_path ? fixedScriptPath : proposal.interpreter;
    const args = proposal.interpreter === proposal.script_path
      ? proposal.args
      : [fixedScriptPath, ...proposal.args];
    const started = Date.now();
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, args, {
        cwd: `/proc/self/fd/${cwdDescriptor}`,
        detached: true,
        shell: false,
        env: {
          PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          HOME: "/nonexistent",
          LANG: "C.UTF-8",
          LC_ALL: "C.UTF-8",
          SHELLBRIDGE_EXECUTION_PROFILE: "minimal_host",
        },
        stdio: ["ignore", "pipe", "pipe", scriptDescriptor],
      });
    } catch (error) {
      fs.closeSync(scriptDescriptor);
      fs.closeSync(cwdDescriptor);
      try { fs.unlinkSync(snapshotPath!); } catch { /* cleanup best effort */ }
      throw error;
    }
    fs.closeSync(scriptDescriptor);
    fs.closeSync(cwdDescriptor);
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let truncated = false;
    const capture = (destination: Buffer[]) => (chunk: Buffer) => {
      if (bytes < proposal.max_output_bytes) {
        const available = proposal.max_output_bytes - bytes;
        destination.push(chunk.subarray(0, available));
      }
      bytes += chunk.length;
      if (bytes > proposal.max_output_bytes) truncated = true;
    };
    child.stdout!.on("data", capture(stdout));
    child.stderr!.on("data", capture(stderr));
    const exit = new Promise<{ code: number; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once("error", () => reject(new Error("script_spawn_failed")));
      child.once("exit", (code, signal) => resolve({ code: code ?? 1, signal }));
    });
    const timer = setTimeout(() => killGroup(child), proposal.timeout_ms);
    try {
      const result = await exit;
      return {
        classification: "approval_required",
        execution_channel: "existing_script",
        status: result.signal === "SIGKILL" ? "timed_out" : result.code === 0 ? "completed" : "failed",
        exit_code: result.code,
        signal: result.signal,
        duration_ms: Date.now() - started,
        stdout: redactUntrustedExecutionOutput(Buffer.concat(stdout).toString("utf8"), proposal.args),
        stderr: redactUntrustedExecutionOutput(Buffer.concat(stderr).toString("utf8"), proposal.args),
        truncated,
      };
    } finally {
      clearTimeout(timer);
      try { fs.unlinkSync(snapshotPath); } catch { /* cleanup best effort */ }
    }
  }
}
