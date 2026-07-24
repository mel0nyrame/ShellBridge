import { spawn, type ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { mkdir, readFile, rmdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { redact } from "./redactor.js";
import { createRootReadViewPlan, PrivateKeyIndex, type RootViewEntry } from "./root-read-view.js";

interface SandboxedShellOptions {
  helperPath: string;
  seccompPath: string;
  bwrapPath: string;
  readRoots: string[];
  blockedPaths: string[];
  observerUid: number;
  observerGid: number;
  cgroupRoot: string;
  requireCgroup: boolean;
}

export interface SandboxedShellResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  truncated: boolean;
}

export type SandboxProfile = "diagnostic" | "project_task";

const runtimeSources = [
  "/usr",
  "/opt/node-v22.11.0-linux-x64",
  "/etc/ld.so.cache",
  "/etc/passwd",
  "/etc/group",
  "/etc/nsswitch.conf",
  "/etc/hosts",
  "/etc/localtime",
  "/etc/alternatives",
];

function inside(target: string, root: string): boolean {
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function resolveBlockedPaths(targets: string[]): string[] {
  return targets.map((target) => {
    const resolved = path.resolve(target);
    try { return fs.realpathSync(resolved); } catch { return resolved; }
  });
}

function validateRootFd(helperPath: string, rootFd: number, parentFd: number, filesystemFd: number, rootName: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(helperPath, ["validate-tree-fd", rootName], {
      env: {},
      stdio: ["ignore", "ignore", "pipe", rootFd, parentFd, filesystemFd],
    });
    let stderrBytes = 0;
    child.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 16 * 1024) child.kill("SIGKILL");
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("error", () => {
      clearTimeout(timer);
      reject(new Error("sandbox_root_validation_failed"));
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error("sandbox_root_validation_failed"));
    });
  });
}

function validateRuntimeDisjointFds(
  helperPath: string,
  runtimeFds: number[],
  blockedFds: number[],
  timeoutMs: number,
): Promise<void> {
  if (runtimeFds.length === 0 || blockedFds.length === 0) return Promise.reject(new Error("sandbox_runtime_validation_failed"));
  return new Promise((resolve, reject) => {
    const child = spawn(
      helperPath,
      ["validate-disjoint-fds", String(runtimeFds.length), String(blockedFds.length)],
      { env: {}, stdio: ["ignore", "ignore", "pipe", ...runtimeFds, ...blockedFds] },
    );
    let settled = false;
    let timer: NodeJS.Timeout;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    child.once("error", () => finish(new Error("sandbox_runtime_validation_failed")));
    child.once("exit", (code) => finish(code === 0 ? undefined : new Error("sandbox_runtime_validation_failed")));
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("sandbox_runtime_validation_failed"));
    }, timeoutMs);
  });
}

function directoryArguments(target: string): string[] {
  const parts = target.split(path.sep).filter(Boolean);
  const result: string[] = [];
  let current = "";
  for (const part of parts) {
    current += `/${part}`;
    result.push("--dir", current);
  }
  return result;
}

async function configureCgroup(root: string, pid: number, profile: SandboxProfile): Promise<string> {
  try { await writeFile(path.join(root, "cgroup.subtree_control"), "+cpu +memory +pids"); } catch {
    throw new Error("cgroup_controllers_failed");
  }
  const job = path.join(root, `job-${pid}-${crypto.randomUUID()}`);
  try { await mkdir(job, { mode: 0o700 }); } catch { throw new Error("cgroup_create_failed"); }
  try {
    try { await writeFile(path.join(job, "memory.max"), profile === "project_task" ? "2147483648" : "268435456"); } catch { throw new Error("cgroup_memory_failed"); }
    try { await writeFile(path.join(job, "pids.max"), profile === "project_task" ? "512" : "64"); } catch { throw new Error("cgroup_pids_failed"); }
    try { await writeFile(path.join(job, "cpu.max"), profile === "project_task" ? "200000 100000" : "100000 100000"); } catch { throw new Error("cgroup_cpu_failed"); }
    try { await writeFile(path.join(job, "cgroup.procs"), String(pid)); } catch { throw new Error("cgroup_attach_failed"); }
    let membership: string;
    try { membership = await readFile(`/proc/${pid}/cgroup`, "utf8"); } catch { throw new Error("cgroup_membership_failed"); }
    if (!membership.includes(path.basename(job))) throw new Error("cgroup_membership_failed");
    return job;
  } catch (error) {
    await cleanupCgroup(job);
    throw error;
  }
}

async function cleanupCgroup(job: string | undefined): Promise<void> {
  if (!job) return;
  await writeFile(path.join(job, "cgroup.kill"), "1").catch(() => undefined);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await rmdir(job);
      return;
    } catch {
      if (attempt < 4) await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

function killGroup(child: ChildProcess): void {
  if (!child.pid) return;
  try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
}

export class SandboxedShell {
  private readonly roots: string[];
  private readonly blocked: string[];
  private readonly canonicalBlocked: string[];
  private readonly privateKeyIndexes = new Map<string, PrivateKeyIndex>();

  constructor(private readonly options: SandboxedShellOptions) {
    if (!Number.isInteger(options.observerUid) || !Number.isInteger(options.observerGid)
        || options.observerUid <= 0 || options.observerGid <= 0) throw new Error("invalid_observer_identity");
    this.roots = options.readRoots.map((root) => fs.realpathSync(root));
    this.blocked = options.blockedPaths.map((target) => path.resolve(target));
    this.canonicalBlocked = resolveBlockedPaths(this.blocked);
    for (const root of this.roots) {
      if (this.canonicalBlocked.some((target) => inside(root, target))) {
        throw new Error("sandbox_root_overlaps_blocked_path");
      }
    }
    for (const source of runtimeSources.filter((item) => fs.existsSync(item))) {
      const canonical = fs.realpathSync(source);
      if (this.canonicalBlocked.some((target) => inside(canonical, target) || inside(target, canonical))) {
        throw new Error("sandbox_runtime_overlaps_blocked_path");
      }
      const sourceMetadata = fs.statSync(canonical);
      for (const target of this.canonicalBlocked) {
        try {
          const targetMetadata = fs.statSync(target);
          if (sourceMetadata.dev === targetMetadata.dev && sourceMetadata.ino === targetMetadata.ino) {
            throw new Error("sandbox_runtime_overlaps_blocked_path");
          }
        } catch (error) {
          if (error instanceof Error && error.message === "sandbox_runtime_overlaps_blocked_path") throw error;
        }
      }
    }
  }

  async initialize(timeoutMs = 60_000): Promise<void> {
    const deadlineMs = Date.now() + timeoutMs;
    for (const root of this.roots) {
      const rootFd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const parentFd = fs.openSync(path.dirname(root), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const filesystemFd = fs.openSync("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      try {
        const remainingMs = deadlineMs - Date.now();
        if (remainingMs <= 0) throw new Error("sandbox_private_key_scan_failed");
        await validateRootFd(
          this.options.helperPath,
          rootFd,
          parentFd,
          filesystemFd,
          path.basename(root),
          Math.min(remainingMs, 15_000),
        );
        const canonicalBlocked = resolveBlockedPaths(this.blocked);
        const index = this.privateKeyIndexes.get(root) ?? new PrivateKeyIndex();
        this.privateKeyIndexes.set(root, index);
        createRootReadViewPlan(root, [...this.blocked, ...canonicalBlocked], { index, deadlineMs });
      } finally {
        fs.closeSync(filesystemFd);
        fs.closeSync(parentFd);
        fs.closeSync(rootFd);
      }
    }
  }

  async run(request: { command: string; cwd: string; timeoutMs: number; maxOutputBytes: number; profile?: SandboxProfile }): Promise<SandboxedShellResult> {
    const profile = request.profile ?? "diagnostic";
    const timeoutMaximum = profile === "project_task" ? 10 * 60_000 : 60_000;
    const outputMaximum = profile === "project_task" ? 1024 * 1024 : 128 * 1024;
    if (typeof request.command !== "string" || request.command.length === 0 || request.command.length > (profile === "project_task" ? 16 * 1024 : 4096) || request.command.includes("\0")) {
      throw new Error("invalid_command");
    }
    if (!Number.isInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > timeoutMaximum) throw new Error("invalid_timeout");
    if (!Number.isInteger(request.maxOutputBytes) || request.maxOutputBytes < 1 || request.maxOutputBytes > outputMaximum) throw new Error("invalid_output_limit");
    const deadlineMs = Date.now() + request.timeoutMs;
    const cwd = fs.realpathSync(request.cwd);
    const root = this.roots.find((candidate) => inside(cwd, candidate));
    if (!root) throw new Error("cwd_outside_sandbox_roots");
    const canonicalBlocked = resolveBlockedPaths(this.blocked);
    if (canonicalBlocked.some((target) => inside(root, target))) {
      throw new Error("sandbox_root_overlaps_blocked_path");
    }
    if (canonicalBlocked.some((target) => inside(cwd, target))) throw new Error("cwd_outside_sandbox_roots");
    const openedFds: number[] = [];
    const trackedOpen = (target: string, flags: number) => {
      const descriptor = fs.openSync(target, flags);
      openedFds.push(descriptor);
      return descriptor;
    };
    let child: ChildProcess;
    try {
      const hostNet = fs.statSync("/proc/self/ns/net").ino;
      const hostPid = fs.statSync("/proc/self/ns/pid").ino;
      const seccompFd = trackedOpen(this.options.seccompPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const rootFd = trackedOpen(root, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const rootParent = path.dirname(root);
      const parentFd = trackedOpen(rootParent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const filesystemFd = trackedOpen("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      const helperFd = trackedOpen(this.options.helperPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      await validateRootFd(
        this.options.helperPath,
        rootFd,
        parentFd,
        filesystemFd,
        path.basename(root),
        Math.max(1, Math.min(deadlineMs - Date.now(), 15_000)),
      );
      const privateKeyIndex = this.privateKeyIndexes.get(root) ?? new PrivateKeyIndex();
      this.privateKeyIndexes.set(root, privateKeyIndex);
      const viewPlan = createRootReadViewPlan(
        root,
        [...this.blocked, ...canonicalBlocked],
        { index: privateKeyIndex, deadlineMs },
      );
      const runtimeBindings = runtimeSources.flatMap((source) => {
        if (!fs.existsSync(source)) return [];
        const canonical = fs.realpathSync(source);
        const fd = trackedOpen(canonical, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
          | (fs.statSync(canonical).isDirectory() ? fs.constants.O_DIRECTORY : 0));
        return [{ fd, target: source }];
      });
      const rewrittenBindings: Array<{ fd: number; entry: RootViewEntry }> = [];
      for (const rewrite of viewPlan.rewrites) {
        for (const entry of rewrite.entries) {
          const current = fs.lstatSync(entry.source);
          if (BigInt(current.dev) !== entry.device || BigInt(current.ino) !== entry.inode
              || (entry.kind === "symlink" && fs.readlinkSync(entry.source) !== entry.linkTarget)) {
            throw new Error("sandbox_root_changed");
          }
          if (entry.kind === "symlink") continue;
          const fd = trackedOpen(
            entry.source,
            fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
              | (entry.kind === "directory" ? fs.constants.O_DIRECTORY : 0),
          );
          const opened = fs.fstatSync(fd);
          if (BigInt(opened.dev) !== entry.device || BigInt(opened.ino) !== entry.inode) {
            throw new Error("sandbox_root_changed");
          }
          rewrittenBindings.push({
            fd,
            entry,
          });
        }
      }
      const blockedFileBindings = viewPlan.masks.flatMap(({ target, kind }) => {
        if (kind === "directory") return [];
        return [{ fd: trackedOpen("/dev/null", fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW), target }];
      });
      const blockedFds = canonicalBlocked.flatMap((target) => {
        if (!fs.existsSync(target)) return [];
        const canonical = fs.realpathSync(target);
        const metadata = fs.statSync(canonical);
        if (!metadata.isFile() && !metadata.isDirectory()) return [];
        return [trackedOpen(
          canonical,
          fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
            | (metadata.isDirectory() ? fs.constants.O_DIRECTORY : 0),
        )];
      });
      await validateRuntimeDisjointFds(
        this.options.helperPath,
        runtimeBindings.map(({ fd }) => fd),
        blockedFds,
        Math.max(1, Math.min(deadlineMs - Date.now(), 15_000)),
      );
      const args = [
        "--unshare-all", "--unshare-user",
        ...(profile === "diagnostic" ? ["--disable-userns", "--assert-userns-disabled"] : []),
        "--uid", String(this.options.observerUid), "--gid", String(this.options.observerGid),
        "--cap-drop", "ALL", "--die-with-parent", "--new-session", "--hostname", "shellbridge-sandbox",
        "--clearenv", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/nonexistent", "--setenv", "LANG", "C.UTF-8", "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "TMPDIR", "/tmp",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev",
        "--dir", "/etc", "--dir", "/opt",
      ];
      runtimeBindings.forEach((binding, index) => args.push("--ro-bind-fd", String(7 + index), binding.target));
      args.push("--size", profile === "project_task" ? "1073741824" : "16777216", "--tmpfs", "/tmp", "--chmod", "1777", "/tmp");
      args.push(...directoryArguments(root));
      args.push("--ro-bind-fd", "5", root);
      for (const rewrite of viewPlan.rewrites) {
        args.push("--tmpfs", rewrite.target, "--chmod", "755", rewrite.target);
        for (const entry of rewrite.entries) {
          if (entry.kind === "symlink") {
            args.push("--symlink", entry.linkTarget!, entry.target);
            continue;
          }
          const bindingIndex = rewrittenBindings.findIndex((binding) => binding.entry === entry);
          if (bindingIndex < 0) throw new Error("sandbox_root_changed");
          args.push("--ro-bind-fd", String(7 + runtimeBindings.length + bindingIndex), entry.target);
        }
        args.push("--remount-ro", rewrite.target);
      }
      for (const { target, kind } of viewPlan.masks) {
        if (kind === "directory") args.push("--tmpfs", target, "--chmod", "000", target);
      }
      blockedFileBindings.forEach((binding, index) => {
        args.push(
          "--perms", "000", "--ro-bind-data",
          String(7 + runtimeBindings.length + rewrittenBindings.length + index),
          binding.target,
        );
      });
      args.push("--dir", "/opt", "--dir", "/opt/shellbridge", "--ro-bind-fd", "6", "/opt/shellbridge/sandbox-init");
      args.push("--seccomp", "4", "--chdir", cwd);
      args.push(
        "--", "/opt/shellbridge/sandbox-init", "sandbox-init",
        String(this.options.observerUid), String(this.options.observerGid),
        String(hostNet), String(hostPid),
        profile === "project_task" ? "600" : "10",
        profile === "project_task" ? "68719476736" : "2147483648",
        profile === "project_task" ? "1024" : "64",
        profile === "project_task" ? "1073741824" : "1048576",
        profile === "project_task" ? "256" : "64",
        request.command,
      );

      child = spawn(this.options.helperPath, ["cgroup-exec", this.options.bwrapPath, "--", ...args], {
        detached: true,
        env: {},
        stdio: [
          "ignore", "pipe", "pipe", "pipe", seccompFd, rootFd, helperFd,
          ...runtimeBindings.map(({ fd }) => fd),
          ...rewrittenBindings.map(({ fd }) => fd),
          ...blockedFileBindings.map(({ fd }) => fd),
        ],
      });
    } catch (error) {
      if (Date.now() >= deadlineMs) throw new Error("sandbox_timeout");
      throw error;
    } finally {
      openedFds.forEach((descriptor) => {
        try { fs.closeSync(descriptor); } catch { /* already closed */ }
      });
    }
    const spawned = new Promise<void>((resolve, reject) => {
      child.once("spawn", resolve);
      child.once("error", () => reject(new Error("sandbox_spawn_failed")));
    });
    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null; spawnFailed?: true }>((resolve) => {
      child.once("error", () => resolve({ code: null, signal: null, spawnFailed: true }));
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let outputBytes = 0;
    let outputExceeded = false;
    const capture = (destination: Buffer[]) => (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > request.maxOutputBytes) {
        outputExceeded = true;
        if (profile === "diagnostic") killGroup(child);
        return;
      }
      destination.push(chunk);
    };
    child.stdout?.on("data", capture(stdout));
    child.stderr?.on("data", capture(stderr));

    let cgroupJob: string | undefined;
    try {
      await spawned;
      if (!Number.isInteger(child.pid) || Number(child.pid) <= 0) throw new Error("sandbox_pid_unavailable");
      if (this.options.requireCgroup) {
        cgroupJob = await configureCgroup(this.options.cgroupRoot, Number(child.pid), profile);
      }
      const blocker = child.stdio[3];
      if (!blocker || typeof (blocker as NodeJS.WritableStream).write !== "function") throw new Error("sandbox_blocker_unavailable");
      (blocker as NodeJS.WritableStream).write(Buffer.from([1]));
      (blocker as NodeJS.WritableStream).end();
    } catch (error) {
      killGroup(child);
      await exited;
      await cleanupCgroup(cgroupJob);
      const errno = error && typeof error === "object" && "code" in error ? String((error as NodeJS.ErrnoException).code) : "";
      const reason = error instanceof Error && /^[a-z_]+$/.test(error.message)
        ? error.message
        : /^[A-Z_]+$/.test(errno) ? errno.toLowerCase() : "sandbox_setup_failed";
      throw new Error(`sandbox_unavailable:${reason}`);
    }

    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) {
      killGroup(child);
      await exited;
      await cleanupCgroup(cgroupJob);
      throw new Error("sandbox_timeout");
    }
    const timer = setTimeout(() => killGroup(child), remainingMs);
    let exit: Awaited<typeof exited>;
    try {
      exit = await exited;
    } finally {
      clearTimeout(timer);
      await cleanupCgroup(cgroupJob);
    }

    const stdoutText = redact(Buffer.concat(stdout).toString("utf8"));
    const stderrText = redact(Buffer.concat(stderr).toString("utf8"));
    if (outputExceeded && profile === "diagnostic") throw new Error("sandbox_output_limit_exceeded");
    if (exit.spawnFailed) throw new Error("sandbox_unavailable");
    if (exit.signal === "SIGKILL" && profile === "diagnostic") throw new Error("sandbox_timeout");
    if (stderrText.includes("shellbridge_helper:") || stderrText.startsWith("bwrap:")) throw new Error("sandbox_unavailable");
    return { stdout: stdoutText, stderr: stderrText, exitCode: exit.signal === "SIGKILL" ? 124 : exit.code ?? 1, truncated: outputExceeded };
  }
}
