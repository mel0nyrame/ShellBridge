import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { ManagedPathPolicy, isInside } from "./path-policy.js";
import { PrivateKeyIndex } from "./root-read-view.js";

const MAX_GIT_OUTPUT = 64 * 1024 * 1024;
const ENV_EXAMPLE = /^\.env\.(?:example|sample|template)(?:\.|$)/i;

interface GitResult {
  stdout: Buffer;
  stderr: Buffer;
  status: number;
}

interface GitHeadState {
  branch: string;
  head: string | null;
  unborn: boolean;
  comparisonTree: string;
}

export interface GitCommitProposal {
  kind: "git_commit";
  repo: string;
  branch: string;
  head: string | null;
  unborn: boolean;
  initial_index_tree: string;
  initial_index_hash: string | null;
  repository_state_hash: string;
  target_index_tree: string;
  message: string;
  paths?: string[];
  all: boolean;
  files: Array<{ status: string; path: string }>;
  diff_stat: string;
  staged: Array<{ status: string; path: string }>;
  unstaged: Array<{ status: string; path: string }>;
  untracked: string[];
  content_summary: string[];
}

function fixedGitEnvironment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: "/nonexistent",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_OPTIONAL_LOCKS: "0",
    ...extra,
  };
}

function runGit(repo: string, args: string[], options: { env?: NodeJS.ProcessEnv; allowFailure?: boolean; input?: string | Buffer } = {}): GitResult {
  const result = spawnSync("git", [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "commit.gpgSign=false",
    "-c", "diff.external=",
    "-C", repo,
    ...args,
  ], {
    env: fixedGitEnvironment(options.env),
    encoding: null,
    maxBuffer: MAX_GIT_OUTPUT,
    shell: false,
    input: options.input,
  });
  if (result.error && result.status === null) throw new Error("git_unavailable");
  if (result.status !== 0 && !options.allowFailure) {
    const detail = result.stderr.toString("utf8").trim().split("\n")[0] ?? "";
    throw new Error(detail ? `git_failed:${detail}` : "git_failed");
  }
  return { stdout: result.stdout, stderr: result.stderr, status: result.status ?? 1 };
}

function emptyTree(repo: string): string {
  return runGit(repo, ["hash-object", "-t", "tree", "/dev/null"]).stdout.toString("utf8").trim();
}

function headState(repo: string): GitHeadState {
  const branchResult = runGit(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"], { allowFailure: true });
  const headResult = runGit(repo, ["rev-parse", "--verify", "HEAD^{commit}"], { allowFailure: true });
  if (headResult.status === 0) {
    const head = headResult.stdout.toString("utf8").trim();
    return {
      branch: branchResult.status === 0 ? branchResult.stdout.toString("utf8").trim() : "",
      head,
      unborn: false,
      comparisonTree: head,
    };
  }
  if (branchResult.status !== 0) throw new Error("git_head_unavailable");
  const branchRef = runGit(repo, ["symbolic-ref", "--quiet", "HEAD"]).stdout.toString("utf8").trim();
  const refResult = runGit(repo, ["show-ref", "--verify", "--quiet", branchRef], { allowFailure: true });
  if (refResult.status !== 1) throw new Error("git_repository_corrupt");
  return {
    branch: branchResult.stdout.toString("utf8").trim(),
    head: null,
    unborn: true,
    comparisonTree: emptyTree(repo),
  };
}

function parseStatus(raw: Buffer) {
  const entries: Array<{ index: string; worktree: string; path: string }> = [];
  const fields = raw.toString("utf8").split("\0");
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (!field) continue;
    const x = field[0] ?? " ";
    const y = field[1] ?? " ";
    const name = field.slice(3);
    entries.push({ index: x, worktree: y, path: name });
    if (x === "R" || x === "C") index += 1;
  }
  return entries;
}

function statusSummary(repo: string) {
  const raw = runGit(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]).stdout;
  const entries = parseStatus(raw);
  return {
    entries,
    staged: entries.filter((item) => item.index !== " " && item.index !== "?").map((item) => ({ status: item.index, path: item.path })),
    unstaged: entries.filter((item) => item.worktree !== " " && item.worktree !== "?").map((item) => ({ status: item.worktree, path: item.path })),
    untracked: entries.filter((item) => item.index === "?" && item.worktree === "?").map((item) => item.path),
    raw,
  };
}

function stateHash(repo: string, comparisonTree: string, paths: string[] | undefined, all: boolean): string {
  const status = statusSummary(repo);
  const selectedEntries = all ? status.entries : status.entries.filter((item) => (paths ?? []).some((selected) => (
    item.path === selected || item.path.startsWith(`${selected}${path.sep}`)
  )));
  const digest = crypto.createHash("sha256");
  digest.update(JSON.stringify(selectedEntries));
  digest.update(runGit(repo, [
    "diff", "--no-ext-diff", "--no-textconv", "--binary", comparisonTree, "--",
    ...(all ? [] : literalPaths(paths ?? [])),
  ]).stdout);
  const selectedUntracked = selectedEntries
    .filter((item) => item.index === "?" && item.worktree === "?")
    .map((item) => item.path);
  for (const relative of selectedUntracked.sort()) {
    const target = path.join(repo, relative);
    const metadata = fs.lstatSync(target);
    digest.update(relative);
    digest.update(`${metadata.mode}:${metadata.size}:`);
    if (metadata.isSymbolicLink()) digest.update(fs.readlinkSync(target));
    else if (metadata.isFile()) digest.update(fs.readFileSync(target));
  }
  return digest.digest("hex");
}

function normalizePaths(repo: string, requested: string[]): string[] {
  if (!Array.isArray(requested) || requested.length === 0 || requested.length > 500) throw new Error("invalid_git_paths");
  return [...new Set(requested.map((item) => {
    if (typeof item !== "string" || item.length === 0 || item.length > 4096 || item.includes("\0")) throw new Error("invalid_git_path");
    const absolute = path.resolve(repo, item);
    if (!isInside(absolute, repo)) throw new Error("git_path_outside_repository");
    const relative = path.relative(repo, absolute) || ".";
    if (relative === ".") throw new Error("git_repository_wide_path_requires_all");
    if (relative === ".git" || relative.startsWith(`.git${path.sep}`)) throw new Error("git_metadata_path_not_allowed");
    return relative;
  }))];
}

function literalPaths(paths: string[]): string[] {
  return paths.map((item) => `:(literal)${item}`);
}

function withTemporaryIndex<T>(repo: string, callback: (environment: NodeJS.ProcessEnv) => T): T {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "shellbridge-git-index-"));
  const indexPath = path.join(directory, "index");
  try {
    return callback({ GIT_INDEX_FILE: indexPath });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function repositoryIndexPath(repo: string): string {
  return path.resolve(repo, runGit(repo, ["rev-parse", "--git-path", "index"]).stdout.toString("utf8").trim());
}

function fileHash(target: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
}

function indexHash(target: string): string | null {
  try {
    return fileHash(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

function targetPlan(repo: string, comparisonTree: string, paths: string[] | undefined, all: boolean) {
  return withTemporaryIndex(repo, (env) => {
    runGit(repo, ["read-tree", comparisonTree], { env });
    if (all) runGit(repo, ["add", "-A", "--"], { env });
    else runGit(repo, ["add", "--", ...literalPaths(paths ?? [])], { env });
    const targetTree = runGit(repo, ["write-tree"], { env }).stdout.toString("utf8").trim();
    const names = runGit(repo, ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-status", "-z", comparisonTree, "--"], { env }).stdout.toString("utf8").split("\0");
    const files: Array<{ status: string; path: string }> = [];
    for (let index = 0; index + 1 < names.length; index += 2) {
      if (!names[index]) continue;
      files.push({ status: names[index]!, path: names[index + 1]! });
    }
    const diffStat = runGit(repo, ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--stat", comparisonTree, "--"], { env }).stdout.toString("utf8");
    return { targetTree, files, diffStat };
  });
}

export class GitService {
  private readonly policy: ManagedPathPolicy;
  private readonly privateKeys = new PrivateKeyIndex();

  constructor(root: string, blockedPaths: string[]) {
    this.policy = new ManagedPathPolicy(root, blockedPaths);
  }

  resolveRepository(requested: string): string {
    const candidate = this.policy.resolve(requested);
    const metadata = fs.lstatSync(candidate);
    if (!metadata.isDirectory()) throw new Error("git_repository_not_directory");
    const repository = runGit(candidate, ["rev-parse", "--show-toplevel"]).stdout.toString("utf8").trim();
    const canonical = fs.realpathSync(repository);
    this.policy.resolve(canonical);
    if (!isInside(canonical, this.policy.root)) throw new Error("git_repository_outside_operation_root");
    if (runGit(canonical, ["rev-parse", "--is-bare-repository"]).stdout.toString("utf8").trim() !== "false") {
      throw new Error("bare_repository_not_allowed");
    }
    const gitDirectory = path.resolve(canonical, runGit(canonical, ["rev-parse", "--git-dir"]).stdout.toString("utf8").trim());
    this.policy.resolve(gitDirectory);
    const executableFilters = runGit(canonical, ["config", "--local", "--name-only", "--get-regexp", "^filter\\..*\\.(clean|process)$"], { allowFailure: true }).stdout.toString("utf8").trim();
    if (executableFilters) throw new Error("git_executable_filter_not_allowed");
    return canonical;
  }

  private assertSafeFiles(repo: string, files: string[]): void {
    for (const relative of files) {
      const name = path.basename(relative);
      if ((name === ".env" || name.startsWith(".env.")) && !ENV_EXAMPLE.test(name)) {
        throw new Error("blocked_resource");
      }
      const target = this.policy.resolve(path.join(repo, relative));
      let metadata: fs.Stats;
      try { metadata = fs.lstatSync(target); } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      if (metadata.isFile() && this.privateKeys.classify(target, metadata)) throw new Error("blocked_resource");
    }
  }

  private changedFilesSelected(repo: string, paths: string[] | undefined, all: boolean): string[] {
    const changed = statusSummary(repo).entries.map((item) => item.path);
    if (all) return changed;
    return changed.filter((candidate) => (paths ?? []).some((selected) => (
      candidate === selected || candidate.startsWith(`${selected}${path.sep}`)
    )));
  }

  status(requestedRepo: string) {
    const repo = this.resolveRepository(requestedRepo);
    const currentHead = headState(repo);
    const summary = statusSummary(repo);
    return {
      repo,
      branch: currentHead.branch,
      head: currentHead.head,
      unborn: currentHead.unborn,
      staged: summary.staged,
      unstaged: summary.unstaged,
      untracked: summary.untracked,
      diff_stat: runGit(repo, ["diff", "--no-ext-diff", "--no-textconv", "--stat", currentHead.comparisonTree, "--"]).stdout.toString("utf8"),
    };
  }

  stage(input: { repo: string; paths?: string[]; all?: boolean }) {
    const repo = this.resolveRepository(input.repo);
    if (Boolean(input.all) === Boolean(input.paths)) throw new Error("specify_paths_or_all");
    const normalized = input.all ? undefined : normalizePaths(repo, input.paths ?? []);
    this.assertSafeFiles(repo, this.changedFilesSelected(repo, normalized, Boolean(input.all)));
    if (input.all) runGit(repo, ["add", "-A", "--"]);
    else runGit(repo, ["add", "--", ...literalPaths(normalized ?? [])]);
    return this.status(repo);
  }

  unstage(input: { repo: string; paths?: string[]; all?: boolean }) {
    const repo = this.resolveRepository(input.repo);
    if (Boolean(input.all) === Boolean(input.paths)) throw new Error("specify_paths_or_all");
    const paths = input.all ? [":/"] : literalPaths(normalizePaths(repo, input.paths ?? []));
    runGit(repo, ["restore", `--source=${headState(repo).comparisonTree}`, "--staged", "--", ...paths]);
    return this.status(repo);
  }

  prepareCommit(input: { repo: string; message: string; paths?: string[]; all?: boolean }): GitCommitProposal {
    const repo = this.resolveRepository(input.repo);
    if (typeof input.message !== "string" || input.message.trim().length === 0 || input.message.length > 1000 || input.message.includes("\0")) {
      throw new Error("invalid_commit_message");
    }
    if (Boolean(input.all) === Boolean(input.paths)) throw new Error("specify_paths_or_all");
    const paths = input.all ? undefined : normalizePaths(repo, input.paths ?? []);
    const currentHead = headState(repo);
    if (!currentHead.branch) throw new Error("detached_head_not_allowed");
    const initialIndexTree = runGit(repo, ["write-tree"]).stdout.toString("utf8").trim();
    const initialIndexHash = indexHash(repositoryIndexPath(repo));
    const currentStatus = statusSummary(repo);
    const target = targetPlan(repo, currentHead.comparisonTree, paths, Boolean(input.all));
    if (target.files.length === 0) throw new Error("nothing_to_commit");
    this.assertSafeFiles(repo, target.files.map((file) => file.path));
    const repositoryStateHash = stateHash(repo, currentHead.comparisonTree, paths, Boolean(input.all));
    return {
      kind: "git_commit",
      repo,
      branch: currentHead.branch,
      head: currentHead.head,
      unborn: currentHead.unborn,
      initial_index_tree: initialIndexTree,
      initial_index_hash: initialIndexHash,
      repository_state_hash: repositoryStateHash,
      target_index_tree: target.targetTree,
      message: input.message,
      ...(paths ? { paths } : {}),
      all: Boolean(input.all),
      files: target.files,
      diff_stat: target.diffStat,
      staged: currentStatus.staged,
      unstaged: currentStatus.unstaged,
      untracked: currentStatus.untracked,
      content_summary: target.files.map((file) => `${file.status} ${file.path}`),
    };
  }

  validateCommitProposal(proposal: GitCommitProposal): void {
    const repo = this.resolveRepository(proposal.repo);
    if (repo !== proposal.repo) throw new Error("git_repository_changed");
    const currentHead = headState(repo);
    if (currentHead.branch !== proposal.branch) throw new Error("git_branch_changed");
    if (currentHead.head !== proposal.head || currentHead.unborn !== proposal.unborn) throw new Error("git_head_changed");
    if (runGit(repo, ["write-tree"]).stdout.toString("utf8").trim() !== proposal.initial_index_tree) throw new Error("git_index_changed");
    if (indexHash(repositoryIndexPath(repo)) !== proposal.initial_index_hash) throw new Error("git_index_changed");
    if (stateHash(repo, currentHead.comparisonTree, proposal.paths, proposal.all) !== proposal.repository_state_hash) throw new Error("git_worktree_changed");
    const recreated = targetPlan(repo, currentHead.comparisonTree, proposal.paths, proposal.all);
    this.assertSafeFiles(repo, recreated.files.map((file) => file.path));
    if (recreated.targetTree !== proposal.target_index_tree
        || JSON.stringify(recreated.files) !== JSON.stringify(proposal.files)) throw new Error("git_commit_plan_changed");
  }

  executeCommit(proposal: GitCommitProposal) {
    this.validateCommitProposal(proposal);
    const repo = proposal.repo;
    const identity = {
      GIT_AUTHOR_NAME: "ShellBridge",
      GIT_AUTHOR_EMAIL: "shellbridge@localhost",
      GIT_COMMITTER_NAME: "ShellBridge",
      GIT_COMMITTER_EMAIL: "shellbridge@localhost",
    };
    const commitArguments = ["commit-tree", proposal.target_index_tree];
    if (proposal.head) commitArguments.push("-p", proposal.head);
    commitArguments.push("-m", proposal.message);
    const commit = runGit(repo, commitArguments, {
      env: identity,
    }).stdout.toString("utf8").trim();
    const indexPath = repositoryIndexPath(repo);
    this.policy.resolve(indexPath);
    const indexLock = `${indexPath}.lock`;
    const postIndexBytes = withTemporaryIndex(repo, (env) => {
      runGit(repo, ["read-tree", proposal.all ? proposal.target_index_tree : proposal.initial_index_tree], { env });
      if (!proposal.all) {
        runGit(repo, [
          "restore", `--source=${proposal.target_index_tree}`, "--staged", "--",
          ...literalPaths(proposal.paths ?? []),
        ], { env });
      }
      return fs.readFileSync(env.GIT_INDEX_FILE!);
    });
    let lockDescriptor: number | undefined;
    try {
      lockDescriptor = fs.openSync(indexLock, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
      if (indexHash(indexPath) !== proposal.initial_index_hash) throw new Error("git_index_changed");
      fs.writeFileSync(lockDescriptor, postIndexBytes);
      fs.fsyncSync(lockDescriptor);
      fs.closeSync(lockDescriptor);
      lockDescriptor = undefined;
      runGit(repo, ["update-ref", `refs/heads/${proposal.branch}`, commit, proposal.head ?? ""]);
      fs.renameSync(indexLock, indexPath);
    } finally {
      if (lockDescriptor !== undefined) fs.closeSync(lockDescriptor);
      try { fs.unlinkSync(indexLock); } catch { /* committed index lock was renamed */ }
    }
    if (runGit(repo, ["rev-parse", "HEAD"]).stdout.toString("utf8").trim() !== commit
        || runGit(repo, ["rev-parse", `${commit}^{tree}`]).stdout.toString("utf8").trim() !== proposal.target_index_tree) {
      throw new Error("git_commit_verification_failed");
    }
    const files = runGit(repo, ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", commit]).stdout.toString("utf8").trim().split("\n").filter(Boolean);
    return { commit, files, status: this.status(repo) };
  }
}
