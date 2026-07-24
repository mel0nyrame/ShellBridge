import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, test } from "vitest";
import { createTestApp, type TestApp } from "./support/test-app.js";

const execFileAsync = promisify(execFile);
const apps: TestApp[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function createUnbornRepository(files: Record<string, string> = {}) {
  const app = await createTestApp({ files });
  apps.push(app);
  await execFileAsync("git", ["init", "-b", "main"], { cwd: app.fixtureDir });
  return app;
}

async function commitAll(
  app: TestApp,
  message: string,
  identity = { name: "History Writer", email: "history@example.test" },
) {
  await execFileAsync("git", ["add", "-A"], { cwd: app.fixtureDir });
  await execFileAsync("git", [
    "-c", `user.name=${identity.name}`,
    "-c", `user.email=${identity.email}`,
    "commit", "-m", message,
  ], { cwd: app.fixtureDir });
}

describe("local Git transactions", () => {
  test("reports an unborn branch and its untracked files", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n" });

    const response = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({
      status: "completed",
      branch: "main",
      head: null,
      unborn: true,
      staged: [],
      unstaged: [],
      untracked: ["README.md"],
    });
  });

  test("rejects a branch ref that points to a missing object instead of treating it as unborn", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n" });
    await (await import("node:fs/promises")).writeFile(
      path.join(app.fixtureDir, ".git", "refs", "heads", "main"),
      `${"1".repeat(40)}\n`,
      "utf8",
    );

    const response = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({ error: "git_repository_corrupt" });
  });

  test("stages and unstages files on an unborn branch without changing the worktree", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n", "notes.txt": "notes\n" });

    const staged = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/stage",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, paths: ["README.md", "notes.txt"] },
    });
    expect(staged.statusCode, staged.body).toBe(200);
    expect(staged.json()).toMatchObject({
      head: null,
      unborn: true,
      staged: [
        { status: "A", path: "README.md" },
        { status: "A", path: "notes.txt" },
      ],
      untracked: [],
    });

    const unstaged = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/unstage",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, paths: ["README.md", "notes.txt"] },
    });
    expect(unstaged.statusCode, unstaged.body).toBe(200);
    expect(unstaged.json()).toMatchObject({
      head: null,
      unborn: true,
      staged: [],
      untracked: ["README.md", "notes.txt"],
    });
    await expect((await import("node:fs/promises")).readFile(path.join(app.fixtureDir, "README.md"), "utf8")).resolves.toBe("hello\n");
    await expect((await import("node:fs/promises")).readFile(path.join(app.fixtureDir, "notes.txt"), "utf8")).resolves.toBe("notes\n");
  });

  test("prepares and executes an immutable root commit", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n" });
    const commitMessage = "Create initial archive\n\nRecord the first file.";

    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: commitMessage, paths: ["README.md"] },
    });
    expect(prepared.statusCode, prepared.body).toBe(202);
    expect(prepared.json().proposal).toMatchObject({
      kind: "git_commit",
      branch: "main",
      head: null,
      unborn: true,
      message: commitMessage,
      files: [{ status: "A", path: "README.md" }],
    });

    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode, executed.body).toBe(200);
    expect(executed.json()).toMatchObject({
      status: "completed",
      files: ["A\tREADME.md"],
    });
    expect(executed.json().commit).toMatch(/^[a-f0-9]{40,64}$/);
    const status = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(status.json()).toMatchObject({ head: executed.json().commit, unborn: false });
    const revision = await execFileAsync("git", ["rev-list", "--parents", "-n", "1", "HEAD"], { cwd: app.fixtureDir });
    expect(revision.stdout.trim().split(/\s+/)).toHaveLength(1);
    const message = await execFileAsync("git", ["log", "-1", "--format=%B"], { cwd: app.fixtureDir });
    expect(message.stdout.trim()).toBe(commitMessage);
    const identity = await execFileAsync("git", ["log", "-1", "--format=%an <%ae>|%cn <%ce>"], { cwd: app.fixtureDir });
    expect(identity.stdout.trim()).toBe("ShellBridge <shellbridge@localhost>|ShellBridge <shellbridge@localhost>");
    const committedFiles = await execFileAsync("git", ["diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "HEAD"], { cwd: app.fixtureDir });
    expect(committedFiles.stdout.trim()).toBe("README.md");
  });

  test("rejects an unborn proposal if another process creates the first commit", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n" });
    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: "Stale initial commit", all: true },
    });
    expect(prepared.statusCode, prepared.body).toBe(202);

    await commitAll(app, "External initial commit", { name: "External Writer", email: "external@example.test" });

    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode).toBe(409);
    expect(executed.json()).toEqual({ error: "git_head_changed" });
    const count = await execFileAsync("git", ["rev-list", "--count", "HEAD"], { cwd: app.fixtureDir });
    expect(count.stdout.trim()).toBe("1");
  });

  test("stages and unstages all files on an unborn branch", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n", "notes.txt": "notes\n" });
    const staged = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/stage",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, all: true },
    });
    expect(staged.statusCode, staged.body).toBe(200);
    expect(staged.json().staged).toEqual([
      { status: "A", path: "README.md" },
      { status: "A", path: "notes.txt" },
    ]);

    const unstaged = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/unstage",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, all: true },
    });
    expect(unstaged.statusCode, unstaged.body).toBe(200);
    expect(unstaged.json()).toMatchObject({ staged: [], untracked: ["README.md", "notes.txt"] });
  });

  test("rejects an unborn proposal if the index changes after preparation", async () => {
    const app = await createUnbornRepository({ "README.md": "hello\n" });
    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: "Initial commit", all: true },
    });
    expect(prepared.statusCode, prepared.body).toBe(202);
    await execFileAsync("git", ["add", "README.md"], { cwd: app.fixtureDir });

    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode).toBe(409);
    expect(executed.json()).toEqual({ error: "git_index_changed" });
    const status = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(status.json()).toMatchObject({ head: null, unborn: true });
  });

  test("preserves the normal commit flow in a repository with history", async () => {
    const app = await createUnbornRepository({ "README.md": "first\n" });
    await commitAll(app, "First commit");
    await (await import("node:fs/promises")).writeFile(path.join(app.fixtureDir, "README.md"), "second\n", "utf8");

    const changed = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(changed.json()).toMatchObject({ staged: [], unstaged: [{ status: "M", path: "README.md" }] });
    const staged = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/stage",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, paths: ["README.md"] },
    });
    expect(staged.json()).toMatchObject({ staged: [{ status: "M", path: "README.md" }], unstaged: [] });
    const unstaged = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/unstage",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, paths: ["README.md"] },
    });
    expect(unstaged.json()).toMatchObject({ staged: [], unstaged: [{ status: "M", path: "README.md" }] });

    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: "Second commit", paths: ["README.md"] },
    });
    expect(prepared.statusCode, prepared.body).toBe(202);
    expect(prepared.json().proposal).toMatchObject({ unborn: false, files: [{ status: "M", path: "README.md" }] });
    expect(prepared.json().proposal.head).toMatch(/^[a-f0-9]{40,64}$/);

    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode, executed.body).toBe(200);
    expect(executed.json()).toMatchObject({ status: "completed", files: ["M\tREADME.md"] });
    const count = await execFileAsync("git", ["rev-list", "--count", "HEAD"], { cwd: app.fixtureDir });
    expect(count.stdout.trim()).toBe("2");
  });

  test("reports an empty unborn repository and refuses an empty commit", async () => {
    const app = await createUnbornRepository();
    const status = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(status.statusCode, status.body).toBe(200);
    expect(status.json()).toMatchObject({
      branch: "main",
      head: null,
      unborn: true,
      staged: [],
      unstaged: [],
      untracked: [],
    });

    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: "Empty commit", all: true },
    });
    expect(prepared.statusCode).toBe(400);
    expect(prepared.json()).toEqual({ error: "nothing_to_commit" });
  });

  test("rejects an unborn proposal if selected worktree content changes", async () => {
    const app = await createUnbornRepository({ "README.md": "first\n" });
    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: "Initial commit", paths: ["README.md"] },
    });
    expect(prepared.statusCode, prepared.body).toBe(202);
    await (await import("node:fs/promises")).writeFile(path.join(app.fixtureDir, "README.md"), "second\n", "utf8");

    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode).toBe(409);
    expect(executed.json()).toEqual({ error: "git_worktree_changed" });
  });

  test("keeps detached HEAD readable but rejects commit preparation", async () => {
    const app = await createUnbornRepository({ "README.md": "first\n" });
    await commitAll(app, "First commit");
    await execFileAsync("git", ["checkout", "--detach"], { cwd: app.fixtureDir });
    await (await import("node:fs/promises")).writeFile(path.join(app.fixtureDir, "README.md"), "second\n", "utf8");

    const status = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(status.statusCode, status.body).toBe(200);
    expect(status.json()).toMatchObject({ branch: "", unborn: false });
    expect(status.json().head).toMatch(/^[a-f0-9]{40,64}$/);

    const prepared = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/commits/prepare",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir, message: "Detached commit", all: true },
    });
    expect(prepared.statusCode).toBe(403);
    expect(prepared.json()).toEqual({ error: "detached_head_not_allowed" });
  });

  test("continues to reject non-repositories and symbolic-link repository paths", async () => {
    const nonRepository = await createTestApp();
    apps.push(nonRepository);
    const invalid = await nonRepository.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: nonRepository.authHeaders,
      payload: { repo: nonRepository.fixtureDir },
    });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.json()).toEqual({ error: "operation_failed" });

    const app = await createUnbornRepository({ "README.md": "hello\n" });
    const alias = path.join(path.dirname(app.fixtureDir), "repository-link");
    await (await import("node:fs/promises")).symlink(app.fixtureDir, alias);
    const linked = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: alias },
    });
    expect(linked.statusCode).toBe(403);
    expect(linked.json()).toEqual({ error: "symbolic_link_not_allowed" });

    const outside = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: "/etc" },
    });
    expect(outside.statusCode).toBe(403);
    expect(outside.json()).toEqual({ error: "path_outside_operation_root" });
  });

  test.skipIf(process.getuid?.() !== 0)("keeps Git dubious-ownership protection enabled", async ({ skip }) => {
    const app = await createUnbornRepository({ "README.md": "hello\n" });
    try {
      await (await import("node:fs/promises")).chown(app.fixtureDir, 65534, 65534);
    } catch (error) {
      if (["EINVAL", "EPERM"].includes((error as NodeJS.ErrnoException).code ?? "")) skip();
      throw error;
    }

    const response = await app.fastify.inject({
      method: "POST",
      url: "/v1/git/status",
      headers: app.authHeaders,
      payload: { repo: app.fixtureDir },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toContain("dubious ownership");
  });
});
