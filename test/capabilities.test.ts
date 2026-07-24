import { afterEach, describe, expect, test } from "vitest";
import { execFileSync } from "node:child_process";
import { readFile, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import Database from "better-sqlite3";
import { createTestApp, type TestApp } from "./support/test-app.js";

const apps: TestApp[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((item) => item.close()));
});

describe("structured document, Git, and task capabilities", () => {
  test("reports independent switches and honors the global kill switch", async () => {
    const app = await createTestApp({ writeActionsEnabled: false, documentWritesEnabled: true });
    apps.push(app);
    const health = await app.fastify.inject({ method: "GET", url: "/health", headers: app.authHeaders });
    expect(health.json()).toMatchObject({
      write_actions_enabled: false,
      document_writes_enabled: true,
      local_git_writes_enabled: true,
      existing_script_runs_enabled: true,
    });
    const denied = await app.fastify.inject({
      method: "POST",
      url: "/v1/documents/write",
      headers: app.authHeaders,
      payload: { path: path.join(path.dirname(app.fixtureDir), "denied.md"), content: "no" },
    });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toEqual({ error: "document_writes_disabled" });
  });

  test("writes, patches, and moves only md/txt documents with hashes and diffs", async () => {
    const app = await createTestApp();
    apps.push(app);
    const root = path.dirname(app.fixtureDir);
    const created = await app.fastify.inject({
      method: "POST",
      url: "/v1/documents/write",
      headers: app.authHeaders,
      payload: { path: path.join(root, "docs", "handoff.MD"), content: "# Handoff\n\nfirst\n" },
    });
    expect(created.statusCode, created.body).toBe(200);
    expect(created.json()).toMatchObject({ status: "completed", change_summary: "created text document" });
    expect(created.json().diff).toContain("+++ ");
    const initialHash = created.json().hash as string;

    const patched = await app.fastify.inject({
      method: "POST",
      url: "/v1/documents/patch",
      headers: app.authHeaders,
      payload: {
        path: path.join(root, "docs", "handoff.MD"),
        expected_hash: initialHash,
        replacements: [{ old_text: "first", new_text: "second" }],
      },
    });
    expect(patched.statusCode, patched.body).toBe(200);
    expect(patched.json().diff).toContain("-first");
    expect(patched.json().diff).toContain("+second");

    const stale = await app.fastify.inject({
      method: "POST",
      url: "/v1/documents/patch",
      headers: app.authHeaders,
      payload: {
        path: path.join(root, "docs", "handoff.MD"),
        expected_hash: initialHash,
        replacements: [{ old_text: "second", new_text: "third" }],
      },
    });
    expect(stale.statusCode).toBe(400);
    expect(stale.json()).toEqual({ error: "document_hash_mismatch" });

    const moved = await app.fastify.inject({
      method: "POST",
      url: "/v1/documents/move",
      headers: app.authHeaders,
      payload: {
        source: path.join(root, "docs", "handoff.MD"),
        destination: path.join(root, "handoff", "technical.txt"),
        expected_hash: patched.json().hash,
      },
    });
    expect(moved.statusCode, moved.body).toBe(200);
    await expect(readFile(path.join(root, "handoff", "technical.txt"), "utf8")).resolves.toContain("second");

    for (const extension of ["ts", "json", "env"]) {
      const denied = await app.fastify.inject({
        method: "POST",
        url: "/v1/documents/write",
        headers: app.authHeaders,
        payload: { path: path.join(root, `denied.${extension}`), content: "no" },
      });
      expect(denied.statusCode).toBe(403);
      expect(denied.json()).toEqual({ error: "document_extension_not_allowed" });
    }

    await symlink(path.join(root, "handoff"), path.join(root, "linked"));
    const symlinkDenied = await app.fastify.inject({
      method: "POST",
      url: "/v1/documents/write",
      headers: app.authHeaders,
      payload: { path: path.join(root, "linked", "escape.md"), content: "no" },
    });
    expect(symlinkDenied.statusCode).toBe(403);
    expect(symlinkDenied.json()).toEqual({ error: "symbolic_link_not_allowed" });
  });

  test.skipIf(process.env.SHELLBRIDGE_SANDBOXED_PROJECT_TASK === "1")("stages, unstages, freezes, and commits an exact local Git plan", async () => {
    const app = await createTestApp({ files: { "tracked.txt": "base\n" } });
    apps.push(app);
    const repo = app.fixtureDir;
    execFileSync("git", ["init", "-q", repo]);
    execFileSync("git", ["-C", repo, "config", "user.name", "Test"]);
    execFileSync("git", ["-C", repo, "config", "user.email", "test@example.invalid"]);
    execFileSync("git", ["-C", repo, "add", "tracked.txt"]);
    execFileSync("git", ["-C", repo, "commit", "-q", "-m", "base"]);
    await writeFile(path.join(repo, "tracked.txt"), "changed\n");
    await writeFile(path.join(repo, "unrelated.txt"), "keep untracked\n");

    const stage = await app.fastify.inject({
      method: "POST", url: "/v1/git/stage", headers: app.authHeaders,
      payload: { repo, paths: ["tracked.txt"] },
    });
    expect(stage.statusCode, stage.body).toBe(200);
    expect(stage.json().staged).toContainEqual({ status: "M", path: "tracked.txt" });

    const unstage = await app.fastify.inject({
      method: "POST", url: "/v1/git/unstage", headers: app.authHeaders,
      payload: { repo, paths: ["tracked.txt"] },
    });
    expect(unstage.statusCode, unstage.body).toBe(200);
    expect(unstage.json().unstaged).toContainEqual({ status: "M", path: "tracked.txt" });

    await app.fastify.inject({
      method: "POST", url: "/v1/git/stage", headers: app.authHeaders,
      payload: { repo, paths: ["tracked.txt"] },
    });
    const prepared = await app.fastify.inject({
      method: "POST", url: "/v1/git/commits/prepare", headers: app.authHeaders,
      payload: { repo, message: "docs: exact local commit", paths: ["tracked.txt"] },
    });
    expect(prepared.statusCode, prepared.body).toBe(202);
    expect(prepared.json().proposal.files).toEqual([{ status: "M", path: "tracked.txt" }]);
    expect(prepared.json().proposal.diff_stat).toContain("tracked.txt");

    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode, executed.body).toBe(200);
    expect(executed.json(), executed.body).toMatchObject({ status: "completed" });
    expect(executed.json().commit).toMatch(/^[a-f0-9]{40}$/);
    expect(execFileSync("git", ["-C", repo, "show", "--format=", "--name-only", "HEAD"], { encoding: "utf8" }).trim()).toBe("tracked.txt");
    expect(execFileSync("git", ["-C", repo, "status", "--short"], { encoding: "utf8" })).toContain("?? unrelated.txt");
    const replay = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(replay.statusCode).toBe(409);

    await writeFile(path.join(repo, "new-handoff.md"), "# New\n");
    const newFilePlan = await app.fastify.inject({
      method: "POST", url: "/v1/git/commits/prepare", headers: app.authHeaders,
      payload: { repo, message: "docs: add handoff", paths: ["new-handoff.md"] },
    });
    expect(newFilePlan.statusCode, newFilePlan.body).toBe(202);
    const newFileCommit = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${newFilePlan.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(newFileCommit.statusCode, newFileCommit.body).toBe(200);
    expect(execFileSync("git", ["-C", repo, "show", "--format=", "--name-only", "HEAD"], { encoding: "utf8" }).trim()).toBe("new-handoff.md");

    await writeFile(path.join(repo, ".env"), "TOKEN=do-not-stage\n");
    const blockedAll = await app.fastify.inject({
      method: "POST", url: "/v1/git/stage", headers: app.authHeaders,
      payload: { repo, all: true },
    });
    expect(blockedAll.statusCode).toBe(403);
    expect(blockedAll.json()).toEqual({ error: "blocked_resource" });
  });

  test.skipIf(process.env.SHELLBRIDGE_SANDBOXED_PROJECT_TASK === "1")("rejects a frozen Git commit when relevant repository state changes", async () => {
    const app = await createTestApp({ files: { "tracked.txt": "base\n" } });
    apps.push(app);
    const repo = app.fixtureDir;
    execFileSync("git", ["init", "-q", repo]);
    execFileSync("git", ["-C", repo, "config", "user.name", "Test"]);
    execFileSync("git", ["-C", repo, "config", "user.email", "test@example.invalid"]);
    execFileSync("git", ["-C", repo, "add", "tracked.txt"]);
    execFileSync("git", ["-C", repo, "commit", "-q", "-m", "base"]);
    await writeFile(path.join(repo, "tracked.txt"), "first\n");
    const prepared = await app.fastify.inject({
      method: "POST", url: "/v1/git/commits/prepare", headers: app.authHeaders,
      payload: { repo, message: "change", paths: ["tracked.txt"] },
    });
    await writeFile(path.join(repo, "tracked.txt"), "second\n");
    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${prepared.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode).toBe(409);
    expect(executed.json()).toEqual({ error: "git_worktree_changed" });
  });

  test.skipIf(process.env.SHELLBRIDGE_SANDBOXED_PROJECT_TASK === "1")("runs an existing package task in a disposable writable project copy", async () => {
    const app = await createTestApp({
      files: {
        "package.json": JSON.stringify({
          scripts: {
            check: "node -e \"require('node:fs').writeFileSync('generated.txt','temporary'); console.log('task-ok')\"",
          },
        }),
      },
    });
    apps.push(app);
    const response = await app.fastify.inject({
      method: "POST",
      url: "/v1/tasks/run",
      headers: app.authHeaders,
      payload: { cwd: app.fixtureDir, package_script: "check" },
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toMatchObject({
      classification: "read_only",
      execution_channel: "sandboxed_project_task",
      status: "completed",
      exit_code: 0,
      truncated: false,
      host_changes_persisted: false,
    });
    expect(response.json().stdout).toContain("task-ok");
    await expect(readFile(path.join(app.fixtureDir, "generated.txt"), "utf8")).rejects.toThrow();
    const db = new Database(app.databasePath, { readonly: true });
    expect(db.prepare("SELECT COUNT(*) AS count FROM proposals").get()).toEqual({ count: 0 });
    db.close();
  }, 30_000);

  test("cancels, executes, redacts, and rejects replay of an existing side-effect script", async () => {
    const app = await createTestApp({
      files: {
        "effect.sh": "#!/bin/bash\nset -eu\nprintf done > \"$1\"\nprintf 'api_token=supersecretvalue\\n'\nprintf 'abcdefghijklmnopqrstuvwxyz1234567890\\n'\n",
      },
    });
    apps.push(app);
    const output = path.join(app.fixtureDir, "effect-output.txt");
    const prepare = () => app.fastify.inject({
      method: "POST",
      url: "/v1/scripts/prepare",
      headers: app.authHeaders,
      payload: {
        script_path: path.join(app.fixtureDir, "effect.sh"),
        args: [output],
        cwd: app.fixtureDir,
        impact_summary: "writes the test output file",
      },
    });
    const cancelledPlan = await prepare();
    const cancelled = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${cancelledPlan.json().approval_id}/cancel`,
      headers: app.authHeaders,
    });
    expect(cancelled.json()).toMatchObject({ status: "cancelled" });
    await expect(readFile(output, "utf8")).rejects.toThrow();

    const stalePlan = await prepare();
    await writeFile(path.join(app.fixtureDir, "effect.sh"), "#!/bin/bash\nprintf replaced\n");
    const staleExecution = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${stalePlan.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(staleExecution.statusCode).toBe(409);
    expect(staleExecution.json()).toEqual({ error: "script_changed" });
    await writeFile(path.join(app.fixtureDir, "effect.sh"), "#!/bin/bash\nset -eu\nprintf done > \"$1\"\nprintf 'api_token=supersecretvalue\\n'\nprintf 'abcdefghijklmnopqrstuvwxyz1234567890\\n'\n");

    const plan = await prepare();
    expect(plan.body).not.toContain(output);
    const executed = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${plan.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(executed.statusCode, executed.body).toBe(200);
    expect(executed.json()).toMatchObject({ status: "completed", exit_code: 0 });
    expect(executed.body).toContain("[REDACTED");
    expect(executed.body).not.toContain("supersecretvalue");
    expect(executed.body).not.toContain("abcdefghijklmnopqrstuvwxyz1234567890");
    await expect(readFile(output, "utf8")).resolves.toBe("done");
    const replay = await app.fastify.inject({
      method: "POST",
      url: `/v1/shell/approvals/${plan.json().approval_id}/execute`,
      headers: app.authHeaders,
    });
    expect(replay.statusCode).toBe(409);
    const database = await readFile(app.databasePath);
    expect(database.toString("utf8")).not.toContain("supersecretvalue");
  });
});
