import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod/v4";
import type { GatewayConfig } from "./config.js";
import { SHELLBRIDGE_VERSION } from "./version.js";
import {
  COMMAND_MAX_LENGTH,
  COMMAND_OUTPUT_MAX_BYTES,
  COMMAND_TIMEOUT_MAX_MS,
  DOCUMENT_MAX_BYTES,
  PROJECT_TASK_OUTPUT_MAX_BYTES,
  PROJECT_TASK_TIMEOUT_MAX_MS,
  SCRIPT_RUN_OUTPUT_MAX_BYTES,
  SCRIPT_RUN_TIMEOUT_MAX_MS,
} from "./domain.js";

const MCP_SESSION_TTL_MS = 60 * 60_000;
const MCP_SESSION_LIMIT_PER_APP = 64;
const pendingInitializations = new WeakMap<FastifyInstance, number>();
const transports = new Map<string, {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  app: FastifyInstance;
  lastUsedAt: number;
}>();

async function pruneMcpSessions(app: FastifyInstance): Promise<void> {
  const cutoff = Date.now() - MCP_SESSION_TTL_MS;
  const closing: Promise<void>[] = [];
  for (const [id, current] of transports) {
    if (current.app !== app || current.lastUsedAt >= cutoff) continue;
    transports.delete(id);
    closing.push(current.server.close().catch(() => undefined));
  }
  await Promise.all(closing);
}

export async function closeMcpSessions(app: FastifyInstance): Promise<void> {
  pendingInitializations.delete(app);
  const closing: Promise<void>[] = [];
  for (const [id, current] of transports) {
    if (current.app !== app) continue;
    transports.delete(id);
    closing.push(current.server.close().catch(() => undefined));
  }
  await Promise.all(closing);
}

function ensureDestroySoon(request: FastifyRequest): void {
  const socket = request.raw.socket as typeof request.raw.socket & { destroySoon?: () => void };
  if (socket && typeof socket.destroySoon !== "function") {
    socket.destroySoon = () => undefined;
  }
}

function textResult(value: unknown, isError = false) {
  return { content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value) }], ...(isError ? { isError: true } : {}) };
}

function createServer(app: FastifyInstance, config: GatewayConfig): McpServer {
  const server = new McpServer({ name: "shellbridge", version: SHELLBRIDGE_VERSION }, {
    instructions: "普通文件、源码和文本诊断使用 run_shell_command。运行已经存在的测试或项目脚本使用 run_project_task，它在无网络临时副本中执行且不持久化输出。只有 .md/.txt 文档、结构化本地 Git 操作和用户明确要求的已有副作用脚本可以写入。不得用文档工具创建脚本，不得主动部署或重启。blocked 资源不能通过确认解锁。",
  });
  const internalHeaders = { authorization: `Bearer ${config.token}` };
  server.registerTool("run_shell_command", {
    title: "Run one ShellBridge command",
    description: "Run a complete Bash diagnostic command inside the read-only Bubblewrap sandbox. Pipes, loops, conditions, substitutions, awk/sed/find/xargs, and small Python or Node scripts are supported. The sandbox has no host write access, network, control sockets, or host process view.",
    inputSchema: { command: z.string().min(1).max(COMMAND_MAX_LENGTH), cwd: z.string().optional(), timeout_ms: z.number().int().min(1).max(COMMAND_TIMEOUT_MAX_MS).optional(), max_output_bytes: z.number().int().min(1).max(COMMAND_OUTPUT_MAX_BYTES).optional() },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/shell/commands", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("run_shell_batch", {
    title: "Run an explicit ShellBridge batch",
    description: "Run an explicit sequence of complete Bash diagnostic commands. Each command gets a fresh read-only Bubblewrap sandbox and cannot create a write proposal.",
    inputSchema: { commands: z.array(z.strictObject({ command: z.string().min(1).max(COMMAND_MAX_LENGTH), cwd: z.string().optional(), timeout_ms: z.number().int().min(1).max(COMMAND_TIMEOUT_MAX_MS).optional(), max_output_bytes: z.number().int().min(1).max(COMMAND_OUTPUT_MAX_BYTES).optional() })).min(1).max(10) },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/shell/batches", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("inspect_config", {
    title: "Inspect selected fields from a registered configuration",
    description: "Read only exact JSON Pointers or env variable names from an administrator-registered config target. Credentials are returned only as missing, empty, or set/redacted state and never as values.",
    inputSchema: z.strictObject({
      path: z.string().min(1).max(4096),
      format: z.enum(["json", "env"]),
      selectors: z.array(z.string().min(1).max(256)).min(1).max(32),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/inspect/config", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("run_project_task", {
    title: "Run an existing project task read-only",
    description: "Run one package.json script that already exists, or one existing shell/Python/Node/Go project script, inside a no-network Bubblewrap task sandbox. The project is copied to a command-lifetime writable tmpfs so caches, coverage, builds, and reports never change the host. Inline commands are not accepted and no proposal is created.",
    inputSchema: z.strictObject({
      cwd: z.string().min(1).max(4096),
      package_script: z.string().min(1).max(128).optional(),
      script_path: z.string().min(1).max(4096).optional(),
      args: z.array(z.string().max(4096)).max(100).optional(),
      timeout_ms: z.number().int().min(1).max(PROJECT_TASK_TIMEOUT_MAX_MS).optional(),
      max_output_bytes: z.number().int().min(1).max(PROJECT_TASK_OUTPUT_MAX_BYTES).optional(),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/tasks/run", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("write_text_document", {
    title: "Create or replace a Markdown or text document",
    description: "Consequential document write. Atomically create or replace only a .md or .txt regular file under /root. Parent directories may be created. Source, config, script, credential, blocked, and symlink targets are rejected. expected_hash protects updates from concurrent changes.",
    inputSchema: z.strictObject({
      path: z.string().min(1).max(4096),
      content: z.string().max(DOCUMENT_MAX_BYTES),
      expected_hash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/documents/write", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("patch_text_document", {
    title: "Patch a Markdown or text document",
    description: "Consequential document write. Apply exact structured text replacements to one existing .md or .txt regular file under /root using atomic replacement. Use expected_hash when modifying an observed file. Blocked resources and symlinks are always rejected.",
    inputSchema: z.strictObject({
      path: z.string().min(1).max(4096),
      replacements: z.array(z.strictObject({
        old_text: z.string().min(1),
        new_text: z.string(),
        replace_all: z.boolean().optional(),
      })).min(1).max(100),
      expected_hash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/documents/patch", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("move_text_document", {
    title: "Move or rename a Markdown or text document",
    description: "Consequential document write. Atomically move one .md or .txt regular file under /root to a new .md or .txt path. The destination must not exist. Blocked resources, non-document extensions, and symlinks are rejected.",
    inputSchema: z.strictObject({
      source: z.string().min(1).max(4096),
      destination: z.string().min(1).max(4096),
      expected_hash: z.string().regex(/^[a-f0-9]{64}$/).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/documents/move", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("get_git_status", {
    title: "Get complete local Git status",
    description: "Read the complete staged, unstaged, and untracked status of a real Git worktree under /root without contacting remotes.",
    inputSchema: z.strictObject({ repo: z.string().min(1).max(4096) }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/status", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("git_stage", {
    title: "Stage local Git changes",
    description: "Consequential local Git write. Stage explicit paths, or all=true, in a real worktree under /root. It never contacts or changes remotes.",
    inputSchema: z.strictObject({
      repo: z.string().min(1).max(4096),
      paths: z.array(z.string().min(1).max(4096)).min(1).max(500).optional(),
      all: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/stage", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("git_unstage", {
    title: "Unstage local Git changes",
    description: "Consequential local Git write. Unstage explicit paths, or all=true, without changing worktree files. It does not run reset --hard or contact remotes.",
    inputSchema: z.strictObject({
      repo: z.string().min(1).max(4096),
      paths: z.array(z.string().min(1).max(4096)).min(1).max(500).optional(),
      all: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/unstage", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("prepare_git_commit", {
    title: "Prepare an immutable local Git commit",
    description: "Prepare, but do not execute, one exact local commit for explicit paths or all=true. The proposal freezes the repository, branch, HEAD, current index, worktree state, target index tree, message, and full file list. If pending, call execute_proposal with its approval_id.",
    inputSchema: z.strictObject({
      repo: z.string().min(1).max(4096),
      message: z.string().min(1).max(1000),
      paths: z.array(z.string().min(1).max(4096)).min(1).max(500).optional(),
      all: z.boolean().optional(),
    }),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/git/commits/prepare", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("prepare_existing_script_run", {
    title: "Prepare one existing side-effecting script run",
    description: "Use only when the user explicitly asks, or the current task necessarily requires it. Prepare an existing backup, export, deployment, restart, or maintenance script; never proactively deploy, restart, or maintain. Inline commands are rejected. The proposal freezes inode, content hash, interpreter, arguments, cwd, resource limits, and environment profile. If pending, call execute_proposal.",
    inputSchema: z.strictObject({
      script_path: z.string().min(1).max(4096),
      args: z.array(z.string().max(4096)).max(100).optional(),
      cwd: z.string().min(1).max(4096).optional(),
      impact_summary: z.string().min(4).max(1000),
      timeout_ms: z.number().int().min(1).max(SCRIPT_RUN_TIMEOUT_MAX_MS).optional(),
      max_output_bytes: z.number().int().min(1).max(SCRIPT_RUN_OUTPUT_MAX_BYTES).optional(),
    }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  }, async (input) => {
    const response = await app.inject({ method: "POST", url: "/v1/scripts/prepare", headers: internalHeaders, payload: input });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("get_proposal", {
    title: "Get a ShellBridge proposal",
    description: "Use this to inspect the complete redacted preview and current status of an existing proposal.",
    inputSchema: { approval_id: z.string().uuid() },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async ({ approval_id }) => {
    const response = await app.inject({ method: "GET", url: `/v1/shell/approvals/${approval_id}`, headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("execute_proposal", {
    title: "Execute one immutable ShellBridge proposal",
    description: "Consequential write tool. Call immediately after a prepare tool returns pending. Accepts only that approval_id and cannot add or override a command, cwd, path, or argument. The client should show its official confirmation UI. A refusal must stop the workflow; a successful result resumes it.",
    inputSchema: z.strictObject({ approval_id: z.string().uuid() }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, async ({ approval_id }) => {
    const response = await app.inject({ method: "POST", url: `/v1/shell/approvals/${approval_id}/execute`, headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("cancel_proposal", {
    title: "Cancel one pending ShellBridge proposal",
    description: "Cancel one pending immutable proposal so it can never execute. This changes proposal state but does not run the planned host action.",
    inputSchema: z.strictObject({ approval_id: z.string().uuid() }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ approval_id }) => {
    const response = await app.inject({ method: "POST", url: `/v1/shell/approvals/${approval_id}/cancel`, headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  server.registerTool("prepare_approval_smoke", {
    title: "Prepare the fixed approval UI smoke operation",
    description: "Prepare the fixed local-only approval smoke operation when a root administrator has temporarily enabled it. It accepts no path or shell input. If pending, immediately call execute_proposal with its approval_id.",
    inputSchema: z.strictObject({}),
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => {
    const response = await app.inject({ method: "POST", url: "/v1/shell/approval-smoke", headers: internalHeaders });
    return textResult(response.body, response.statusCode >= 400);
  });
  return server;
}

export async function handleMcpRequest(app: FastifyInstance, config: GatewayConfig, request: FastifyRequest, reply: FastifyReply): Promise<void> {
  ensureDestroySoon(request);
  await pruneMcpSessions(app);
  const sessionId = request.headers["mcp-session-id"] as string | undefined;
  let current = sessionId ? transports.get(sessionId) : undefined;
  if (current) current.lastUsedAt = Date.now();
  if (!current && !sessionId && isInitializeRequest(request.body)) {
    const active = [...transports.values()].filter((item) => item.app === app).length;
    const pending = pendingInitializations.get(app) ?? 0;
    if (active + pending >= MCP_SESSION_LIMIT_PER_APP) {
      reply.code(429).send({ jsonrpc: "2.0", error: { code: -32000, message: "MCP session limit reached" }, id: null });
      return;
    }
    pendingInitializations.set(app, pending + 1);
    let reservationHeld = true;
    const releaseReservation = () => {
      if (!reservationHeld) return;
      reservationHeld = false;
      const remaining = (pendingInitializations.get(app) ?? 1) - 1;
      if (remaining <= 0) pendingInitializations.delete(app);
      else pendingInitializations.set(app, remaining);
    };
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        releaseReservation();
        transports.set(id, { transport, server, app, lastUsedAt: Date.now() });
      },
      onsessionclosed: (id) => { transports.delete(id); },
    });
    const server = createServer(app, config);
    try {
      await server.connect(transport as any);
      reply.hijack();
      await transport.handleRequest(request.raw, reply.raw, request.body);
    } finally {
      releaseReservation();
    }
    return;
  }
  if (!current) { reply.code(400).send({ jsonrpc: "2.0", error: { code: -32000, message: "MCP session is missing or invalid" }, id: null }); return; }
  reply.hijack();
  await current.transport.handleRequest(request.raw, reply.raw, request.body);
}
