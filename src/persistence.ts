import Database from "better-sqlite3";
import crypto from "node:crypto";
import type { GatewayConfig } from "./config.js";
import { OWNER_PRINCIPAL_ID, type PrincipalId, type ProposalState } from "./domain.js";

export interface Proposal {
  id: string;
  principal_id: PrincipalId;
  state: ProposalState;
  payload: unknown;
  hash: string;
  expires_at: string;
  result?: unknown;
}

export class ProposalError extends Error {
  constructor(public readonly code: string) {
    super(code);
  }
}

export function proposalHash(payload: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

function seal(value: string, key: Buffer): string {
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");
}

function unseal(value: string, key: Buffer): string {
  const raw = Buffer.from(value, "base64"); const iv = raw.subarray(0, 12); const tag = raw.subarray(12, 28); const body = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}

export class Store {
  private readonly db: Database.Database;
  constructor(private readonly config: GatewayConfig) {
    this.db = new Database(config.databasePath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS proposals (id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, state TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS action_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      principal_id TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      detail_hash TEXT NOT NULL,
      outcome TEXT NOT NULL,
      created_at TEXT NOT NULL
    );`);
    const columns = new Set((this.db.prepare("PRAGMA table_info(proposals)").all() as Array<{ name: string }>).map(({ name }) => name));
    if (!columns.has("result")) this.db.exec("ALTER TABLE proposals ADD COLUMN result TEXT");
    if (!columns.has("finished_at")) this.db.exec("ALTER TABLE proposals ADD COLUMN finished_at TEXT");
    this.db.prepare("INSERT OR IGNORE INTO principals (id, created_at) VALUES (?, ?)").run(OWNER_PRINCIPAL_ID, new Date().toISOString());
  }
  createProposal(payload: unknown, hash: string, expiresAt: string, principalId: PrincipalId): string {
    const id = crypto.randomUUID();
    this.db.prepare("INSERT INTO proposals (id,principal_id,state,payload,hash,expires_at,created_at) VALUES (?,?,'pending',?,?,?,?)").run(id, principalId, seal(JSON.stringify(payload), this.config.encryptionKey), hash, expiresAt, new Date().toISOString());
    return id;
  }
  private decode(row: any): Proposal {
    if (!["pending", "executing", "completed", "failed", "expired", "cancelled"].includes(row.state)) throw new ProposalError("proposal_integrity_failed");
    if (row.principal_id !== OWNER_PRINCIPAL_ID) throw new ProposalError("approval_principal_mismatch");
    const payload = JSON.parse(unseal(row.payload, this.config.encryptionKey));
    const actualHash = proposalHash(payload);
    const expected = Buffer.from(row.hash, "hex");
    const actual = Buffer.from(actualHash, "hex");
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) throw new ProposalError("proposal_integrity_failed");
    return { ...row, principal_id: row.principal_id as PrincipalId, state: row.state as ProposalState, payload, result: row.result ? JSON.parse(unseal(row.result, this.config.encryptionKey)) : undefined };
  }
  expireDue(now = new Date().toISOString()): number {
    return this.db.prepare("UPDATE proposals SET state='expired',finished_at=? WHERE state='pending' AND expires_at<=?").run(now, now).changes;
  }
  getProposal(id: string): Proposal | undefined {
    const transaction = this.db.transaction(() => {
      this.expireDue();
      const row = this.db.prepare("SELECT id,principal_id,state,payload,hash,expires_at,result FROM proposals WHERE id=?").get(id) as any;
      return row ? this.decode(row) : undefined;
    });
    return transaction();
  }
  claimProposal(id: string, principalId: PrincipalId, validate: (proposal: Proposal) => void): Proposal {
    const transaction = this.db.transaction(() => {
      const now = new Date().toISOString();
      this.expireDue(now);
      const row = this.db.prepare("SELECT id,principal_id,state,payload,hash,expires_at,result FROM proposals WHERE id=?").get(id) as any;
      if (!row) throw new ProposalError("approval_not_found");
      const proposal = this.decode(row);
      if (proposal.principal_id !== principalId) throw new ProposalError("approval_principal_mismatch");
      if (proposal.state !== "pending") throw new ProposalError("approval_not_executable");
      validate(proposal);
      const changed = this.db.prepare("UPDATE proposals SET state='executing' WHERE id=? AND principal_id=? AND state='pending' AND hash=? AND expires_at>?").run(id, principalId, proposal.hash, now).changes;
      if (changed !== 1) throw new ProposalError("approval_not_executable");
      return { ...proposal, state: "executing" as const };
    });
    return transaction.immediate();
  }
  finishProposal(id: string, state: "completed" | "failed", result: unknown): void {
    const changed = this.db.prepare("UPDATE proposals SET state=?,result=?,finished_at=? WHERE id=? AND state='executing'").run(state, seal(JSON.stringify(result), this.config.encryptionKey), new Date().toISOString(), id).changes;
    if (changed !== 1) throw new ProposalError("approval_state_conflict");
  }
  cancelProposal(id: string): boolean {
    return this.db.prepare("UPDATE proposals SET state='cancelled',finished_at=? WHERE id=? AND state='pending'").run(new Date().toISOString(), id).changes === 1;
  }
  auditAction(action: string, target: string | null, detail: unknown, outcome: string): void {
    const detailHash = crypto.createHash("sha256").update(JSON.stringify(detail)).digest("hex");
    this.db.prepare("INSERT INTO action_audit (principal_id,action,target,detail_hash,outcome,created_at) VALUES (?,?,?,?,?,?)")
      .run(OWNER_PRINCIPAL_ID, action, target, detailHash, outcome, new Date().toISOString());
  }
  close(): void { this.db.close(); }
}
