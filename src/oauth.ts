import crypto from "node:crypto";
import Database from "better-sqlite3";
import type { GatewayConfig } from "./config.js";
import { registerExactRedactionSecrets } from "./redactor.js";

const hash = (value: string) => crypto.createHash("sha256").update(value).digest("hex");
const secret = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");

export class OAuthService {
  private readonly db: Database.Database;
  constructor(private readonly config: GatewayConfig) {
    this.db = new Database(config.databasePath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, client_name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS oauth_codes (code_hash TEXT PRIMARY KEY, principal_id TEXT NOT NULL, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, resource TEXT NOT NULL, challenge TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER);
      CREATE TABLE IF NOT EXISTS oauth_tokens (token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, principal_id TEXT NOT NULL, client_id TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER);
      CREATE TABLE IF NOT EXISTS oauth_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, principal_id TEXT NOT NULL, event TEXT NOT NULL, client_id TEXT, outcome TEXT NOT NULL, created_at TEXT NOT NULL);
    `);
  }
  close(): void { this.db.close(); }
  metadata() {
    return { issuer: this.config.publicBaseUrl, authorization_endpoint: `${this.config.publicBaseUrl}/oauth/authorize`, token_endpoint: `${this.config.publicBaseUrl}/oauth/token`, registration_endpoint: `${this.config.publicBaseUrl}/oauth/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], token_endpoint_auth_methods_supported: ["none"], code_challenge_methods_supported: ["S256"], scopes_supported: ["mcp", "offline_access"] };
  }
  protectedResourceMetadata() { return { resource: `${this.config.publicBaseUrl}/mcp`, authorization_servers: [this.config.publicBaseUrl], scopes_supported: ["mcp", "offline_access"], bearer_methods_supported: ["header"] }; }
  registerClient(input: any) {
    if (!Array.isArray(input?.redirect_uris) || input.redirect_uris.length < 1 || input.token_endpoint_auth_method !== "none") throw new Error("invalid_client_metadata");
    const redirects = input.redirect_uris.map((raw: unknown) => {
      if (typeof raw !== "string") throw new Error("invalid_redirect_uri");
      const uri = new URL(raw); if (uri.protocol !== "https:" || uri.hash || !this.config.oauthRedirectHosts.includes(uri.hostname)) throw new Error("invalid_redirect_uri"); return uri.toString();
    });
    const clientId = secret(24);
    this.db.prepare("INSERT INTO oauth_clients VALUES (?, 'owner-1', ?, ?, ?)").run(clientId, String(input.client_name ?? "ChatGPT MCP client").slice(0, 200), JSON.stringify(redirects), new Date().toISOString());
    this.audit("client_registered", clientId, "success");
    return { client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), client_name: String(input.client_name ?? "ChatGPT MCP client").slice(0, 200), redirect_uris: redirects, grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
  }
  validateAuthorization(input: Record<string, string>): { redirectUri: string; resource: string; scope: string; clientName: string } {
    if (input.response_type !== "code" || input.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(input.code_challenge ?? "")) throw new Error("invalid_request");
    const client = this.db.prepare("SELECT client_name,redirect_uris FROM oauth_clients WHERE client_id=? AND principal_id='owner-1'").get(input.client_id) as { client_name: string; redirect_uris: string } | undefined;
    if (!client) throw new Error("invalid_client");
    if (!input.redirect_uri || !input.client_id) throw new Error("invalid_request");
    const redirectUri = new URL(input.redirect_uri).toString();
    if (!(JSON.parse(client.redirect_uris) as string[]).includes(redirectUri)) throw new Error("invalid_redirect_uri");
    const resource = new URL(input.resource ?? `${this.config.publicBaseUrl}/mcp`).toString();
    if (resource !== `${this.config.publicBaseUrl}/mcp`) throw new Error("invalid_target");
    const requested = new Set((input.scope ?? "mcp").split(/\s+/).filter(Boolean));
    if ([...requested].some((item) => !["mcp", "offline_access"].includes(item))) throw new Error("invalid_scope");
    requested.add("mcp");
    return { redirectUri, resource, scope: [...requested].join(" "), clientName: client.client_name };
  }
  ownerSecretMatches(value: string): boolean {
    const a = Buffer.from(value); const b = Buffer.from(this.config.oauthOwnerSecret);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  issueCode(input: Record<string, string>): { code: string; redirectUri: string; scope: string } {
    const { redirectUri, resource, scope } = this.validateAuthorization(input); const code = secret(32);
    registerExactRedactionSecrets([code]);
    this.db.prepare("INSERT INTO oauth_codes VALUES (?, 'owner-1', ?, ?, ?, ?, ?, ?, NULL)").run(hash(code), input.client_id, redirectUri, resource, input.code_challenge, scope, Date.now() + 5 * 60_000);
    this.audit("authorization_code_issued", input.client_id ?? null, "success");
    return { code, redirectUri, scope };
  }
  exchangeCode(input: Record<string, string>) {
    const row = this.db.prepare("SELECT * FROM oauth_codes WHERE code_hash=?").get(hash(input.code ?? "")) as any;
    const requestedResource = new URL(input.resource ?? `${this.config.publicBaseUrl}/mcp`).toString();
    if (!input.redirect_uri || !row || row.principal_id !== "owner-1" || row.consumed_at || row.expires_at <= Date.now() || row.client_id !== input.client_id || row.redirect_uri !== new URL(input.redirect_uri).toString() || row.resource !== requestedResource) throw new Error("invalid_grant");
    if (hash(input.code_verifier ?? "") !== Buffer.from(row.challenge, "base64url").toString("hex")) throw new Error("invalid_grant");
    const consumed = this.db.prepare("UPDATE oauth_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL").run(Date.now(), hash(input.code ?? ""));
    if (consumed.changes !== 1) throw new Error("invalid_grant");
    this.audit("authorization_code_exchanged", row.client_id, "success");
    return this.issueTokens(row.client_id, row.resource, row.scope);
  }
  refresh(input: Record<string, string>) {
    const tokenHash = hash(input.refresh_token ?? "");
    const row = this.db.prepare("SELECT * FROM oauth_tokens WHERE token_hash=? AND kind='refresh'").get(tokenHash) as any;
    const requestedResource = new URL(input.resource ?? `${this.config.publicBaseUrl}/mcp`).toString();
    if (!row || row.principal_id !== "owner-1" || row.consumed_at || row.expires_at <= Date.now() || row.client_id !== input.client_id || row.resource !== requestedResource) throw new Error("invalid_grant");
    const consumed = this.db.prepare("UPDATE oauth_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL").run(Date.now(), tokenHash);
    if (consumed.changes !== 1) throw new Error("invalid_grant");
    this.audit("refresh_rotated", row.client_id, "success");
    return this.issueTokens(row.client_id, row.resource, row.scope);
  }
  validateAccess(token: string, resource: string): boolean {
    const row = this.db.prepare("SELECT principal_id,resource,scope,expires_at,consumed_at FROM oauth_tokens WHERE token_hash=? AND kind='access'").get(hash(token)) as any;
    return Boolean(row && row.principal_id === "owner-1" && row.resource === resource && String(row.scope).split(/\s+/).includes("mcp") && !row.consumed_at && row.expires_at > Date.now());
  }
  audit(event: string, clientId: string | null, outcome: string): void { this.db.prepare("INSERT INTO oauth_audit (principal_id,event,client_id,outcome,created_at) VALUES ('owner-1',?,?,?,?)").run(event, clientId, outcome, new Date().toISOString()); }
  private issueTokens(clientId: string, resource: string, scope: string) {
    const access = secret(32); const refresh = scope.split(/\s+/).includes("offline_access") ? secret(48) : undefined; const now = Date.now();
    registerExactRedactionSecrets(refresh ? [access, refresh] : [access]);
    const insert = this.db.prepare("INSERT INTO oauth_tokens VALUES (?, ?, ?, ?, ?, ?, ?, NULL)");
    const transaction = this.db.transaction(() => { insert.run(hash(access), "access", "owner-1", clientId, resource, scope, now + 60 * 60_000); if (refresh) insert.run(hash(refresh), "refresh", "owner-1", clientId, resource, scope, now + 30 * 24 * 60 * 60_000); }); transaction();
    return { access_token: access, token_type: "Bearer", expires_in: 3600, ...(refresh ? { refresh_token: refresh } : {}), scope, resource };
  }
}
