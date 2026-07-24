import { execFile } from "node:child_process";
import path from "node:path";

export type ConfigFormat = "json" | "env";
export type ConfigField =
  | { selector: string; status: "missing" | "empty" | "set"; redacted: true }
  | { selector: string; status: "missing" | "null" }
  | { selector: string; status: "set"; value: string | number | boolean }
  | { selector: string; status: "set"; value_type: "object" | "array" };

export interface ConfigInspection {
  status: "completed";
  path: string;
  format: ConfigFormat;
  fields: ConfigField[];
}

interface ConfigInspectorOptions {
  helperPath: string;
  registeredTargets: string[];
  registeredRoots?: string[];
  disclosedValuesByTarget?: Record<string, Record<string, string[]>>;
  maxBytes: number;
  timeoutMs: number;
}

const missing = Symbol("missing");
const secretName = /(api[_-]?key|auth[_-]?token|token|secret|password|private[_-]?key|authorization|cookie)/i;
const secretValue = /(?:\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{8,}\b|\bgh[pousr]_[A-Za-z0-9_]{8,}\b|\bxox[baprs]-[A-Za-z0-9-]{8,}\b)/i;

function readSecure(helperPath: string, root: string, relative: string, maxBytes: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    execFile(
      helperPath,
      ["secure-read", "--", root, relative, String(maxBytes)],
      { encoding: "buffer", timeout: timeoutMs, maxBuffer: maxBytes + 1024, shell: false, env: {} },
      (error, stdout) => error ? reject(new Error("config_read_failed")) : resolve(stdout),
    );
  });
}

function decodePointer(pointer: string): string[] {
  if (!pointer.startsWith("/")) throw new Error("invalid_selector");
  return pointer.slice(1).split("/").map((part) => {
    if (/~(?:[^01]|$)/.test(part)) throw new Error("invalid_selector");
    return part.replace(/~1/g, "/").replace(/~0/g, "~");
  });
}

function selectJson(value: unknown, pointer: string): { value: unknown | typeof missing; name: string } {
  const parts = decodePointer(pointer);
  let current: unknown = value;
  for (const part of parts) {
    if (Array.isArray(current)) {
      if (!/^(0|[1-9]\d*)$/.test(part) || Number(part) >= current.length) return { value: missing, name: part };
      current = current[Number(part)];
    } else if (current !== null && typeof current === "object" && Object.prototype.hasOwnProperty.call(current, part)) {
      current = (current as Record<string, unknown>)[part];
    } else {
      return { value: missing, name: part };
    }
  }
  return { value: current, name: parts.at(-1) ?? "" };
}

function parseEnv(text: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error("invalid_format");
    let value = match[2] ?? "";
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    result.set(match[1]!, value);
  }
  return result;
}

function sanitizeUrl(raw: string): string | undefined {
  try {
    const value = new URL(raw);
    if (value.protocol !== "https:" && value.protocol !== "http:") return undefined;
    const suspiciousSegment = value.pathname.split("/").some((segment) => {
      if (!segment) return false;
      if (/(?:token|secret|password|api[_-]?key|auth)/i.test(segment)) return true;
      if (segment.length < 16) return false;
      const unique = new Set(segment.toLowerCase()).size;
      return unique >= 10 && /[a-z]/i.test(segment) && /\d|[_-]/.test(segment);
    });
    if (suspiciousSegment) return undefined;
    value.username = "";
    value.password = "";
    value.search = "";
    value.hash = "";
    return value.toString().replace(/\/$/, raw.endsWith("/") ? "/" : "");
  } catch {
    return undefined;
  }
}

function field(selector: string, name: string, value: unknown | typeof missing, disclosedValues: Set<string> | undefined): ConfigField {
  const isSecret = secretName.test(name);
  if (value === missing) return isSecret ? { selector, status: "missing", redacted: true } : { selector, status: "missing" };
  if (value === null) return isSecret ? { selector, status: "empty", redacted: true } : { selector, status: "null" };
  if (isSecret) return { selector, status: value === "" ? "empty" : "set", redacted: true };
  if (Array.isArray(value)) return { selector, status: "set", value_type: "array" };
  if (typeof value === "object") return { selector, status: "set", value_type: "object" };
  if (typeof value === "number" || typeof value === "boolean") {
    return disclosedValues?.has(String(value))
      ? { selector, status: "set", value }
      : { selector, status: "set", redacted: true };
  }
  if (typeof value !== "string") return { selector, status: "missing" };
  if (value === "") return { selector, status: "empty", redacted: true };
  if (secretValue.test(value)) return { selector, status: "set", redacted: true };
  if (!disclosedValues?.has(value)) return { selector, status: "set", redacted: true };
  if (/url$/i.test(name)) {
    const sanitized = sanitizeUrl(value);
    return sanitized === undefined
      ? { selector, status: "set", redacted: true }
      : { selector, status: "set", value: sanitized };
  }
  return { selector, status: "set", value };
}

export class ConfigInspector {
  private readonly targets: Set<string>;
  private readonly roots: string[];
  private readonly disclosedValues: Map<string, Map<string, Set<string>>>;

  constructor(private readonly options: ConfigInspectorOptions) {
    this.targets = new Set(options.registeredTargets.map((item) => path.resolve(item)));
    this.roots = (options.registeredRoots ?? []).map((item) => path.resolve(item));
    this.disclosedValues = new Map(Object.entries(options.disclosedValuesByTarget ?? {}).map(
      ([target, selectors]) => [path.resolve(target), new Map(Object.entries(selectors).map(
        ([selector, values]) => [selector, new Set(values)],
      ))],
    ));
  }

  async inspect(request: { path: string; format: ConfigFormat; selectors: string[] }): Promise<ConfigInspection> {
    if (!Array.isArray(request.selectors) || request.selectors.length === 0 || request.selectors.length > 32) throw new Error("invalid_selectors");
    if (request.selectors.some((item) => typeof item !== "string" || item.length === 0 || item.length > 256)) throw new Error("invalid_selectors");
    const target = path.resolve(request.path);
    let root = "";
    let relative = "";
    if (this.targets.has(target)) {
      root = path.dirname(target);
      relative = path.basename(target);
    } else {
      for (const candidate of this.roots) {
        const candidateRelative = path.relative(candidate, target);
        if (candidateRelative && !candidateRelative.startsWith(`..${path.sep}`) && candidateRelative !== ".." && !path.isAbsolute(candidateRelative)) {
          root = candidate;
          relative = candidateRelative;
          break;
        }
      }
    }
    if (!root) throw new Error("config_target_not_registered");

    const raw = await readSecure(this.options.helperPath, root, relative, this.options.maxBytes, this.options.timeoutMs);
    const disclosed = this.disclosedValues.get(target);
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      throw new Error("invalid_utf8");
    }

    let fields: ConfigField[];
    if (request.format === "json") {
      let parsed: unknown;
      try { parsed = JSON.parse(text); } catch { throw new Error("invalid_format"); }
      fields = request.selectors.map((selector) => {
        const selected = selectJson(parsed, selector);
        return field(selector, selected.name, selected.value, disclosed?.get(selector));
      });
    } else if (request.format === "env") {
      const parsed = parseEnv(text);
      fields = request.selectors.map((selector) => {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(selector)) throw new Error("invalid_selector");
        return field(selector, selector, parsed.has(selector) ? parsed.get(selector) : missing, disclosed?.get(selector));
      });
    } else {
      throw new Error("invalid_format");
    }
    return { status: "completed", path: target, format: request.format, fields };
  }
}
