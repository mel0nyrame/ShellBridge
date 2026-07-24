const SECRET_KEY = /(api[_-]?key|token|secret|password|private[_-]?key|authorization|cookie)/i;
const SECRET_VALUE = /\b(?:sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|xox[baprs]-[A-Za-z0-9-]{8,})\b/g;
const JWT_VALUE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const PRIVATE_KEY_BLOCK = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g;
const exactSecrets = new Set<string>();

export function registerExactRedactionSecrets(values: Iterable<string>): void {
  for (const value of values) {
    if (typeof value === "string" && value.length >= 4 && value.length <= 16 * 1024) exactSecrets.add(value);
  }
}

export function redact(text: string): string {
  let redacted = text;
  for (const value of [...exactSecrets].sort((left, right) => right.length - left.length)) {
    redacted = redacted.split(value).join(`[REDACTED length=${value.length}]`);
  }
  return redacted
    .replace(PRIVATE_KEY_BLOCK, (value) => `[REDACTED PRIVATE KEY length=${value.length}]`)
    .replace(/(["']?)([A-Za-z_][A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|private[_-]?key|authorization|cookie)[A-Za-z0-9_-]*)(["']?)(\s*[:=]\s*)(["']?)([^\s,}\]"']+)(["']?)/gi, (_m, _q1: string, key: string, _q2: string, sep: string, _q3: string, value: string, _q4: string) => `${key}${sep}[REDACTED length=${value.length}]`)
    .replace(/([A-Za-z_][A-Za-z0-9_-]*(?:api[_-]?key|token|secret|password|private[_-]?key|authorization|cookie)[A-Za-z0-9_-]*)\s*([=:])\s*([^\s,}\]]+)/gi, (_m, key: string, sep: string, value: string) => `${key}${sep}[REDACTED length=${value.length}]`)
    .replace(SECRET_VALUE, (value) => `[REDACTED length=${value.length}]`)
    .replace(JWT_VALUE, (value) => `[REDACTED length=${value.length}]`)
    .replace(/(Bearer\s+)[^\s]+/gi, "$1[REDACTED]");
}

export function redactUntrustedExecutionOutput(text: string, sensitiveValues: string[] = []): string {
  let output = redact(text);
  for (const value of [...new Set(sensitiveValues)].filter((item) => item.length >= 4).sort((left, right) => right.length - left.length)) {
    output = output.split(value).join(`[REDACTED ARGUMENT length=${value.length}]`);
  }
  return output.replace(/\b[A-Za-z0-9_+/=-]{32,}\b/g, (value) => `[REDACTED OPAQUE length=${value.length}]`);
}
