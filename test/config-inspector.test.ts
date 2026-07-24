import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, test } from "vitest";
import { ConfigInspector } from "../src/config-inspector.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("ConfigInspector", () => {
  test("returns selected service settings while reducing credentials to state", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-config-"));
    roots.push(root);
    const configDirectory = path.join(root, "service");
    const configPath = path.join(configDirectory, "settings.json");
    await mkdir(configDirectory);
    await writeFile(configPath, JSON.stringify({
      env: {
        SERVICE_BASE_URL: "https://gateway.example.test/v1",
        SERVICE_MODEL: "diagnostic-model",
        SERVICE_API_KEY: "test-secret-never-return",
        SERVICE_AUTH_TOKEN: "",
        RETRY_COUNT: 42,
        FEATURE_ENABLED: true,
      },
    }));

    const inspector = new ConfigInspector({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      registeredTargets: [configPath],
      disclosedValuesByTarget: {
        [configPath]: {
          "/env/SERVICE_BASE_URL": ["https://gateway.example.test/v1"],
          "/env/SERVICE_MODEL": ["diagnostic-model"],
        },
      },
      maxBytes: 64 * 1024,
      timeoutMs: 2_000,
    });
    const result = await inspector.inspect({
      path: configPath,
      format: "json",
      selectors: [
        "/env/SERVICE_BASE_URL",
        "/env/SERVICE_MODEL",
        "/env/SERVICE_API_KEY",
        "/env/SERVICE_AUTH_TOKEN",
        "/env/RETRY_COUNT",
        "/env/FEATURE_ENABLED",
      ],
    });

    expect(result).toEqual({
      status: "completed",
      path: configPath,
      format: "json",
      fields: [
        { selector: "/env/SERVICE_BASE_URL", status: "set", value: "https://gateway.example.test/v1" },
        { selector: "/env/SERVICE_MODEL", status: "set", value: "diagnostic-model" },
        { selector: "/env/SERVICE_API_KEY", status: "set", redacted: true },
        { selector: "/env/SERVICE_AUTH_TOKEN", status: "empty", redacted: true },
        { selector: "/env/RETRY_COUNT", status: "set", redacted: true },
        { selector: "/env/FEATURE_ENABLED", status: "set", redacted: true },
      ],
    });
    expect(JSON.stringify(result)).not.toContain("test-secret-never-return");
  });

  test("supports exact env selectors and never evaluates or returns credential values", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-env-"));
    roots.push(root);
    const configPath = path.join(root, "service.env");
    await writeFile(configPath, [
      "SERVICE_BASE_URL=https://gateway.example.test/v1?token=remove-me",
      "SERVICE_MODEL=diagnostic-model",
      "SERVICE_API_KEY=short-secret",
      "UNSAFE_BASE_URL=data:text/plain,opaque-secret",
      "PATH_TOKEN_BASE_URL=https://gateway.example.test/api/token/opaque-secret-123456",
    ].join("\n"));
    const inspector = new ConfigInspector({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      registeredTargets: [configPath],
      disclosedValuesByTarget: {
        [configPath]: {
          SERVICE_BASE_URL: ["https://gateway.example.test/v1?token=remove-me"],
          SERVICE_MODEL: ["diagnostic-model"],
          UNSAFE_BASE_URL: ["data:text/plain,opaque-secret"],
          PATH_TOKEN_BASE_URL: ["https://gateway.example.test/api/token/opaque-secret-123456"],
        },
      },
      maxBytes: 64 * 1024,
      timeoutMs: 2_000,
    });

    const result = await inspector.inspect({
      path: configPath,
      format: "env",
      selectors: ["SERVICE_BASE_URL", "SERVICE_MODEL", "SERVICE_API_KEY", "SERVICE_AUTH_TOKEN", "UNSAFE_BASE_URL", "PATH_TOKEN_BASE_URL"],
    });

    expect(result.fields).toEqual([
      { selector: "SERVICE_BASE_URL", status: "set", value: "https://gateway.example.test/v1" },
      { selector: "SERVICE_MODEL", status: "set", value: "diagnostic-model" },
      { selector: "SERVICE_API_KEY", status: "set", redacted: true },
      { selector: "SERVICE_AUTH_TOKEN", status: "missing", redacted: true },
      { selector: "UNSAFE_BASE_URL", status: "set", redacted: true },
      { selector: "PATH_TOKEN_BASE_URL", status: "set", redacted: true },
    ]);
    expect(JSON.stringify(result)).not.toContain("short-secret");
    expect(JSON.stringify(result)).not.toContain("remove-me");
  });

  test("fails closed for malformed, non-UTF8, oversized, unregistered, and symlink targets", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "shellbridge-invalid-config-"));
    roots.push(root);
    const malformed = path.join(root, "malformed.json");
    const invalidUtf8 = path.join(root, "invalid.env");
    const oversized = path.join(root, "oversized.json");
    const outside = path.join(root, "outside.json");
    const linked = path.join(root, "linked.json");
    await writeFile(malformed, '{"API_KEY":"never-return",');
    await writeFile(invalidUtf8, Buffer.from([0xff, 0xfe, 0xfd]));
    await writeFile(oversized, JSON.stringify({ model: "x".repeat(2048) }));
    await writeFile(outside, '{"model":"outside"}');
    await symlink(outside, linked);
    const inspector = new ConfigInspector({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      registeredTargets: [malformed, invalidUtf8, oversized, linked],
      maxBytes: 1024,
      timeoutMs: 2_000,
    });

    await expect(inspector.inspect({ path: malformed, format: "json", selectors: ["/API_KEY"] })).rejects.toThrow("invalid_format");
    await expect(inspector.inspect({ path: invalidUtf8, format: "env", selectors: ["API_KEY"] })).rejects.toThrow("invalid_utf8");
    await expect(inspector.inspect({ path: oversized, format: "json", selectors: ["/model"] })).rejects.toThrow("config_read_failed");
    await expect(inspector.inspect({ path: outside, format: "json", selectors: ["/model"] })).rejects.toThrow("config_target_not_registered");
    await expect(inspector.inspect({ path: linked, format: "json", selectors: ["/model"] })).rejects.toThrow("config_read_failed");
  });
});
