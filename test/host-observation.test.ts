import path from "node:path";
import { describe, expect, test } from "vitest";
import { HostObservation } from "../src/host-observation.js";

describe.skipIf(process.env.SHELLBRIDGE_NATIVE_ACCEPTANCE !== "1")("HostObservation", () => {
  test("reports the registered Claude executable and version under the observer profile", async () => {
    const observation = new HostObservation({
      helperPath: path.resolve("dist/native/shellbridge-helper"),
      observerUid: 65534,
      observerGid: 65534,
      commandPaths: {
        claude: ["/usr/local/bin/claude", "/usr/bin/claude"],
      },
      timeoutMs: 5_000,
      maxOutputBytes: 16 * 1024,
    });

    const result = await observation.inspectCommand({ commandId: "claude" });

    expect(result.installed).toBe(true);
    if (!result.installed) throw new Error("claude_not_installed");
    expect(result.path).toBe("/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe");
    expect(result.version).toMatch(/\d+\.\d+/);
    await expect(observation.inspectCommand({ commandId: "claude --version" as "claude" })).rejects.toThrow("unsupported_command_id");
  });
});
