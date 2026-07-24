import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const source = await readFile(new URL("../src/version.ts", import.meta.url), "utf8");
const match = source.match(/SHELLBRIDGE_VERSION\s*=\s*"([^"]+)"/);

if (!match || match[1] !== manifest.version) {
  console.error(`Version mismatch: package.json=${manifest.version}, src/version.ts=${match?.[1] ?? "missing"}`);
  process.exit(1);
}
