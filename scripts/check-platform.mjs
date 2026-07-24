import process from "node:process";

if (process.platform !== "linux" || process.arch !== "x64") {
  console.error(`ShellBridge native helper supports Linux x86_64 only (detected ${process.platform} ${process.arch}).`);
  process.exit(1);
}
