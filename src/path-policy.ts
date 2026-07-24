import fs from "node:fs";
import path from "node:path";

export function isInside(target: string, root: string): boolean {
  return target === root || target.startsWith(`${root}${path.sep}`);
}

export class ManagedPathPolicy {
  readonly root: string;
  private readonly blocked: string[];

  constructor(root: string, blockedPaths: string[]) {
    this.root = fs.realpathSync(root);
    if (!fs.statSync(this.root).isDirectory()) throw new Error("operation_root_not_directory");
    this.blocked = blockedPaths.map((item) => {
      const resolved = path.resolve(item);
      try { return fs.realpathSync(resolved); } catch { return resolved; }
    });
  }

  resolve(raw: string): string {
    if (typeof raw !== "string" || raw.length === 0 || raw.length > 4096 || raw.includes("\0")) {
      throw new Error("invalid_path");
    }
    const target = path.resolve(this.root, raw);
    if (!isInside(target, this.root)) throw new Error("path_outside_operation_root");
    if (this.blocked.some((blocked) => isInside(target, blocked))) throw new Error("blocked_resource");
    this.assertExistingComponentsSafe(target);
    return target;
  }

  assertExistingComponentsSafe(target: string): void {
    const relative = path.relative(this.root, target);
    let current = this.root;
    for (const component of relative.split(path.sep).filter(Boolean)) {
      current = path.join(current, component);
      let metadata: fs.Stats;
      try { metadata = fs.lstatSync(current); } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") break;
        throw error;
      }
      if (metadata.isSymbolicLink()) throw new Error("symbolic_link_not_allowed");
      const canonical = fs.realpathSync(current);
      if (!isInside(canonical, this.root)) throw new Error("path_outside_operation_root");
      if (this.blocked.some((blocked) => isInside(canonical, blocked))) throw new Error("blocked_resource");
    }
  }

  ensureParent(target: string): void {
    const relative = path.relative(this.root, path.dirname(target));
    let current = this.root;
    for (const component of relative.split(path.sep).filter(Boolean)) {
      current = path.join(current, component);
      try {
        const metadata = fs.lstatSync(current);
        if (metadata.isSymbolicLink()) throw new Error("symbolic_link_not_allowed");
        if (!metadata.isDirectory()) throw new Error("parent_not_directory");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        fs.mkdirSync(current, { mode: 0o700 });
      }
      const canonical = fs.realpathSync(current);
      if (!isInside(canonical, this.root)) throw new Error("path_outside_operation_root");
      if (this.blocked.some((blocked) => isInside(canonical, blocked))) throw new Error("blocked_resource");
    }
  }
}
