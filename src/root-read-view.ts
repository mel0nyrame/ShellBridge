import fs from "node:fs";
import path from "node:path";

export interface RootViewEntry {
  source: string;
  target: string;
  kind: "file" | "directory" | "symlink";
  device: bigint;
  inode: bigint;
  linkTarget?: string;
}

export interface RootViewRewrite {
  target: string;
  entries: RootViewEntry[];
}

export interface RootReadViewPlan {
  masks: Array<{ target: string; kind: "file" | "directory" }>;
  rewrites: RootViewRewrite[];
}

interface PrivateKeyCacheEntry {
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  privateKey: boolean;
}

export class PrivateKeyIndex {
  private readonly entries = new Map<string, PrivateKeyCacheEntry>();

  classify(target: string, metadata: fs.Stats): boolean {
    const key = inodeKey(metadata);
    const cached = this.entries.get(key);
    if (cached && cached.size === metadata.size
        && cached.mtimeMs === metadata.mtimeMs && cached.ctimeMs === metadata.ctimeMs) {
      return cached.privateKey;
    }
    const privateKey = startsWithPrivateKey(target, metadata);
    this.entries.set(key, {
      size: metadata.size,
      mtimeMs: metadata.mtimeMs,
      ctimeMs: metadata.ctimeMs,
      privateKey,
    });
    return privateKey;
  }

  retain(inodes: Set<string>): void {
    for (const key of this.entries.keys()) {
      if (!inodes.has(key)) this.entries.delete(key);
    }
  }
}

const PRIVATE_KEY_HEADER = /^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/m;
const ENV_EXAMPLE = /^\.env\.(?:example|sample|template)(?:\.|$)/i;

function inside(target: string, root: string): boolean {
  return target === root || target.startsWith(`${root}${path.sep}`);
}

function isSecretEnvFile(name: string): boolean {
  return (name === ".env" || name.startsWith(".env.")) && !ENV_EXAMPLE.test(name);
}

function inodeKey(metadata: fs.Stats): string {
  return `${metadata.dev}:${metadata.ino}`;
}

function collectBlockedInodes(target: string, destination: Set<string>, deadlineMs: number): void {
  if (Date.now() >= deadlineMs) throw new Error("sandbox_private_key_scan_failed");
  let metadata: fs.Stats;
  try { metadata = fs.lstatSync(target, { bigint: false }); } catch { return; }
  if (metadata.isSymbolicLink()) return;
  if (metadata.isFile()) {
    destination.add(inodeKey(metadata));
    return;
  }
  if (!metadata.isDirectory()) return;
  for (const name of fs.readdirSync(target)) {
    collectBlockedInodes(path.join(target, name), destination, deadlineMs);
  }
}

function startsWithPrivateKey(target: string, metadata: fs.Stats): boolean {
  if (metadata.size <= 0) return false;
  const descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== metadata.dev || opened.ino !== metadata.ino) throw new Error("sandbox_root_changed");
    const buffer = Buffer.allocUnsafe(Math.min(metadata.size, 4096));
    const count = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
    return PRIVATE_KEY_HEADER.test(buffer.subarray(0, count).toString("utf8"));
  } finally {
    fs.closeSync(descriptor);
  }
}

function depth(target: string): number {
  return target.split(path.sep).filter(Boolean).length;
}

function inspectSymlink(target: string, root: string, blockedPaths: string[]): {
  linkTarget: string;
  unsafe: boolean;
} {
  const linkTarget = fs.readlinkSync(target);
  let resolved: string;
  try { resolved = fs.realpathSync(target); } catch { resolved = ""; }
  return {
    linkTarget,
    unsafe: !resolved || !inside(resolved, root)
      || blockedPaths.some((blocked) => inside(resolved, blocked)),
  };
}

export function createRootReadViewPlan(
  root: string,
  blockedPaths: string[],
  privateKeys: {
    index: PrivateKeyIndex;
    deadlineMs: number;
  },
): RootReadViewPlan {
  const rootMetadata = fs.statSync(root);
  const lexicalBlocked = blockedPaths.map((target) => path.resolve(target));
  const blockedInodes = new Set<string>();
  const regularFilesByInode = new Map<string, string[]>();
  lexicalBlocked.forEach((target) => collectBlockedInodes(target, blockedInodes, privateKeys.deadlineMs));
  const masks = new Map<string, "file" | "directory">();
  const blockedDirectories = new Set<string>();
  const unsafeLinks = new Map<string, { device: bigint; inode: bigint; linkTarget: string }>();

  for (const target of lexicalBlocked) {
    if (!inside(target, root) || target === root) continue;
    let metadata: fs.Stats;
    try { metadata = fs.lstatSync(target); } catch { continue; }
    if (metadata.isSymbolicLink()) {
      unsafeLinks.set(target, {
        device: BigInt(metadata.dev),
        inode: BigInt(metadata.ino),
        linkTarget: fs.readlinkSync(target),
      });
    } else {
      const kind = metadata.isDirectory() ? "directory" : "file";
      masks.set(target, kind);
      if (kind === "directory") blockedDirectories.add(target);
    }
  }

  const walk = (directory: string): void => {
    for (const name of fs.readdirSync(directory)) {
      if (Date.now() >= privateKeys.deadlineMs) {
        throw new Error("sandbox_private_key_scan_failed");
      }
      const target = path.join(directory, name);
      if ([...blockedDirectories].some((blocked) => inside(target, blocked))) continue;
      const metadata = fs.lstatSync(target);
      if (metadata.dev !== rootMetadata.dev) throw new Error("sandbox_root_contains_nested_mount");
      if (metadata.isSymbolicLink()) {
        const link = inspectSymlink(target, root, lexicalBlocked);
        if (link.unsafe) {
          unsafeLinks.set(target, {
            device: BigInt(metadata.dev),
            inode: BigInt(metadata.ino),
            linkTarget: link.linkTarget,
          });
        }
        continue;
      }
      if (metadata.isDirectory()) {
        walk(target);
        continue;
      }
      if (!metadata.isFile()) {
        masks.set(target, "file");
        continue;
      }
      const key = inodeKey(metadata);
      const aliases = regularFilesByInode.get(key) ?? [];
      aliases.push(target);
      regularFilesByInode.set(key, aliases);
      if (isSecretEnvFile(name)) blockedInodes.add(key);
      if (privateKeys.index.classify(target, metadata)) {
        blockedInodes.add(key);
      }
    }
  };
  walk(root);
  privateKeys.index.retain(new Set(regularFilesByInode.keys()));
  for (const key of blockedInodes) {
    for (const target of regularFilesByInode.get(key) ?? []) masks.set(target, "file");
  }

  const rewrittenParents = [...new Set([...unsafeLinks.keys()].map((target) => path.dirname(target)))]
    .sort((left, right) => depth(left) - depth(right) || left.localeCompare(right));
  const directOmissions = new Set([...masks.keys(), ...unsafeLinks.keys()]);
  const rewrites = rewrittenParents.map((target): RootViewRewrite => {
    const entries: RootViewEntry[] = [];
    for (const name of fs.readdirSync(target)) {
      const source = path.join(target, name);
      if (directOmissions.has(source)) continue;
      const metadata = fs.lstatSync(source);
      if (metadata.isSymbolicLink()) {
        const link = inspectSymlink(source, root, lexicalBlocked);
        if (link.unsafe) continue;
        entries.push({
          source,
          target: source,
          kind: "symlink",
          device: BigInt(metadata.dev),
          inode: BigInt(metadata.ino),
          linkTarget: link.linkTarget,
        });
      } else if (metadata.isDirectory() || metadata.isFile()) {
        entries.push({
          source,
          target: source,
          kind: metadata.isDirectory() ? "directory" : "file",
          device: BigInt(metadata.dev),
          inode: BigInt(metadata.ino),
        });
      }
    }
    return { target, entries };
  });

  const rewrittenDirectChildren = new Set(rewrittenParents.flatMap((parent) => (
    [...masks.keys()].filter((target) => path.dirname(target) === parent)
  )));
  return {
    masks: [...masks]
      .filter(([target]) => !rewrittenDirectChildren.has(target))
      .map(([target, kind]) => ({ target, kind })),
    rewrites,
  };
}
