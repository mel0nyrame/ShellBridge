import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DOCUMENT_MAX_BYTES } from "./domain.js";
import { ManagedPathPolicy } from "./path-policy.js";
import { redact } from "./redactor.js";

export interface TextReplacement {
  old_text: string;
  new_text: string;
  replace_all?: boolean;
}

function hash(contents: Buffer | string): string {
  return crypto.createHash("sha256").update(contents).digest("hex");
}

function validateDocumentPath(target: string): void {
  if (!/\.(?:md|txt)$/i.test(target)) throw new Error("document_extension_not_allowed");
  if (target.split(path.sep).includes(".git")) throw new Error("blocked_resource");
}

function validateText(contents: string): Buffer {
  if (contents.includes("\0")) throw new Error("invalid_text_document");
  const bytes = Buffer.from(contents, "utf8");
  if (bytes.length > DOCUMENT_MAX_BYTES) throw new Error("document_too_large");
  return bytes;
}

function readExisting(target: string): { contents: string; bytes: Buffer; hash: string } | undefined {
  let descriptor: number;
  try { descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new Error("symbolic_link_not_allowed");
    throw error;
  }
  try {
    const metadata = fs.fstatSync(descriptor);
    if (!metadata.isFile()) throw new Error("document_not_regular_file");
    if (metadata.size > DOCUMENT_MAX_BYTES) throw new Error("document_too_large");
    const bytes = fs.readFileSync(descriptor);
    const contents = bytes.toString("utf8");
    if (!Buffer.from(contents, "utf8").equals(bytes) || contents.includes("\0")) throw new Error("invalid_text_document");
    return { contents, bytes, hash: hash(bytes) };
  } finally {
    fs.closeSync(descriptor);
  }
}

function requireExpectedHash(existing: ReturnType<typeof readExisting>, expectedHash?: string): void {
  if (expectedHash === undefined) return;
  if (!/^[a-f0-9]{64}$/.test(expectedHash) || !existing || existing.hash !== expectedHash) {
    throw new Error("document_hash_mismatch");
  }
}

function unifiedDiff(from: string, to: string, oldText: string, newText: string): string {
  if (oldText === newText && from === to) return "";
  const oldLines = oldText.split("\n");
  const newLines = newText.split("\n");
  const lines = [
    `--- ${from}`,
    `+++ ${to}`,
    `@@ -1,${oldLines.length} +1,${newLines.length} @@`,
    ...oldLines.map((line) => `-${line}`),
    ...newLines.map((line) => `+${line}`),
  ];
  return redact(`${lines.join("\n")}\n`);
}

function atomicReplace(target: string, contents: Buffer, expectedParent: string): void {
  const parent = path.dirname(target);
  const parentDescriptor = fs.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  const openedParent = fs.realpathSync(`/proc/self/fd/${parentDescriptor}`);
  if (openedParent !== expectedParent) {
    fs.closeSync(parentDescriptor);
    throw new Error("document_parent_changed");
  }
  const fixedParent = `/proc/self/fd/${parentDescriptor}`;
  const temporary = path.join(fixedParent, `.${path.basename(target)}.shellbridge-${crypto.randomUUID()}.tmp`);
  const fixedTarget = path.join(fixedParent, path.basename(target));
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, fixedTarget);
    fs.fsyncSync(parentDescriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch { /* replacement completed or cleanup best effort */ }
    fs.closeSync(parentDescriptor);
  }
}

export class DocumentWriter {
  private readonly policy: ManagedPathPolicy;

  constructor(root: string, blockedPaths: string[]) {
    this.policy = new ManagedPathPolicy(root, blockedPaths);
  }

  write(input: { path: string; content: string; expected_hash?: string }) {
    const target = this.policy.resolve(input.path);
    validateDocumentPath(target);
    const existing = readExisting(target);
    requireExpectedHash(existing, input.expected_hash);
    const bytes = validateText(input.content);
    this.policy.ensureParent(target);
    this.policy.assertExistingComponentsSafe(target);
    const expectedParent = fs.realpathSync(path.dirname(target));
    const current = readExisting(target);
    if (existing?.hash !== current?.hash) throw new Error("document_changed_during_write");
    atomicReplace(target, bytes, expectedParent);
    return {
      path: target,
      hash: hash(bytes),
      change_summary: existing ? "updated text document" : "created text document",
      diff: unifiedDiff(existing ? target : "/dev/null", target, existing?.contents ?? "", input.content),
    };
  }

  patch(input: { path: string; replacements: TextReplacement[]; expected_hash?: string }) {
    const target = this.policy.resolve(input.path);
    validateDocumentPath(target);
    const existing = readExisting(target);
    if (!existing) throw new Error("document_not_found");
    requireExpectedHash(existing, input.expected_hash);
    if (!Array.isArray(input.replacements) || input.replacements.length === 0 || input.replacements.length > 100) {
      throw new Error("invalid_replacements");
    }
    let updated = existing.contents;
    let replacementCount = 0;
    for (const replacement of input.replacements) {
      if (typeof replacement.old_text !== "string" || replacement.old_text.length === 0
          || typeof replacement.new_text !== "string") throw new Error("invalid_replacement");
      const occurrences = updated.split(replacement.old_text).length - 1;
      if (occurrences === 0) throw new Error("patch_context_not_found");
      if (!replacement.replace_all && occurrences !== 1) throw new Error("patch_context_not_unique");
      updated = replacement.replace_all
        ? updated.split(replacement.old_text).join(replacement.new_text)
        : updated.replace(replacement.old_text, replacement.new_text);
      replacementCount += replacement.replace_all ? occurrences : 1;
    }
    const bytes = validateText(updated);
    this.policy.assertExistingComponentsSafe(target);
    const expectedParent = fs.realpathSync(path.dirname(target));
    const current = readExisting(target);
    if (!current || current.hash !== existing.hash) throw new Error("document_changed_during_write");
    atomicReplace(target, bytes, expectedParent);
    return {
      path: target,
      hash: hash(bytes),
      change_summary: `patched text document (${replacementCount} replacement${replacementCount === 1 ? "" : "s"})`,
      diff: unifiedDiff(target, target, existing.contents, updated),
    };
  }

  move(input: { source: string; destination: string; expected_hash?: string }) {
    const source = this.policy.resolve(input.source);
    const destination = this.policy.resolve(input.destination);
    validateDocumentPath(source);
    validateDocumentPath(destination);
    if (source === destination) throw new Error("source_equals_destination");
    const existing = readExisting(source);
    if (!existing) throw new Error("document_not_found");
    requireExpectedHash(existing, input.expected_hash);
    if (readExisting(destination)) throw new Error("destination_exists");
    this.policy.ensureParent(destination);
    this.policy.assertExistingComponentsSafe(source);
    this.policy.assertExistingComponentsSafe(destination);
    const sourceParent = fs.realpathSync(path.dirname(source));
    const destinationParent = fs.realpathSync(path.dirname(destination));
    const current = readExisting(source);
    if (!current || current.hash !== existing.hash) throw new Error("document_changed_during_move");
    const sourceParentDescriptor = fs.openSync(sourceParent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    const destinationParentDescriptor = fs.openSync(destinationParent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      if (fs.realpathSync(`/proc/self/fd/${sourceParentDescriptor}`) !== sourceParent
          || fs.realpathSync(`/proc/self/fd/${destinationParentDescriptor}`) !== destinationParent) {
        throw new Error("document_parent_changed");
      }
      const fixedSource = `/proc/self/fd/${sourceParentDescriptor}/${path.basename(source)}`;
      const fixedDestination = `/proc/self/fd/${destinationParentDescriptor}/${path.basename(destination)}`;
      try {
        fs.linkSync(fixedSource, fixedDestination);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EEXIST") throw new Error("destination_exists");
        if (code === "EXDEV") throw new Error("document_move_cross_device_not_supported");
        throw error;
      }
      try {
        fs.unlinkSync(fixedSource);
      } catch (error) {
        try { fs.unlinkSync(fixedDestination); } catch { /* preserve source and report failure */ }
        throw error;
      }
      fs.fsyncSync(sourceParentDescriptor);
      if (destinationParentDescriptor !== sourceParentDescriptor) fs.fsyncSync(destinationParentDescriptor);
    } finally {
      fs.closeSync(destinationParentDescriptor);
      fs.closeSync(sourceParentDescriptor);
    }
    return {
      path: destination,
      previous_path: source,
      hash: existing.hash,
      change_summary: "moved text document",
      diff: unifiedDiff(source, destination, existing.contents, existing.contents),
    };
  }
}
