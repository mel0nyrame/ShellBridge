# ADR 0015: Expose a precisely filtered root read view

Status: Accepted

Root-host mode presents the configured read root, `/root` by default, at its original path through read-only file-descriptor mounts. Projects, hidden directories, source, Git worktrees, dependencies, build products, caches, and ordinary logs do not require registration.

Exact policy hides registered sensitive paths and object aliases, authentication material, login sessions, real `.env` files, PEM private keys, ShellBridge data, sockets and device nodes, and symlinks escaping the read root or entering blocked objects. Example environment files and ordinary paths merely named cache, log, state, or config remain visible.

The root object is pinned and validated before scanning and mounting. Object identity is rechecked to resist races. Root validation, sensitive-content scanning, masking, read-only mounting, or isolation failure causes the request to fail closed. Additional mounts found beneath a read root are conservatively rejected.
