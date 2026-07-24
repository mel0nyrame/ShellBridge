# Implementation status

Implemented and covered by ordinary or privileged tests: Bearer/OAuth authentication; full Bash syntax in a read-only Bubblewrap view; exact credential, session, `.env`, private-key, socket, escaping-link, database, and registered-path masking; non-root execution; NoNewPrivileges; empty capabilities; PID/proc/network namespaces; network and Unix-socket seccomp; fixed-object fd mounts; cgroup/rlimit/timeout/output limits; registered configuration selection; fixed host-command observation; and disposable project tasks.

Implemented persistent capabilities: atomic Markdown/TXT create, replace, patch, and move; local Git status, stage, unstage, and frozen commit proposals; and frozen pre-existing script execution with cancellation and replay prevention. All remain subject to local kill switches.

Not implemented: push, pull, fetch, remote changes, arbitrary host-write shell, generic shell write proposals, source/configuration structured edits, package changes, active deployment, or service management.
