# Implementation defaults

- The root-managed service never evaluates client shell directly on the host; generic shell text enters Bubblewrap.
- Generic diagnostics use a non-root UID/GID, NoNewPrivileges, zero capabilities, new user/PID/proc/network namespaces, read-only fd mounts, private temporary filesystems, network and Unix-socket seccomp, cgroup limits, and rlimits.
- The default read view is `/root`. Exact deny rules and object/content checks hide credentials, login sessions, control sockets, real `.env` files, PEM private keys, ShellBridge database files, and administrator-registered sensitive paths.
- Command timeout defaults to 15 seconds, output to 32 KiB, HTTP request bodies to 256 KiB, and proposal lifetime to 10 minutes.
- Proposal payloads are sealed with AES-256-GCM in SQLite WAL storage and belong to one stable owner principal.
- TOTP, remote Git, package modification, general network access, and opaque host code execution are not implemented.
- All write capabilities are controlled by a total local switch plus capability-specific switches, and every switch defaults to off.
- OpenAPI consequential annotations express client expectations only. The backend always rechecks authentication, capability state, proposal integrity, expiry, and exact frozen state.
