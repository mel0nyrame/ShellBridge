# ADR 0008: Isolate opaque code execution

Status: Accepted

Client confirmation cannot make interpreter code, nested shell, unknown scripts, downloaded code, binaries, or plugins safe for unrestricted host-root execution.

General shell and project tasks run with a non-root identity, NoNewPrivileges, zero capabilities, read-only host mounts or a disposable project copy, no network, no host control sockets, a clean environment, no TTY, and bounded CPU, memory, process count, time, files, and output. If the isolation boundary cannot be built and verified, execution fails closed.

The only host-side script capability is for a pre-existing script under the operation root. Its inode, content hash, interpreter, arguments, working directory, environment profile, and resource limits are frozen in a proposal and revalidated before execution. ShellBridge cannot create or replace that script through this capability.
