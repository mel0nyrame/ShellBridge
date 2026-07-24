# MCP interface

ShellBridge exposes Streamable HTTP MCP at:

```text
https://shellbridge.example.com/mcp
```

The public URL is configured by `SHELLBRIDGE_PUBLIC_BASE_URL`. OAuth issuer, protected-resource metadata, and the MCP resource are derived from the same value.

Read-only tools include general sandboxed shell commands and batches, registered configuration inspection, fixed command observation, disposable project tasks, local Git status, and proposal inspection. The shell supports full Bash syntax but sees only the configured read-only view. It cannot observe host network state, host process namespaces, systemd control sockets, or other masked resources.

Persistent tools cover restricted Markdown/TXT files, local Git index changes, exact local commits, and pre-existing scripts. The total write switch and relevant capability switch must be enabled locally.

`execute_proposal` accepts only an `approval_id`. The proposal is an immutable execution plan and replay-control record, not a server-hosted approval UI. A client should show its normal confirmation UI and must stop on refusal.

OAuth supports dynamic public-client registration, Authorization Code with PKCE S256, state, RFC 8707 resource binding, `offline_access`, and refresh-token rotation. The owner consent page uses a separate secret and restricts redirects to configured hosts. Tokens are stored as SHA-256 digests, and OAuth audit records never contain token material.

Tool annotations are client hints. Enforcement remains server-side through authentication, local kill switches, typed inputs, exact path policy, read-only mounts, namespaces, seccomp, cgroup/rlimit, openat2, output redaction, and proposal validation.
