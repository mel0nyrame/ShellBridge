# MCP client guidance

Connect an MCP client to:

```text
https://shellbridge.example.com/mcp
```

The deployment must set the same origin in `SHELLBRIDGE_PUBLIC_BASE_URL`. OAuth metadata is available at:

- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource/mcp`

Prefer read-only inspection first. Use `inspect_config` for registered configuration fields and `inspect_command` for fixed host-command observation. Do not ask the generic shell to reveal blocked credentials or host control sockets.

Persistent tools may be unavailable because local write switches are disabled. Do not reinterpret a disabled result as a request to find another write path. For prepare/execute tools, show the complete proposal to the user, pass only its returned `approval_id` to `execute_proposal`, and stop if confirmation is refused.

Tool annotations describe expected client behavior but are not authorization. The server independently authenticates, checks local switches, validates proposal integrity and expiry, rechecks frozen state, and prevents replay.
