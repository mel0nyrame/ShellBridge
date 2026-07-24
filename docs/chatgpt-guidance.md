# ChatGPT connection guidance

Connect ChatGPT to:

```text
https://shellbridge.example.com/mcp
```

Set `SHELLBRIDGE_PUBLIC_BASE_URL` to the deployment's exact HTTPS origin. ShellBridge publishes the OAuth metadata ChatGPT needs at:

- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource/mcp`

Start with read-only inspection. Use `inspect_config` only for registered configuration fields, and do not ask the shell to reveal blocked credentials or host control sockets.

Persistent tools may be unavailable because local write switches are disabled. Do not reinterpret a disabled result as a request to find another write path. For prepare/execute tools, show the complete proposal to the user, pass only its returned `approval_id` to `execute_proposal`, and stop if confirmation is refused.

ChatGPT should treat `blocked`, `disabled`, and approval errors as final policy decisions rather than prompts to bypass ShellBridge's controls.
