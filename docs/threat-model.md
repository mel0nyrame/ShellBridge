# Threat model

## Security goals

ShellBridge aims to protect:

- host secrets and authentication material;
- its Bearer, OAuth, encryption, and configuration trust roots;
- its SQLite database and immutable proposals;
- host files and write capabilities;
- the integrity and replay state of consequential operations.

## Trusted components

The local root administrator, reviewed ShellBridge source and native helper, Linux kernel, Bubblewrap, namespaces, seccomp, cgroup v2, and local root-owned configuration are trusted.

## Untrusted input

Treat model-generated shell, MCP arguments, dynamic OAuth client metadata, repository contents, existing scripts, project task output, filenames, symlinks, and command output as untrusted.

## Main boundaries

General shell text enters only a non-root Bubblewrap environment with a read-only host view, private namespaces, no network, no Unix sockets, no capabilities, NoNewPrivileges, resource limits, timeouts, and output limits. Sensitive resources are removed through exact path and object checks; detected credentials and private keys are not exposed.

Configuration inspection is limited to administrator-registered targets and selectors. Credential-shaped fields are status-only; allowed cleartext values require an explicit target-and-selector disclosure policy.

Persistent operations are separate typed capabilities. Local switches default to off. Git commits and pre-existing scripts freeze relevant identity, content, arguments, state, and limits into encrypted proposals. Execution revalidates state and atomically claims the proposal before acting.

OAuth binds tokens to one owner principal and the configured MCP resource. REST Bearer access is an administrator credential. Neither OpenAPI annotations nor client confirmation UI are treated as backend proof of consent.

## Non-goals

ShellBridge does not attempt to defend against:

- a malicious or compromised host root;
- Linux kernel or trusted dependency vulnerabilities;
- complete side-channel resistance;
- multiple mutually untrusted tenants;
- arbitrary network access or arbitrary host-write shell;
- remote Git operations or package management;
- automatic deployment, upgrades, proxy configuration, or recovery.

Use a dedicated VPS, VM, or otherwise clearly isolated host. ShellBridge is one control layer, not a replacement for host isolation and standard server security.
