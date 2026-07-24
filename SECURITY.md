# Security policy

## Supported versions

ShellBridge is currently a Public Preview. Security fixes target the latest `0.3.x` release and the default branch. Older snapshots may not receive fixes.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting for this repository. Do not open a public issue containing a vulnerability, Bearer token, OAuth secret, data key, private configuration, host log, database, public IP, or deployment topology.

Include a minimal description, affected version or commit, reproduction conditions, impact, and any suggested mitigation. Please remove real credentials and personal data. There is currently no bug-bounty program or guaranteed response SLA.

Ordinary functional bugs that do not expose secrets, cross a security boundary, gain authority, or undermine proposal integrity may be reported in public issues.

## Deployment responsibilities

Deployers are responsible for host isolation, patching, HTTPS, reverse-proxy configuration, firewalling, local key storage, file permissions, backups, and deciding which roots can be exposed. ShellBridge does not support direct public listening; the service is fixed to loopback.

All persistent write capabilities are disabled by default. A client confirmation interface is a user-experience signal, not cryptographic backend authorization. The backend relies on authentication, local kill switches, immutable proposals, state revalidation, atomic claiming, and replay prevention.

Review [docs/threat-model.md](docs/threat-model.md) before deploying. ShellBridge does not protect against a malicious host root, a compromised kernel, or a deployment that leaks its local secrets.
