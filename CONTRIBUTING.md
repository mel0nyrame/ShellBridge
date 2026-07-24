# Contributing

ShellBridge v0.3 targets Node.js 22 and Ubuntu 24.04 on Linux x86_64.

```bash
npm ci
npm run check
```

Privileged native acceptance requires a disposable supported host with root access, Bubblewrap, and writable cgroup v2:

```bash
sudo --preserve-env=PATH npm run test:privileged
```

Keep changes focused. Security-boundary changes must include tests and an explanation of the trust assumption being changed. Fail-closed behavior must not be relaxed merely for convenience.

Never commit real secrets, domains, public IPs, private logs, databases, deployment state, or copied production configuration. Use reserved examples such as `shellbridge.example.com` and `bridge.example.test`.

A new consequential tool must document:

- the exact operation and authority it exposes;
- what is frozen during preparation;
- how races are detected before execution;
- whether execution is idempotent;
- how replay is prevented;
- which local kill switch controls it.

Use short imperative commit subjects, such as `fix: reject base URLs with fragments`. Put security vulnerabilities through GitHub Private Vulnerability Reporting rather than a public issue.
