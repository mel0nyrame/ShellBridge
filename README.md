# ShellBridge

ShellBridge is a security-focused MCP server that gives AI clients controlled access to a Linux host. General shell diagnostics run inside a read-only, network-isolated Bubblewrap sandbox. Persistent changes are limited to explicit document, local Git, and pre-existing script capabilities, with local kill switches and immutable execution proposals.

> **v0.3.0 Public Preview:** ShellBridge is not production-ready. It does not replace a dedicated VPS, virtual machine, container boundary, low-privilege account, HTTPS, or ordinary host hardening.

## Why not expose SSH?

An SSH session usually gives its caller a broad interactive authority. ShellBridge instead exposes narrow, auditable MCP tools:

- general Bash diagnostics run as an unprivileged identity in a read-only mount view;
- network and Unix socket creation are blocked with namespaces and seccomp;
- selected configuration fields can be inspected only through registered, redacting readers;
- persistent operations are separate capabilities, disabled by default;
- consequential script and Git commit operations freeze their exact inputs before execution.

The service remains high-privilege infrastructure because a root-managed process constructs these boundaries and controls host paths.

```text
AI client
   │  HTTPS + OAuth/Bearer
   ▼
reverse proxy or authenticated tunnel
   │  loopback only
   ▼
ShellBridge 127.0.0.1:8765
   ├─ read-only Bubblewrap + seccomp + cgroup
   ├─ registered redacted configuration reads
   └─ locally enabled document/Git/script capabilities
```

## Current capabilities

- Streamable HTTP MCP with Bearer authentication and single-owner OAuth.
- Full Bash syntax for diagnostics inside a read-only Bubblewrap view.
- Exact sensitive-path masking, output redaction, timeouts, output limits, rlimits, and cgroup controls.
- Registered configuration selectors and fixed host-command observation.
- Existing project tasks in a disposable writable copy with no network access.
- Restricted Markdown/TXT writes under the configured operation root.
- Local-only Git status, stage, unstage, and immutable commit proposals.
- Immutable proposals for pre-existing side-effecting scripts, with expiry and replay prevention.

ShellBridge does not provide arbitrary host-write shell, general internet access, remote Git, package management, automatic deployment, automatic upgrades, or multi-tenant authorization.

## Supported platform

The Public Preview support matrix is intentionally narrow:

- Ubuntu 24.04;
- Linux x86_64;
- Node.js 22 or newer;
- cgroup v2;
- Bubblewrap and a C17 compiler;
- a root-managed service.

The native build fails clearly on unsupported operating systems or CPU architectures. ARM64, Docker, Kubernetes, and arbitrary-user mode are not supported in this release.

## Install and run locally

Install the host prerequisites on Ubuntu 24.04:

```bash
sudo apt-get update
sudo apt-get install --yes build-essential bubblewrap
node --version
```

Install Node.js 22+ using a source you trust, then:

```bash
git clone https://github.com/fengyincheng/ShellBridge.git
cd ShellBridge
npm ci
npm run build
cp .env.example .env
```

Edit `.env` and set at least:

```bash
SHELLBRIDGE_BEARER_TOKEN=replace-with-a-long-random-secret
SHELLBRIDGE_DATA_KEY=replace-with-output-from-openssl-rand-base64-32
SHELLBRIDGE_OAUTH_OWNER_SECRET=replace-with-an-independent-random-secret
SHELLBRIDGE_PUBLIC_BASE_URL=http://127.0.0.1:8765
SHELLBRIDGE_DATABASE_PATH=/tmp/shellbridge-dev.db
```

Generate the data key with:

```bash
openssl rand -base64 32
```

Load the environment, run the read-only preflight, then start:

```bash
set -a
. ./.env
set +a
npm run doctor
npm start
```

The process always listens on loopback. The default is `127.0.0.1:8765`; `SHELLBRIDGE_PORT` may change the port, but the host cannot be configured to `0.0.0.0`. A local health check requires the full Bearer value:

```bash
curl --fail --header "Authorization: Bearer $SHELLBRIDGE_BEARER_TOKEN" \
  http://127.0.0.1:8765/health
```

`npm run doctor` reports prerequisites and configuration only. It does not install packages, edit the host, create a proxy, or enable writes.

## MCP and OAuth

The MCP endpoint is:

```text
https://shellbridge.example.com/mcp
```

For a remote client, set `SHELLBRIDGE_PUBLIC_BASE_URL` to that deployment's exact HTTPS origin. ShellBridge derives its MCP resource, OAuth issuer and metadata, and OpenAPI server from this one value.

Dynamic OAuth clients register at `/oauth/register`, use Authorization Code with PKCE, and are restricted to administrator-configured redirect hosts. The owner authorizes a client using the local `SHELLBRIDGE_OAUTH_OWNER_SECRET`. This establishes the single owner principal; it does not turn a client confirmation dialog into cryptographic backend authorization.

## Write capabilities and proposals

All persistent capabilities are off by default:

```text
SHELLBRIDGE_WRITE_ACTIONS_ENABLED=false
SHELLBRIDGE_DOCUMENT_WRITES_ENABLED=false
SHELLBRIDGE_LOCAL_GIT_WRITES_ENABLED=false
SHELLBRIDGE_EXISTING_SCRIPT_RUNS_ENABLED=false
```

The total switch and the relevant capability switch must both be enabled locally. Enabling one capability does not unlock arbitrary host writes.

Git commits and pre-existing script runs use a prepare/execute flow. Preparation stores an encrypted proposal containing the exact repository or script identity, inputs, limits, and relevant state. Execution revalidates that frozen state, atomically claims the proposal, and prevents replay. Client UI confirmation is expected, but the backend relies on its own local switches and proposal validation.

See [consequential tool contracts](docs/consequential-tools.md) for each tool's exact authority, race checks, idempotence, replay behavior, and kill switch.

## systemd deployment

The example unit assumes the repository is installed at `/opt/shellbridge`:

```bash
sudo git clone https://github.com/fengyincheng/ShellBridge.git /opt/shellbridge
cd /opt/shellbridge
sudo npm ci
sudo npm run build
sudo install -d -o root -g root -m 0700 /etc/shellbridge /var/lib/shellbridge
sudo install -o root -g root -m 0600 \
  deploy/systemd/shellbridge.env.example /etc/shellbridge/shellbridge.env
sudo install -o root -g root -m 0644 \
  deploy/systemd/shellbridge.service /etc/systemd/system/shellbridge.service
```

Stop here and populate every required secret and the correct public URL in `/etc/shellbridge/shellbridge.env`. Do not start the service with the placeholder values. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now shellbridge
```

Review paths for your host; this unit is an Ubuntu 24.04 example, not a universal distribution package.

## HTTPS reverse proxy

Never expose port 8765 directly to the public internet. Put an HTTPS reverse proxy or authenticated tunnel in front of loopback:

```text
HTTPS reverse proxy or authenticated tunnel
    ↓
127.0.0.1:8765
```

The proxy must preserve authorization headers, support streaming HTTP responses, and limit request bodies and timeouts appropriately. ShellBridge does not provision certificates, tunnels, DNS, or firewall rules.

## Security boundaries and limitations

- The root administrator, ShellBridge source and native helper, Linux kernel, Bubblewrap, seccomp, cgroup v2, and local configuration are trusted.
- Model-generated shell, MCP arguments, repository contents, script output, and dynamic OAuth client metadata are untrusted.
- A compromised host root, kernel exploit, complete side-channel resistance, and multi-tenant isolation are out of scope.
- The default read view is `/root`; precise deny rules hide known sensitive resources. Deploy on a dedicated or clearly isolated host and review the configured roots.
- REST OpenAPI is a concise path summary, not a promise of a stable general-purpose REST API.

See [the threat model](docs/threat-model.md), [security policy](SECURITY.md), and [implementation status](docs/implementation-status.md).

## Tests

```bash
npm run test:core
npm run build
```

The ordinary suite uses a controlled test double for generic shell execution and skips privileged native acceptance tests. On a supported, disposable Ubuntu 24.04 x86_64 host with root access, Bubblewrap, and writable cgroup v2:

```bash
sudo --preserve-env=PATH npm run test:privileged
```

Do not run privileged acceptance on a host you have not prepared for destructive mount/cgroup test fixtures.

## Contributing and license

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing a security boundary. Vulnerabilities belong in private vulnerability reports, not public issues.

ShellBridge is licensed under the Apache License 2.0.
