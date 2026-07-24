# ADR 0006: Protect the ShellBridge trust root

Status: Accepted

ShellBridge configuration, credentials, database, audit state, native helper, policy code, service definition, reverse-proxy credentials, and process-control interfaces form the trust root. API operations must not modify, stop, replace, or delete these resources.

Upgrades, restarts, credential rotation, capability enablement, and recovery remain local root-administrator tasks. Client confirmation cannot downgrade a permanently blocked trust-root operation.
