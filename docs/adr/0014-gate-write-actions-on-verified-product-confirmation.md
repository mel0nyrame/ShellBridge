# ADR 0014: Gate write actions locally and present client confirmation

Status: Accepted

Consequential tools are marked for client confirmation. Prepare operations only read, validate, preview, and persist a short-lived immutable proposal. Execute operations accept only the proposal identifier and cannot add or override a command, path, argument, or working directory.

Client confirmation is not cryptographic backend authorization. Server-enforced boundaries are authentication, one stable principal, local capability switches, immutable proposal hashes, expiry, exact state revalidation, an atomic pending-to-executing transition, blocked-resource policy, rate limiting, auditing, and replay prevention.

The total write switch and each capability switch default to false and can be changed only in local service configuration. If a client cannot reliably present confirmation, deployers should leave write capabilities disabled.
