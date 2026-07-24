# ADR 0003: One stable owner principal

Status: Accepted

The Public Preview has one stable owner principal. The administrator Bearer token and OAuth access tokens are credentials for that owner, not separate users. Credential rotation does not change proposal ownership, stored audit state, or replay protection.

The data model associates proposals and OAuth state with the stable principal so that a future migration is possible, but this release does not implement multiple users, roles, or tenant isolation.
