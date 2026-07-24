# ADR 0001: Automatic redacted configuration reads

Status: Accepted

Sensitive configuration is inspected through `inspect_config`, not generic shell output. A local administrator registers exact targets, roots, selectors, and any non-secret string values that may be disclosed. Credential-shaped fields return status only. Parse failures, unknown selectors, and unregistered targets fail closed without returning raw content.

The same redaction rules apply to responses, errors, and stored audit data. Client confirmation cannot authorize returning a secret.
