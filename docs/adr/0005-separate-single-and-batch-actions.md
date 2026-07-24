# ADR 0005: Separate single and batch diagnostics

Status: Accepted

`POST /v1/shell/commands` is the default incremental diagnostic endpoint. `POST /v1/shell/batches` is an optional optimization for an already-known list of at most ten diagnostic commands.

Both execute only through the same read-only sandbox. Each batch item is validated independently and execution stops on the first failure. Interface separation improves client intent; it does not create a different security boundary or unlock persistent changes.
