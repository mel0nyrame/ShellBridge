# ADR 0004: Preserve the incremental agent loop

Status: Accepted

Clients submit the operation currently needed, observe the result, and decide the next step. ShellBridge does not require a complete investigation plan or implement a workflow engine.

Generic diagnostic commands and explicit diagnostic batches run only in the read-only sandbox and never create write proposals. Typed consequential operations may prepare one immutable proposal. The client can inspect, execute, or cancel that proposal; execution returns the result so the original incremental task can continue. A proposal never authorizes future, undisclosed operations.

Each batch item has its own command, working directory, timeout, and output limit. Items do not share an interactive shell, `cd`, exported variables, aliases, or other implicit state.
