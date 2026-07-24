# ADR 0007: Fail closed for sensitive sources

Status: Accepted, with the generic root-view scope refined by ADR 0015

Known credential stores, login sessions, real environment files, private keys, control sockets, the ShellBridge database, registered sensitive paths, and aliases to blocked objects must not enter generic command output. Unknown configuration structures use `inspect_config`; they are not made safe by client claims, encoding, splitting, redirection, or confirmation.

Source identity and path policy use canonical object checks and defend against symlinks, hard links, bind mounts, path traversal, and classification/execution races. stdout, stderr, errors, and audit output share the same redaction boundary.
