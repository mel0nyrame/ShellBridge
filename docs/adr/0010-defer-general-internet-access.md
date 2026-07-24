# ADR 0010: Defer internet access

Status: Accepted

ShellBridge does not provide `curl`, `wget`, HTTP response bodies, downloads, external write requests, authenticated APIs, package installation, or server-side connectivity probes. Generic and project-task sandboxes have no network.

A future network feature requires a separate threat model and ADR covering SSRF, redirects, DNS rebinding, private and link-local targets, cloud metadata, credentials, response limits, and downloaded content. It must not weaken the existing offline profiles.
