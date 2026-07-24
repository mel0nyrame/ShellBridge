# ADR 0009: Keep opaque code offline

Status: Accepted

Opaque code runs in a separate network namespace and cannot reach the internet, DNS, host loopback, private networks, cloud metadata, or Unix network proxies. Proxy environment variables and inherited file descriptors are removed, and seccomp blocks network and Unix socket syscalls.

Network isolation cannot be relaxed by a client or approval. Package installation and lifecycle scripts that require network access are not supported in the Public Preview.
