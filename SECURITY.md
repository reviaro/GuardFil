# Security policy

GuardFil is alpha software. Read the [limits](README.md#limits) before
relying on it as a security boundary.

## Supported versions

Only the latest alpha release and `main` receive fixes.

## Reporting a vulnerability

Do not open a public issue. Use **Report a vulnerability** on the
repository's [Security tab](https://github.com/reviaro/GuardFil/security/advisories/new)
(GitHub private vulnerability reporting). If that is unavailable, contact the
maintainer through their [GitHub profile](https://github.com/reviaro) and ask
for a private channel before sharing details.

Please include the commit or release, the runtime (Codex, Claude Code or
Python), your policy if relevant, and the smallest steps that reproduce it.
Do not include real API keys or other secrets.

This is a one-maintainer project: expect an acknowledgement within about a
week. There is no bug bounty.

## What counts

In scope: anything that lets an agent in the executor do what policy blocks or
holds, without the owner's approval. For example: reaching the network, a
provider key, host files or GuardFil's own state; reading or writing workspace
paths that policy denies; answering its own held call; bypassing MCP, gateway
or website rules for calls they cover; or exceeding the spending ledger.

Out of scope: the documented [limits](README.md#limits); attacks that need a
compromised host, Docker daemon or owner account; and what an allowed program
or allowed data flow can do by design.
