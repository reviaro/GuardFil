Run against compiled binaries:

```sh
go build -o /tmp/guardfil ./cmd/guardfil
go build -o /tmp/guardfil-approve ./cmd/guardfil-approve
python3 -B devenv/headless-e2e/run.py /tmp/guardfil /tmp/guardfil-approve
```

This starts a real GuardFil process and a local fake app on dynamically selected
ports. It uses fresh owner-only configuration and synthetic credentials. It
checks UI-absent and UI-inactive startup, live allow/monitor/deny decisions,
owner-socket approval/denial/expiry, Python decorator side effects and result
filtering, content and injection rules, gateway TCP/Unix transport and credential
redaction, named sessions and revocation, policy/content file changes across
restart, logs, and the standalone approval CLI. It cleans up its processes and
temporary files. No provider API or real credential is used. CI runs this suite.

Website enforcement has real TLS upstream tests in
`internal/gateway/website_test.go`; native fetch projection, deny precedence and
URL ambiguity checks are in `internal/approval/website_rules_test.go`. The
scripted Codex and Claude runtime suites also run with the UI omitted.

For the shipped Python agent, run this additional test with Docker and the
pinned executor image available:

```sh
python3 -B devenv/headless-e2e/python_runtime.py /tmp/guardfil
```

It invokes `guardfil-local.sh run-agent --runtime python` with a scripted
neutral model broker. The real networkless executor performs an allowed note
write and read; a blocked write must leave no file. It verifies decisions and
session cleanup. This test also runs in the CI executor job. The broker override
serves only local scripted replies and never reads provider credentials.
