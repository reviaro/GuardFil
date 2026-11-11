# GuardFil advisory demo

`go run ./cmd/guardfil-advisory-demo` evaluates a fixed, made-up fake-tool fixture set through the existing action, policy, identity, and decision kernel. It is advisory only: `ALLOW` is diagnostic, `dispatch_eligible` is always false, and no tool is executed.

The command has no listener, executor, fixture-selected filesystem access, network client, or server dependency. Its report and fixtures are visibly synthetic and are not a replay of agent traffic.

Each row also records `fake_tool_known`, `auth`, and the producing `stage`. `kernel_reason` is returned by the action or decision kernel; tool lookup is reported separately.
