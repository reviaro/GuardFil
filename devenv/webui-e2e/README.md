Headless click-through of the GuardFil control UI (`internal/webui`) against a real `guardfil`
with the approval service and UI active. Uses the pinned Playwright image (Chromium included),
so nothing is installed on the host.

    docker pull mcr.microsoft.com/playwright:v1.49.1-noble
    docker run --rm --user $(id -u):$(id -g) -e HOME=/tmp -v "$PWD/devenv/webui-e2e:/e2e" -w /e2e \
      mcr.microsoft.com/playwright:v1.49.1-noble npm install --no-audit --no-fund   # once
    go build -o /tmp/guardfil ./cmd/guardfil        # or the docker build from the README
    devenv/webui-e2e/run.sh /tmp/guardfil

It logs in (and checks a wrong token fails), adds an "ask me" rule and deletes the allow rule
through the form, sends a shell request to the approval socket and clicks **Allow**, checks a
bad folder and invalid YAML are refused, adds an amount rule on the stock-app catalog's
`place_order` (a comma in the amount is refused) and a Filter rule, restores the policy file, checks the phone layout in
dark mode, and logs out. It prints PASS/FAIL per step and writes screenshots to `shots/`.

The polish checks also exercise keyboard tab navigation, approval focus across
polls, connection-loss recovery, submit progress, and correcting a rejected
content-list save. Both tabs are checked at 320, 768 and 1440 pixels in light
and dark themes for page overflow, named controls and stretched form fields.
The loopback cookie-replay and invisible-preview regressions remain included.

`workflows.js` exercises the remaining editing controls against live decisions:
valid YAML/JSON saves and discards, saved-version restores and cancellations,
file read/write rules, Website allow/block/monitor/approval, new and existing
principals, all six amount comparisons, content Edit/Cancel/Delete/Restore,
case sensitivity, directions, tool scopes, all injection actions, result
Allow/Deny, and the Try form. It checks persistence through browser reload.
The fixture includes both the stock-app and executor tool catalogs. Backend
restart and operation with no UI are checked by `devenv/headless-e2e/run.py`.

The page's CSP has no `unsafe-eval`, so the script waits with Playwright locators rather than
`waitForFunction`. Only the phone-width measurement uses a context with `bypassCSP`.

`node_modules/` and `shots/` are git-ignored, but `scripts/check-clean.sh` (used by CI and the
reproducibility gate) rejects ignored files too: delete them before running those checks.
