Headless click-through of the GuardFil playground (system Chrome + playwright-core, no browser download).
  npm install            # once
  bash ../playground.sh <worktree>
  curl -s -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:8787/api/policy/reset
  node run.js            # prints PASS/FAIL per step, screenshots *.png here
On Linux set the browser: CHROME=/usr/bin/chromium node run.js (or /usr/bin/google-chrome).
The harness uses bypassCSP because the page's CSP (script-src 'self') blocks Playwright's evaluate.
