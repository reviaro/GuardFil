// Claude Code tool-set checks: run against a playground started with -tools claude-code.
const { chromium } = require('playwright-core');
const BASE = process.env.BASE || 'http://127.0.0.1:8787';
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true });
  const page = await browser.newPage({ bypassCSP: true });
  await page.goto(BASE + '/');
  await page.waitForFunction(() => document.querySelectorAll('#tool-select option').length > 1);
  const opts = await page.$$eval('#tool-select option', os => os.map(o => o.value));
  const ids = (await (await page.request.get(BASE + '/api/state')).json()).tool_map.map(e => e.id);
  const missing = ids.filter(id => !opts.includes(id));
  await page.click('#tab-policy-btn');
  const ts = (await page.textContent('#policy-tool-set')).trim();
  let fail = 0;
  const check = (n, c, d) => { console.log((c ? 'PASS ' : 'FAIL ') + n + (d ? '  [' + d + ']' : '')); if (!c) fail++; };
  check('dropdown lists every tool_map id', ids.length > 0 && missing.length === 0, 'ids=' + ids.length + ' missing=' + missing.join(','));
  check('policy tab shows tool set claude-code', ts === 'claude-code', ts);
  await browser.close();
  console.log(fail ? 'CC-MODE: ' + fail + ' FAILED' : 'CC-MODE: ALL PASSED');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('CRASH', e); process.exit(2); });
