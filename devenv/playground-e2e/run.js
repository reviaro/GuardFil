// Headless click-through of the GuardFil playground using the system Chrome.
const { chromium } = require('playwright-core');
const BASE = process.env.BASE || 'http://127.0.0.1:8787';
const OUT = __dirname;
let failures = 0;
function check(name, cond, detail) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (detail ? '  [' + detail + ']' : ''));
  if (!cond) failures++;
}

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true });
  const page = await browser.newPage({ bypassCSP: true, viewport: { width: 1280, height: 900 } });
  const consoleErrors = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('pageerror', e => consoleErrors.push(String(e)));
  page.on('dialog', d => { consoleErrors.push('DIALOG: ' + d.message()); d.dismiss(); });
  await page.goto(BASE + '/');
  await page.waitForFunction(() => document.querySelectorAll('#tool-select option').length > 1);

  async function evalPreset(id, extra) {
    await page.click('#tab-evaluate-btn');
    await page.click('#' + id);
    if (extra) await extra();
    const before = await page.textContent('#decision-fields').catch(() => '');
    await page.click('#submit-evaluate');
    await page.waitForFunction(b => !document.querySelector('#result-card').classList.contains('hidden') && document.querySelector('#decision-fields').textContent !== b, before);
    return {
      badge: (await page.textContent('#badge-effect')).trim(),
      summary: (await page.textContent('#result-summary')).trim(),
      fields: await page.textContent('#decision-fields'),
      envelope: await page.textContent('#envelope-pre'),
    };
  }

  let r = await evalPreset('preset-allow-read');
  check('allowed read -> ALLOW POLICY_ALLOWED', r.badge === 'ALLOW' && r.summary.startsWith('POLICY_ALLOWED'), r.badge + ' ' + r.summary);
  check('allowed read -> dispatch_eligible false', /dispatch_eligiblefalse/.test(r.fields));
  await page.screenshot({ path: OUT + '/01-allow.png', fullPage: true });

  r = await evalPreset('preset-deny-delete');
  check('denied delete -> BLOCK POLICY_DENIED (policy)', r.badge === 'BLOCK' && r.summary === 'POLICY_DENIED (policy)', r.summary);
  check('denied delete -> guardfil.error/1 envelope', r.envelope.includes('"guardfil.error/1"') && r.envelope.includes('not_dispatched'));
  await page.screenshot({ path: OUT + '/02-deny.png', fullPage: true });

  r = await evalPreset('preset-no-cred');
  check('no credential -> AUTH_REQUIRED (auth)', r.summary === 'AUTH_REQUIRED (auth)', r.summary);
  r = await evalPreset('preset-malformed');
  check('malformed -> PARSE_INVALID (parse)', r.summary === 'PARSE_INVALID (parse)', r.summary);
  r = await evalPreset('preset-unknown-tool');
  check('unknown tool -> TOOL_REVISION_UNKNOWN (normalize)', r.summary === 'TOOL_REVISION_UNKNOWN (normalize)', r.summary);
  r = await evalPreset('preset-expired-env');
  check('expired envelope -> DEADLINE_EXCEEDED (policy)', r.summary === 'DEADLINE_EXCEEDED (policy)', r.summary);
  r = await evalPreset('preset-allow-read', async () => { await page.check('#cancelled-check'); });
  check('cancelled -> CANCELLED (policy)', r.summary === 'CANCELLED (policy)', r.summary);
  r = await evalPreset('preset-allow-read', async () => { await page.fill('#payload-input', '{"note_id":"a\\nb"}'); });
  check('\\n escape in string -> BLOCK', r.badge === 'BLOCK', r.summary);
  r = await evalPreset('preset-allow-read', async () => { await page.fill('#payload-input', '  {"note_id":"x"}\n'); });
  check('surrounding whitespace (kernel decides)', r.badge === 'ALLOW' || r.badge === 'BLOCK', r.badge + ' ' + r.summary);
  r = await evalPreset('preset-allow-read', async () => { await page.selectOption('#credential-select', 'expired'); });
  check('expired credential -> AUTH_INVALID (auth)', r.summary === 'AUTH_INVALID (auth)', r.summary);
  r = await evalPreset('preset-allow-read', async () => { await page.fill('#ttl-input', '60000'); });
  const rec = /received_at(\S+?Z)/.exec(r.fields), dl = /deadline_at(\S+?Z)/.exec(r.fields);
  const span = rec && dl ? Date.parse(dl[1]) - Date.parse(rec[1]) : -1;
  check('ttl 60000 -> ALLOW, clamped to 30 s', r.badge === 'ALLOW' && span === 30000, 'span=' + span);
  await page.click('#preset-allow-read');
  await page.fill('#ttl-input', '0');
  await page.click('#submit-evaluate');
  await page.waitForTimeout(1000);
  const banner = await page.textContent('#error-banner');
  const bannerVisible = await page.isVisible('#error-banner');
  const nativeInvalid = await page.$eval('#ttl-input', el => !el.checkValidity());
  check('ttl 0 -> rejected (banner or native validation), no dialog', (bannerVisible && /ttl/i.test(banner)) || nativeInvalid, 'banner=' + bannerVisible + ' ' + banner + ' nativeInvalid=' + nativeInvalid);
  // bypass native validation to hit the server's 400 path
  await page.$eval('#ttl-input', el => { el.removeAttribute('min'); el.removeAttribute('max'); });
  await page.click('#submit-evaluate');
  await page.waitForFunction(() => !document.querySelector('#error-banner').classList.contains('hidden'));
  check('server 400 shown in error banner', /ttl/i.test(await page.textContent('#error-banner')), await page.textContent('#error-banner'));

  // Policy tab
  await page.click('#tab-policy-btn');
  const digest0 = (await page.textContent('#policy-digest')).trim();
  const src = await page.inputValue('#policy-source');
  await page.fill('#policy-source', src.replace('id: allow-read\n   effect: allow', 'id: allow-read\n   effect: deny'));
  await page.click('#policy-apply-btn');
  await page.waitForFunction(d => document.querySelector('#policy-digest').textContent.trim() !== d, digest0);
  const digest1 = (await page.textContent('#policy-digest')).trim();
  check('policy edit changes digest', digest1 !== digest0, digest0.slice(0, 20) + ' -> ' + digest1.slice(0, 20));
  r = await evalPreset('preset-allow-read');
  check('after policy edit read -> POLICY_DENIED', r.summary === 'POLICY_DENIED (policy)', r.summary);
  await page.click('#tab-policy-btn');
  await page.fill('#policy-source', 'not: [valid');
  await page.click('#policy-apply-btn');
  await page.waitForTimeout(1000);
  const pe = await page.isVisible('#policy-error');
  check('invalid policy -> error shown IN POLICY TAB with keep-old note', pe && /stays active/.test(await page.textContent('#policy-error')), 'policy-error visible=' + pe + ' banner=' + await page.textContent('#error-banner'));
  check('invalid policy -> digest kept', (await page.textContent('#policy-digest')).trim() === digest1);
  await page.screenshot({ path: OUT + '/03-policy-error.png', fullPage: true });
  await page.click('#policy-reset-btn');
  await page.waitForFunction(d => document.querySelector('#policy-digest').textContent.trim() === d, digest0);
  check('reset restores default digest', true);
  r = await evalPreset('preset-allow-read');
  check('after reset read -> ALLOW', r.badge === 'ALLOW', r.summary);

  // Fixtures
  await page.click('#tab-fixtures-btn');
  await page.click('#run-fixtures-btn');
  await page.waitForFunction(() => document.querySelectorAll('#fixtures-tbody tr').length > 0);
  const rows = await page.$$eval('#fixtures-tbody tr', trs => trs.map(t => Array.from(t.children).map(c => c.textContent)));
  const allows = rows.filter(x => x[2] === 'ALLOW').map(x => x[0]);
  check('fixtures: only allow-read ALLOW', allows.length === 1 && allows[0] === 'allow-read', allows.join(','));
  check('fixtures: dispatch_eligible false everywhere', rows.every(x => x[7] === 'false'));
  check('fixtures summary computed', /fixtures/.test(await page.textContent('#fixtures-summary')), await page.textContent('#fixtures-summary'));
  await page.screenshot({ path: OUT + '/04-fixtures.png', fullPage: true });

  // History
  await page.click('#tab-history-btn');
  await page.waitForFunction(() => document.querySelectorAll('#history-tbody tr').length > 0);
  const hist = await page.$$eval('#history-tbody tr', trs => trs.length);
  check('history populated', hist >= 10, 'rows=' + hist);
  check('counters shown', /guardfil_decision_allows_total/.test(await page.textContent('#counters-pre')));
  await page.screenshot({ path: OUT + '/05-history.png', fullPage: true });
  await page.click('#history-tbody tr');
  check('history row reopens result card', await page.isVisible('#result-card'));

  // Narrow viewport
  await page.setViewportSize({ width: 400, height: 900 });
  await page.click('#tab-evaluate-btn');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check('400px: no horizontal page scroll', overflow <= 0, 'overflow=' + overflow);
  await page.screenshot({ path: OUT + '/06-narrow.png', fullPage: true });

  const unexpected = consoleErrors.filter(e => !/status of (400|422)/.test(e));
  check('no unexpected console errors or dialogs (400/422 are the deliberate negative cases)', unexpected.length === 0, unexpected.join(' | '));
  await browser.close();
  console.log(failures === 0 ? 'E2E: ALL PASSED' : 'E2E: ' + failures + ' FAILED');
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('E2E CRASH', e); process.exit(2); });
