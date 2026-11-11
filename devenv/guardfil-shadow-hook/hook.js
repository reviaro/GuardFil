#!/usr/bin/env node
// GuardFil shadow hook for Claude Code (PreToolUse). Advisory only.
// Sends ONLY the mapped tool ID and payload {} to the local playground; tool
// arguments never leave this process. Always exits 0 and prints nothing to
// stdout, so it can never block or alter a tool call. Fails open on any error.
'use strict';
const http = require('http');

const URL_HOST = '127.0.0.1';
const RAW_PORT = Number(process.env.GUARDFIL_SHADOW_PORT || 8787);
const PORT = Number.isInteger(RAW_PORT) && RAW_PORT >= 1 && RAW_PORT <= 65535 ? RAW_PORT : 8787;
const TIMEOUT_MS = 1000; // hard cap for the whole hook, including a slow-dripping listener
const DEBUG = process.env.GUARDFIL_SHADOW_DEBUG === '1';

// Exact-name map; must match the playground's claude-code tool set. No case folding:
// unmapped names are sent unchanged so the kernel reports them as unknown/invalid.
const TOOL_MAP = {
  Bash: 'cc.bash', PowerShell: 'cc.powershell', Read: 'cc.read', Write: 'cc.write', Edit: 'cc.edit',
  MultiEdit: 'cc.multi_edit', Glob: 'cc.glob', Grep: 'cc.grep',
  WebFetch: 'cc.web_fetch', WebSearch: 'cc.web_search', Task: 'cc.task',
  Agent: 'cc.agent', TodoWrite: 'cc.todo_write', NotebookEdit: 'cc.notebook_edit',
};

function debug(msg) { if (DEBUG) process.stderr.write('[guardfil-shadow] ' + msg + '\n'); }
// Only echo kernel-shaped tokens, so a foreign listener on the port can't inject terminal escapes.
function token(v) { return typeof v === 'string' && /^[A-Z_]{1,64}$/.test(v) ? v : '?'; }

let done = false;
function finish() { if (!done) { done = true; process.exit(0); } }
process.on('uncaughtException', finish);
setTimeout(finish, TIMEOUT_MS).unref();

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { if (input.length < 1 << 20) input += c; });
process.stdin.on('error', finish);
process.stdin.on('end', () => {
  let name;
  try {
    name = JSON.parse(input).tool_name;
  } catch (_) {
    // Oversized (truncated) input: recover just the tool name so the call still shows in History.
    const m = /"tool_name"\s*:\s*"([^"\\]{1,256})"/.exec(input);
    if (!m) { debug('skipped: unparseable input'); return finish(); }
    name = m[1];
  }
  if (typeof name !== 'string' || name === '') return finish();
  const tool = Object.prototype.hasOwnProperty.call(TOOL_MAP, name) ? TOOL_MAP[name] : name;
  const body = JSON.stringify({
    tool,
    payload_b64: Buffer.from('{}').toString('base64'),
    credential: 'valid',
    ttl_ms: 30000,
  });
  let req;
  try {
  req = http.request({
    host: URL_HOST, port: PORT, path: '/api/evaluate', method: 'POST', timeout: TIMEOUT_MS,
    agent: false, // direct loopback connection, never an env-configured proxy
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  }, (res) => {
    let out = '';
    res.setEncoding('utf8');
    res.on('data', (c) => { if (out.length < 65536) out += c; });
    res.on('end', () => {
      try { const r = JSON.parse(out); debug(tool + ' -> ' + token(r.effect) + ' ' + token(r.code)); } catch (_) { debug(tool + ' -> HTTP ' + res.statusCode); }
      finish();
    });
    res.on('error', finish);
  });
  req.on('timeout', () => { req.destroy(); debug('timeout'); finish(); });
  req.on('error', (e) => { debug('unreachable: ' + token(e.code)); finish(); });
  req.end(body);
  } catch (_) { finish(); }
});
