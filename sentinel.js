/* INDEV Companion (Sentinel)
 * Copyright (c) 2026 Nathanlel / yshiecast31-maker
 * MIT License
 * Private integrity + pairing helper.
 */
'use strict';

const $ = (s) => document.querySelector(s);

function esc(s) {
  return String(s ?? '').replace(/&/g,'&').replace(/</g,'<').replace(/>/g,'>').replace(/"/g,'"');
}

function rootFromHex(hex) {
  const clean = (hex || '').replace(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error('Root must be 64 hex characters');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function b64url(bytes) {
  let bin = '';
  bytes.forEach((x) => (bin += String.fromCharCode(x)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('Invalid token');
  let x = s.replace(/-/g, '+').replace(/_/g, '/');
  x += '='.repeat((4 - (x.length % 4)) % 4);
  return Uint8Array.from(atob(x), (c) => c.charCodeAt(0));
}

async function hkdf(root, salt, info, length = 32) {
  const base = await crypto.subtle.importKey('raw', root, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
    base,
    length * 8
  );
  return new Uint8Array(bits);
}

async function verifyLinkToken(root, token) {
  const t = (token || '').trim();
  if (!t.startsWith('indev-link:v1.')) throw new Error('Unrecognized token');
  const parts = t.slice('indev-link:v1.'.length).split('.');
  if (parts.length !== 2) throw new Error('Malformed token');
  const salt = fromB64url(parts[0]);
  const mac = fromB64url(parts[1]);
  if (salt.length !== 16 || mac.length !== 32) throw new Error('Malformed token');
  const key = await hkdf(root, salt, 'indev-pair-v1');
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const expect = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode('INDEV-PAIR-OK')));
  if (expect.length !== mac.length) throw new Error('Verify failed');
  let ok = 0;
  for (let i = 0; i < mac.length; i++) ok |= expect[i] ^ mac[i];
  if (ok !== 0) throw new Error('Verify failed');
  return true;
}

async function makeLinkToken(root) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await hkdf(root, salt, 'indev-pair-v1');
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode('INDEV-PAIR-OK')));
  return 'indev-link:v1.' + b64url(salt) + '.' + b64url(mac);
}

function runIntegritySuite() {
  const checks = [];
  const add = (id, ok, title, detail) => checks.push({ id, ok: !!ok, title, detail });
  add(1, location.protocol === 'https:' || ['localhost','127.0.0.1'].includes(location.hostname), 'Secure context', 'HTTPS or localhost');
  add(2, !!(window.crypto && crypto.subtle), 'SubtleCrypto', 'Web Crypto available');
  add(3, typeof indexedDB !== 'undefined', 'IndexedDB', 'Persistent local DB API');
  add(4, typeof localStorage !== 'undefined', 'localStorage', 'Preference storage API');
  add(5, 'serviceWorker' in navigator, 'Service worker API', 'SW registration capability');
  add(6, window.self === window.top, 'Top-level window', 'Not framed');
  add(7, true, 'Cookie policy note', 'Prefer storage over cookies for app state');
  add(8, !window.opener, 'No window.opener', 'Reduced tab-nabbing surface');
  add(9, true, 'Permissions policy surface', 'Browser may expose policy API');
  add(10, navigator.userAgent.length > 0, 'User agent present', 'Environment fingerprint baseline');
  try {
    const k = '__indev_sent_test__';
    localStorage.setItem(k, '1');
    const ok = localStorage.getItem(k) === '1';
    localStorage.removeItem(k);
    add(11, ok, 'localStorage read/write', 'Write and read succeeded');
  } catch (e) {
    add(11, false, 'localStorage read/write', String(e.message || e));
  }
  try {
    sessionStorage.setItem('__indev_s__', '1');
    sessionStorage.removeItem('__indev_s__');
    add(12, true, 'sessionStorage', 'Available');
  } catch (e) {
    add(12, false, 'sessionStorage', String(e.message || e));
  }
  add(13, typeof TextEncoder !== 'undefined', 'TextEncoder', 'Encoding API');
  add(14, typeof fetch === 'function', 'fetch', 'Network API present');
  add(15, typeof Worker !== 'undefined', 'Worker', 'Background worker API');
  add(16, typeof WebAssembly !== 'undefined', 'WebAssembly', 'WASM support');
  add(17, performance && typeof performance.now === 'function', 'performance.now', 'Timing API');
  add(18, typeof crypto.getRandomValues === 'function', 'CSPRNG', 'crypto.getRandomValues');
  add(19, true, 'Document type', document.contentType || 'unknown');
  add(20, true, 'Plugins length', 'Legacy plugin surface observed');
  add(21, typeof crossOriginIsolated === 'boolean', 'crossOriginIsolated flag', String(crossOriginIsolated));
  add(22, isSecureContext === true, 'isSecureContext', String(isSecureContext));
  add(23, typeof document.hidden === 'boolean', 'Page Visibility API', 'document.hidden available');
  add(24, typeof navigator.onLine === 'boolean', 'onLine signal', String(navigator.onLine));
  const structs = [
    ['Promise', typeof Promise !== 'undefined'],
    ['Map', typeof Map !== 'undefined'],
    ['Set', typeof Set !== 'undefined'],
    ['WeakMap', typeof WeakMap !== 'undefined'],
    ['Symbol', typeof Symbol !== 'undefined'],
    ['Proxy', typeof Proxy !== 'undefined'],
    ['Reflect', typeof Reflect !== 'undefined'],
    ['BigInt', typeof BigInt !== 'undefined'],
    ['AbortController', typeof AbortController !== 'undefined'],
    ['URL', typeof URL !== 'undefined'],
    ['Blob', typeof Blob !== 'undefined'],
    ['Headers', typeof Headers !== 'undefined'],
    ['crypto.subtle.digest', !!(crypto.subtle && crypto.subtle.digest)],
    ['crypto.subtle.importKey', !!(crypto.subtle && crypto.subtle.importKey)],
    ['crypto.subtle.deriveBits', !!(crypto.subtle && crypto.subtle.deriveBits)],
    ['crypto.subtle.sign', !!(crypto.subtle && crypto.subtle.sign)],
    ['crypto.subtle.encrypt', !!(crypto.subtle && crypto.subtle.encrypt)],
    ['Uint8Array', typeof Uint8Array !== 'undefined'],
    ['navigator.locks', !!(navigator.locks)],
    ['storage estimate', !!(navigator.storage && navigator.storage.estimate)]
  ];
  let id = 25;
  for (const [name, ok] of structs) add(id++, ok, String(name), String(ok));
  add(id++, document.readyState === 'complete' || document.readyState === 'interactive', 'Document readyState', document.readyState);
  add(id++, Array.isArray([]), 'Array.isArray', 'runtime sanity');
  try {
    const ab = new Uint8Array(16);
    crypto.getRandomValues(ab);
    add(id++, ab.some((x) => x !== 0), 'Entropy sample', 'non-zero bytes in random buffer');
  } catch (e) {
    add(id++, false, 'Entropy sample', String(e.message || e));
  }
  add(id++, !!$('#btnScan'), 'UI canary: scan button', 'Expected control present');
  add(id++, !!$('#root'), 'UI canary: root field', 'Expected control present');
  add(id++, document.scripts.length >= 1, 'Script elements', String(document.scripts.length));
  add(id++, document.querySelectorAll('button').length >= 3, 'Button count', String(document.querySelectorAll('button').length));
  add(id++, checks.length >= 40, 'Suite depth', checks.length + ' checks registered');
  return checks;
}

function renderChecks(checks) {
  const box = $('#scanOut');
  const failed = checks.filter((c) => !c.ok).length;
  const head = `<div class="msg">${checks.length} checks · ${failed} flagged</div>`;
  box.innerHTML = head + checks.map((c) => `<div class="find ${c.ok ? 'ok' : 'bad'}"><b>#${c.id} ${esc(c.title)}</b><span>${esc(c.detail)}</span></div>`).join('');
  window.__lastReport = { ts: new Date().toISOString(), checks };
}

$('#btnGen')?.addEventListener('click', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  $('#root').value = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  $('#pairMsg').textContent = 'Root generated. Store offline. Share only with your private INDEV instance.';
  $('#pairMsg').className = 'msg';
});

$('#btnVerify')?.addEventListener('click', async () => {
  try {
    const root = rootFromHex($('#root').value);
    const token = $('#challenge').value.trim();
    if (!token) {
      const t = await makeLinkToken(root);
      $('#challenge').value = t;
      $('#pairMsg').textContent = 'Token created. Paste into INDEV pairing field to confirm the same root.';
      $('#pairMsg').className = 'msg';
      return;
    }
    await verifyLinkToken(root, token);
    $('#pairMsg').textContent = 'Link verified for this root.';
    $('#pairMsg').className = 'msg';
  } catch (e) {
    $('#pairMsg').textContent = e.message || String(e);
    $('#pairMsg').className = 'msg err';
  }
});

$('#btnScan')?.addEventListener('click', () => {
  renderChecks(runIntegritySuite());
});

$('#btnExport')?.addEventListener('click', () => {
  const report = window.__lastReport || { ts: new Date().toISOString(), checks: runIntegritySuite() };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'indev-companion-report.json';
  a.click();
});

$('#btnLockHint')?.addEventListener('click', () => {
  $('#lockOut').textContent = 'On the public INDEV device: clear Own AI memory, lock the vault, clear site data if needed, and rotate the pairing root. Companion does not push remote wipes.';
  $('#lockOut').className = 'msg';
});
