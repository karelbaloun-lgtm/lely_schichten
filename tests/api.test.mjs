// Spuštění: node tests/api.test.mjs
import assert from 'node:assert/strict';
import { createHandler, sha256, hashPassword, verifyPassword, sanitizeConfig, sanitizeShifts, validUsername } from '../lib/api-core.mjs';

class MemStore {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.has(k) ? structuredClone(this.m.get(k)) : null; }
  async setJSON(k, v) { this.m.set(k, structuredClone(v)); }
  async delete(k) { this.m.delete(k); }
  async list() { return { blobs: [...this.m.keys()].map((key) => ({ key })) }; }
}
const SETUP_KEY = 'test-setup-key';
function makeApi() {
  const stores = { accounts: new MemStore(), sessions: new MemStore(), userdata: new MemStore() };
  const handler = createHandler(() => stores, { setupKeyHash: sha256(SETUP_KEY) });
  async function call(body, token) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    const res = await handler(new Request('http://x/api', { method: 'POST', headers, body: JSON.stringify(body) }));
    return { status: res.status, body: await res.json() };
  }
  return { call, stores, handler };
}
let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; } catch (e) { console.error('FAIL:', name, '\n', e); process.exit(1); }
}
const shift = (id, date, type) => ({ id, date, type: type || 'work', legs: [] });

// ─── čisté funkce ──────────────────────────────────────────────────────────
await test('password hash/verify', () => {
  const h = hashPassword('correct horse');
  assert.ok(verifyPassword('correct horse', h));
  assert.ok(!verifyPassword('wrong', h));
  assert.notEqual(hashPassword('correct horse'), h); // jiná sůl
  assert.ok(!verifyPassword('x', 'garbage'));
});
await test('validUsername', () => {
  assert.ok(validUsername('karel'));
  assert.ok(validUsername('jan.novak-2'));
  assert.ok(!validUsername('ab'));
  assert.ok(!validUsername('Karel'));
  assert.ok(!validUsername('../etc'));
  assert.ok(!validUsername('a b c'));
});
await test('sanitizeConfig drops everything but language/hotelAddressHistory', () => {
  const c = sanitizeConfig({ language: 'cs', firstName: 'Hacker', weeklyNorm: 99, hotelAddressHistory: { 'Hotel A': '2026-01-01', bad: 5 }, evil: 1 });
  assert.deepEqual(c, { language: 'cs', hotelAddressHistory: { 'Hotel A': '2026-01-01' } });
  assert.deepEqual(sanitizeConfig({ language: 'xx' }), {});
});
await test('sanitizeShifts validation', () => {
  assert.equal(sanitizeShifts([shift('a', '2026-01-01')]).length, 1);
  assert.throws(() => sanitizeShifts('x'));
  assert.throws(() => sanitizeShifts([{ id: 'a', date: '2026-1-1', type: 'work' }]));
  assert.throws(() => sanitizeShifts([{ id: 'a', date: '2026-01-01', type: 'hack' }]));
  assert.throws(() => sanitizeShifts([shift('a', '2026-01-01'), shift('a', '2026-01-02')]));
});

// ─── setup & login ─────────────────────────────────────────────────────────
await test('status → needsSetup, setup flow, setup disabled afterwards', async () => {
  const { call } = makeApi();
  assert.deepEqual((await call({ action: 'status' })).body, { needsSetup: true });
  let r = await call({ action: 'setup', setupKey: 'wrong', username: 'karel', password: 'password123' });
  assert.equal(r.status, 403);
  r = await call({ action: 'setup', setupKey: SETUP_KEY, username: 'Karel', password: 'short' });
  assert.equal(r.status, 400);
  r = await call({ action: 'setup', setupKey: SETUP_KEY, username: 'Karel', password: 'password123', firstName: 'Karel', lastName: 'Baloun', weeklyNorm: 40 });
  assert.equal(r.status, 200);
  assert.equal(r.body.user.role, 'admin');
  assert.equal(r.body.user.username, 'karel');
  assert.ok(r.body.token);
  assert.deepEqual((await call({ action: 'status' })).body, { needsSetup: false });
  r = await call({ action: 'setup', setupKey: SETUP_KEY, username: 'other', password: 'password123' });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, 'already_set_up');
});

await test('setup: 10 wrong keys lock guessing, even the right key is refused while locked; no account created', async () => {
  const api = makeApi();
  for (let i = 0; i < 10; i++) {
    assert.equal((await api.call({ action: 'setup', setupKey: '10000' + i, username: 'karel', password: 'password123' })).status, 403);
  }
  const r = await api.call({ action: 'setup', setupKey: SETUP_KEY, username: 'karel', password: 'password123', firstName: 'K', lastName: 'B' });
  assert.equal(r.status, 429);
  assert.ok(r.body.retryAfterSec > 0);
  assert.equal((await api.call({ action: 'status' })).body.needsSetup, true);
});

async function withAdmin() {
  const api = makeApi();
  const r = await api.call({ action: 'setup', setupKey: SETUP_KEY, username: 'karel', password: 'password123', firstName: 'Karel', lastName: 'Baloun', weeklyNorm: 40 });
  api.admin = r.body.token;
  return api;
}
async function withUser(api) {
  const c = await api.call({ action: 'createUser', username: 'jan', password: 'initial-pass1', firstName: 'Jan', lastName: 'Novak', weeklyNorm: 38 }, api.admin);
  assert.equal(c.status, 200);
  const l = await api.call({ action: 'login', username: 'jan', password: 'initial-pass1' });
  api.user = l.body.token;
  return l.body;
}

await test('login ok / wrong password / unknown user give the same error', async () => {
  const api = await withAdmin();
  const ok = await api.call({ action: 'login', username: 'karel', password: 'password123' });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.token);
  const bad = await api.call({ action: 'login', username: 'karel', password: 'nope-nope-1' });
  const unknown = await api.call({ action: 'login', username: 'ghost', password: 'nope-nope-1' });
  assert.equal(bad.status, 401);
  assert.deepEqual(bad.body, unknown.body);
});
await test('lockout after 5 failures, even correct password is refused while locked', async () => {
  const api = await withAdmin();
  for (let i = 0; i < 5; i++) {
    assert.equal((await api.call({ action: 'login', username: 'karel', password: 'wrong-wrong' + i })).status, 401);
  }
  const r = await api.call({ action: 'login', username: 'karel', password: 'password123' });
  assert.equal(r.status, 429);
  assert.equal(r.body.error, 'locked');
  assert.ok(r.body.retryAfterSec > 0);
});
await test('me/logout require a valid token', async () => {
  const api = await withAdmin();
  assert.equal((await api.call({ action: 'me' })).status, 401);
  assert.equal((await api.call({ action: 'me' }, 'garbage-token')).status, 401);
  const me = await api.call({ action: 'me' }, api.admin);
  assert.equal(me.body.user.username, 'karel');
  assert.equal((await api.call({ action: 'logout' }, api.admin)).status, 200);
  assert.equal((await api.call({ action: 'me' }, api.admin)).status, 401);
});

// ─── role ──────────────────────────────────────────────────────────────────
await test('admin creates user; user must change password flag; duplicate rejected', async () => {
  const api = await withAdmin();
  const l = await withUser(api);
  assert.equal(l.user.role, 'user');
  assert.equal(l.user.mustChangePassword, true);
  assert.equal(l.user.profile.lastName, 'Novak');
  assert.equal((await api.call({ action: 'createUser', username: 'jan', password: 'another-pass1' }, api.admin)).status, 409);
});
await test('user cannot use admin actions', async () => {
  const api = await withAdmin(); await withUser(api);
  for (const body of [
    { action: 'listUsers' },
    { action: 'createUser', username: 'x1x', password: 'password123' },
    { action: 'updateUser', username: 'karel', firstName: 'x' },
    { action: 'resetPassword', username: 'karel', newPassword: 'password999' },
    { action: 'deleteUser', username: 'karel' }
  ]) {
    assert.equal((await api.call(body, api.user)).status, 403, body.action);
  }
});
await test('user cannot read or write another user\'s data; admin can', async () => {
  const api = await withAdmin(); await withUser(api);
  assert.equal((await api.call({ action: 'getData', user: 'karel' }, api.user)).status, 403);
  assert.equal((await api.call({ action: 'putData', user: 'karel', shifts: [], config: {}, baseLastModified: null }, api.user)).status, 403);
  const put = await api.call({ action: 'putData', user: 'jan', shifts: [shift('a', '2026-03-02')], config: {}, baseLastModified: null }, api.admin);
  assert.equal(put.status, 200);
  const got = await api.call({ action: 'getData' }, api.user);
  assert.equal(got.body.shifts.length, 1);
  assert.equal(got.body.profile.weeklyNorm, 38);
  assert.equal((await api.call({ action: 'getData', user: 'nobody' }, api.admin)).status, 404);
});

// ─── data ──────────────────────────────────────────────────────────────────
await test('putData: first write, conflict on stale base, success on fresh base', async () => {
  const api = await withAdmin();
  assert.equal((await api.call({ action: 'getData' }, api.admin)).body.lastModified, null);
  const a = await api.call({ action: 'putData', shifts: [shift('a', '2026-03-02')], config: { language: 'cs' }, baseLastModified: null }, api.admin);
  assert.equal(a.status, 200);
  const stale = await api.call({ action: 'putData', shifts: [], config: {}, baseLastModified: null }, api.admin);
  assert.equal(stale.status, 409);
  assert.equal(stale.body.shifts.length, 1);
  assert.equal(stale.body.config.language, 'cs');
  const fresh = await api.call({ action: 'putData', shifts: [shift('a', '2026-03-02'), shift('b', '2026-03-03')], config: {}, baseLastModified: a.body.lastModified }, api.admin);
  assert.equal(fresh.status, 200);
  assert.equal((await api.call({ action: 'getData' }, api.admin)).body.shifts.length, 2);
});
await test('putData rejects invalid data and never stores config fields owned by the profile', async () => {
  const api = await withAdmin(); await withUser(api);
  const bad = await api.call({ action: 'putData', shifts: [{ id: 'a', date: 'x', type: 'work' }], config: {}, baseLastModified: null }, api.user);
  assert.equal(bad.status, 400);
  const ok = await api.call({ action: 'putData', shifts: [], config: { language: 'de', firstName: 'Hacker', weeklyNorm: 99 }, baseLastModified: null }, api.user);
  assert.equal(ok.status, 200);
  const got = await api.call({ action: 'getData' }, api.user);
  assert.deepEqual(got.body.config, { language: 'de' });
  assert.equal(got.body.profile.firstName, 'Jan');
  assert.equal(got.body.profile.weeklyNorm, 38);
});

// ─── hesla a relace ────────────────────────────────────────────────────────
await test('changePassword: wrong old pw refused, success rotates sessions and clears flag', async () => {
  const api = await withAdmin(); await withUser(api);
  assert.equal((await api.call({ action: 'changePassword', oldPassword: 'bad-old-pass', newPassword: 'brand-new-pass1' }, api.user)).status, 401);
  assert.equal((await api.call({ action: 'changePassword', oldPassword: 'initial-pass1', newPassword: 'short' }, api.user)).status, 400);
  const r = await api.call({ action: 'changePassword', oldPassword: 'initial-pass1', newPassword: 'brand-new-pass1' }, api.user);
  assert.equal(r.status, 200);
  assert.equal(r.body.user.mustChangePassword, false);
  assert.equal((await api.call({ action: 'me' }, api.user)).status, 401);       // starý token
  assert.equal((await api.call({ action: 'me' }, r.body.token)).status, 200);   // nový token
  assert.equal((await api.call({ action: 'login', username: 'jan', password: 'brand-new-pass1' })).status, 200);
  assert.equal((await api.call({ action: 'login', username: 'jan', password: 'initial-pass1' })).status, 401);
});
await test('resetPassword by admin invalidates user sessions and forces change', async () => {
  const api = await withAdmin(); await withUser(api);
  assert.equal((await api.call({ action: 'resetPassword', username: 'jan', newPassword: 'reset-pass-77' }, api.admin)).status, 200);
  assert.equal((await api.call({ action: 'me' }, api.user)).status, 401);
  const l = await api.call({ action: 'login', username: 'jan', password: 'reset-pass-77' });
  assert.equal(l.status, 200);
  assert.equal(l.body.user.mustChangePassword, true);
});

// ─── správa uživatelů ──────────────────────────────────────────────────────
await test('listUsers never leaks hashes; updateUser changes profile; deleteUser removes account and data', async () => {
  const api = await withAdmin(); await withUser(api);
  await api.call({ action: 'putData', shifts: [shift('a', '2026-03-02')], config: {}, baseLastModified: null }, api.user);
  const list = await api.call({ action: 'listUsers' }, api.admin);
  assert.equal(list.body.users.length, 2);
  assert.ok(!JSON.stringify(list.body).includes('passwordHash'));
  assert.ok(!JSON.stringify(list.body).includes('scrypt'));
  const upd = await api.call({ action: 'updateUser', username: 'jan', lastName: 'Novotny', weeklyNorm: 35 }, api.admin);
  assert.equal(upd.body.user.profile.lastName, 'Novotny');
  assert.equal(upd.body.user.profile.weeklyNorm, 35);
  assert.equal(upd.body.user.profile.firstName, 'Jan');
  assert.equal((await api.call({ action: 'deleteUser', username: 'jan' }, api.admin)).status, 200);
  assert.equal((await api.call({ action: 'me' }, api.user)).status, 401);
  assert.equal(await api.stores.userdata.get('jan'), null);
  assert.equal((await api.call({ action: 'login', username: 'jan', password: 'initial-pass1' })).status, 401);
});
await test('admin cannot delete self or demote the last admin', async () => {
  const api = await withAdmin();
  assert.equal((await api.call({ action: 'deleteUser', username: 'karel' }, api.admin)).body.error, 'cannot_delete_self');
  assert.equal((await api.call({ action: 'updateUser', username: 'karel', role: 'user' }, api.admin)).body.error, 'last_admin');
});

await test('roster: admin sets/gets, sanitized + deduplicated; users and anonymous refused; _roster is not a reachable account', async () => {
  const api = await withAdmin(); await withUser(api);
  assert.deepEqual((await api.call({ action: 'getRoster' }, api.admin)).body.roster, []);
  const set = await api.call({ action: 'setRoster', roster: ['  Jan   Novak ', 'jan novak', '', 'Petr Svoboda', 42, null] }, api.admin);
  assert.equal(set.status, 200);
  assert.deepEqual(set.body.roster, ['Jan Novak', 'Petr Svoboda', '42']);
  assert.deepEqual((await api.call({ action: 'getRoster' }, api.admin)).body.roster, ['Jan Novak', 'Petr Svoboda', '42']);
  assert.equal((await api.call({ action: 'getRoster' }, api.user)).status, 403);
  assert.equal((await api.call({ action: 'setRoster', roster: ['x'] }, api.user)).status, 403);
  assert.equal((await api.call({ action: 'getRoster' })).status, 401);
  assert.equal((await api.call({ action: 'getData', user: '_roster' }, api.admin)).status, 404);
  assert.equal((await api.call({ action: 'setRoster', roster: 'nonsense' }, api.admin)).body.roster.length, 0);
  assert.equal((await api.call({ action: 'setRoster', roster: Array.from({ length: 500 }, (_, i) => 'Name ' + i) }, api.admin)).body.roster.length, 300);
  // seznam se neobjeví v listUsers
  assert.equal((await api.call({ action: 'listUsers' }, api.admin)).body.users.length, 2);
});

await test('activation: off by default, code gates the name list, activate creates a user account, name disappears', async () => {
  const api = await withAdmin();
  await api.call({ action: 'setRoster', roster: ['Karel Baloun', 'Jan Novák', 'Petr van Berg'] }, api.admin);
  // vypnuto → i "prázdný" kód je špatný
  assert.equal((await api.call({ action: 'activationInfo', code: '' })).status, 403);
  assert.equal((await api.call({ action: 'activationInfo', code: undefined })).status, 403);
  const gen = await api.call({ action: 'setActivation', mode: 'generate' }, api.admin);
  const code = gen.body.activationCode;
  assert.match(code, /^[2-9A-Z]{4}-[2-9A-Z]{4}$/);
  assert.equal((await api.call({ action: 'getRoster' }, api.admin)).body.activationCode, code);
  assert.equal((await api.call({ action: 'setActivation', mode: 'generate' }, api.user || 'x')).status, 401);
  // kód je jen pro aktivaci, nepouští k ničemu jinému; zadání bez pomlčky/malými je OK
  const info = await api.call({ action: 'activationInfo', code: code.toLowerCase().replace('-', '') });
  assert.equal(info.status, 200);
  assert.deepEqual(info.body.names, ['Jan Novák', 'Petr van Berg']); // Karel už účet má
  // špatné jméno / už obsazené / špatné heslo / špatné uživatelské jméno
  assert.equal((await api.call({ action: 'activate', code, name: 'Karel Baloun', username: 'karel2', password: 'secret-pass1' })).body.error, 'name_unavailable');
  assert.equal((await api.call({ action: 'activate', code, name: 'Nobody', username: 'nobody', password: 'secret-pass1' })).body.error, 'name_unavailable');
  assert.equal((await api.call({ action: 'activate', code, name: 'Jan Novák', username: 'jan', password: 'short' })).body.error, 'invalid_password');
  assert.equal((await api.call({ action: 'activate', code, name: 'Jan Novák', username: 'a', password: 'secret-pass1' })).body.error, 'invalid_username');
  assert.equal((await api.call({ action: 'activate', code, name: 'Jan Novák', username: 'karel', password: 'secret-pass1' })).body.error, 'exists');
  const ok = await api.call({ action: 'activate', code, name: 'jan  novák', username: 'jan', password: 'secret-pass1' });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.user.role, 'user');
  assert.equal(ok.body.user.mustChangePassword, false);
  assert.equal(ok.body.user.profile.firstName, 'Jan');
  assert.equal(ok.body.user.profile.lastName, 'Novák');
  assert.equal((await api.call({ action: 'me' }, ok.body.token)).body.user.username, 'jan');
  // jméno zmizelo; druhá aktivace stejného jména selže
  assert.deepEqual((await api.call({ action: 'activationInfo', code })).body.names, ['Petr van Berg']);
  assert.equal((await api.call({ action: 'activate', code, name: 'Jan Novák', username: 'jan2', password: 'secret-pass1' })).body.error, 'name_unavailable');
  // uživatel s právy user nemůže kód spravovat
  assert.equal((await api.call({ action: 'setActivation', mode: 'off' }, ok.body.token)).status, 403);
  assert.equal((await api.call({ action: 'getRoster' }, ok.body.token)).status, 403);
  // nový kód zneplatní starý; vypnutí zneplatní vše
  const code2 = (await api.call({ action: 'setActivation', mode: 'generate' }, api.admin)).body.activationCode;
  assert.notEqual(code2, code);
  assert.equal((await api.call({ action: 'activationInfo', code })).status, 403);
  assert.equal((await api.call({ action: 'activationInfo', code: code2 })).status, 200);
  await api.call({ action: 'setActivation', mode: 'off' }, api.admin);
  assert.equal((await api.call({ action: 'activationInfo', code: code2 })).status, 403);
  assert.equal((await api.call({ action: 'getRoster' }, api.admin)).body.activationCode, '');
});
await test('activation: 10 wrong codes lock guessing for everyone (even the right code)', async () => {
  const api = await withAdmin();
  await api.call({ action: 'setRoster', roster: ['Jan Novák'] }, api.admin);
  const code = (await api.call({ action: 'setActivation', mode: 'generate' }, api.admin)).body.activationCode;
  for (let i = 0; i < 10; i++) assert.equal((await api.call({ action: 'activationInfo', code: 'AAAA-' + String(i).padStart(4, '2') })).status, 403);
  const r = await api.call({ action: 'activationInfo', code });
  assert.equal(r.status, 429);
  assert.ok(r.body.retryAfterSec > 0);
  assert.equal((await api.call({ action: 'activate', code, name: 'Jan Novák', username: 'jan', password: 'secret-pass1' })).status, 429);
});

// ─── tvrdost vstupů ────────────────────────────────────────────────────────
await test('malformed requests', async () => {
  const api = await withAdmin();
  const raw = async (init) => (await api.handler(new Request('http://x/api', init))).status;
  assert.equal(await raw({ method: 'GET' }), 405);
  assert.equal(await raw({ method: 'POST', body: 'not json' }), 400);
  assert.equal(await raw({ method: 'POST', body: '[]' }), 400);
  assert.equal((await api.call({ action: 'constructor' })).status, 400);
  assert.equal((await api.call({ action: 'nope' })).status, 400);
  assert.equal((await api.call({})).status, 400);
  assert.equal(await raw({ method: 'POST', body: JSON.stringify({ action: 'status', pad: 'x'.repeat(2100000) }) }), 413);
});

console.log('Alle api-core Tests bestanden ✓ (' + passed + ')');
