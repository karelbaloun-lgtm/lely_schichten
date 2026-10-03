// lib/api-core.mjs
// Veškerá logika účtů, relací, rolí a dat. Úložiště (Netlify Blobs v
// produkci, paměť v testech) se vkládá zvenčí přes createHandler(getStores),
// takže jde všechno testovat bez Netlify. Soubor leží záměrně MIMO
// netlify/functions/ — každý soubor v té složce Netlify bere jako funkci.
import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';

// Jednorázový klíč pro založení prvního admina. V kódu je jen jeho hash;
// akce `setup` navíc funguje jen dokud neexistuje žádný účet.
export const SETUP_KEY_HASH = 'ea3de44a5de027461af8f558a9d15eae32fcb16fe75188351b06efac695ebc50';

const SESSION_TTL_MS = 90 * 24 * 3600 * 1000;
const SESSION_REFRESH_MS = 24 * 3600 * 1000;
const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;
const MAX_BODY_CHARS = 2000000;
const MAX_SHIFTS = 5000;
const SCRYPT_N = 16384;

// ─── Čisté pomocné funkce (exportované kvůli testům) ───────────────────────
export function normalizeUsername(u) {
  return typeof u === 'string' ? u.trim().toLowerCase() : '';
}
export function validUsername(u) {
  return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(u);
}
export function validPassword(p) {
  return typeof p === 'string' && p.length >= 8 && p.length <= 200;
}
export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64, { N: SCRYPT_N, r: 8, p: 1 });
  return 'scrypt$' + SCRYPT_N + '$' + salt.toString('base64') + '$' + hash.toString('base64');
}
export function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 4 || parts[0] !== 'scrypt') return false;
  const N = parseInt(parts[1], 10);
  const salt = Buffer.from(parts[2], 'base64');
  const expected = Buffer.from(parts[3], 'base64');
  const actual = scryptSync(password, salt, expected.length, { N, r: 8, p: 1 });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
const DUMMY_HASH = hashPassword('dummy-password-for-timing');

export function sha256(s) {
  return createHash('sha256').update(s).digest('hex');
}
export function newToken() {
  return randomBytes(32).toString('base64url');
}

export function sanitizeProfile(p) {
  const out = {
    firstName: String((p && p.firstName) || '').trim().slice(0, 60),
    lastName: String((p && p.lastName) || '').trim().slice(0, 60),
    weeklyNorm: Number(p && p.weeklyNorm)
  };
  if (!isFinite(out.weeklyNorm) || out.weeklyNorm < 1 || out.weeklyNorm > 80) out.weeklyNorm = 40;
  return out;
}

// Klíč seznamu montérů; začíná „_“, takže se nikdy nepotká s validním username.
const ROSTER_KEY = '_roster';
const ACTIVATION_KEY = '_activation';
const SETUP_LOCK_KEY = '_setup';
const ROSTER_MAX = 300;
const MAX_CODE_FAILS = 10;
const CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // bez 0/O/1/I/L
export function nameKey(s) { return String(s || '').replace(/\s+/g, ' ').trim().toLowerCase(); }
export function newActivationCode() {
  const b = randomBytes(8);
  let c = '';
  for (let i = 0; i < 8; i++) c += CODE_ALPHABET[b[i] % CODE_ALPHABET.length];
  return c.slice(0, 4) + '-' + c.slice(4);
}
export function sanitizeRoster(list) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const name = String(raw == null ? '' : raw).replace(/\s+/g, ' ').trim().slice(0, 120);
    if (!name || seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    out.push(name);
    if (out.length >= ROSTER_MAX) break;
  }
  return out;
}

// Do dat uživatele smí patřit jen language a hotelAddressHistory — jméno a
// norma jsou v profilu účtu, který spravuje admin.
export function sanitizeConfig(config) {
  const out = {};
  if (config && (config.language === 'de' || config.language === 'cs')) out.language = config.language;
  const hist = config && config.hotelAddressHistory;
  if (hist && typeof hist === 'object' && !Array.isArray(hist)) {
    const clean = {};
    for (const k of Object.keys(hist).slice(0, 500)) {
      if (typeof hist[k] === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(hist[k])) clean[String(k).slice(0, 300)] = hist[k];
    }
    out.hotelAddressHistory = clean;
  }
  return out;
}

// Vrací pole směn, nebo vyhodí chybu s popisem.
export function sanitizeShifts(shifts) {
  if (!Array.isArray(shifts)) throw new Error('shifts must be an array');
  if (shifts.length > MAX_SHIFTS) throw new Error('too many shifts');
  const seen = new Set();
  for (const s of shifts) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) throw new Error('invalid shift');
    if (typeof s.id !== 'string' || !s.id || s.id.length > 80) throw new Error('invalid shift id');
    if (seen.has(s.id)) throw new Error('duplicate shift id');
    seen.add(s.id);
    if (typeof s.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s.date)) throw new Error('invalid shift date');
    if (s.type !== 'work' && s.type !== 'sick' && s.type !== 'vacation') throw new Error('invalid shift type');
  }
  return shifts;
}

// Optimistická kontrola souběhu (stejně jako dřív u sync kódu).
export function resolveWrite(existing, incoming) {
  if (existing && existing.lastModified !== incoming.baseLastModified) {
    return { conflict: true, existing };
  }
  return {
    conflict: false,
    record: { shifts: incoming.shifts, config: incoming.config, lastModified: Date.now(), updatedBy: incoming.updatedBy }
  };
}

function publicUser(acc) {
  return {
    username: acc.username,
    role: acc.role,
    mustChangePassword: !!acc.mustChangePassword,
    profile: acc.profile,
    createdAt: acc.createdAt
  };
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}
class ApiError extends Error {
  constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra; }
}
const fail = (status, code, extra) => { throw new ApiError(status, code, extra); };

// ─── Handler ───────────────────────────────────────────────────────────────
// getStores() -> { accounts, sessions, userdata }; každý store má
// get(key, {type:'json'}), setJSON(key, value), delete(key), list().
export function createHandler(getStores, options) {
  const setupKeyHash = (options && options.setupKeyHash) || SETUP_KEY_HASH;
  async function countAccounts(accounts) {
    const res = await accounts.list();
    return (res && res.blobs ? res.blobs.length : 0);
  }
  async function listAccountKeys(accounts) {
    const res = await accounts.list();
    return (res && res.blobs ? res.blobs.map((b) => b.key) : []);
  }
  async function issueSession(stores, acc) {
    const token = newToken();
    await stores.sessions.setJSON(sha256(token), {
      username: acc.username,
      tokenVersion: acc.tokenVersion || 0,
      expires: Date.now() + SESSION_TTL_MS
    });
    return token;
  }
  async function authenticate(stores, req) {
    const header = req.headers.get('authorization') || '';
    const m = /^Bearer (\S+)$/.exec(header);
    if (!m) fail(401, 'unauthorized');
    const key = sha256(m[1]);
    const sess = await stores.sessions.get(key, { type: 'json' });
    if (!sess || sess.expires < Date.now()) fail(401, 'unauthorized');
    const acc = await stores.accounts.get(sess.username, { type: 'json' });
    if (!acc || (acc.tokenVersion || 0) !== sess.tokenVersion) fail(401, 'unauthorized');
    if (sess.expires - Date.now() < SESSION_TTL_MS - SESSION_REFRESH_MS) {
      sess.expires = Date.now() + SESSION_TTL_MS;
      await stores.sessions.setJSON(key, sess);
    }
    return { acc, sessionKey: key };
  }
  function requireAdmin(acc) { if (acc.role !== 'admin') fail(403, 'forbidden'); }

  // Která data se čtou/zapisují: vlastní, nebo (jen admin) cizí.
  async function resolveTarget(stores, acc, requested) {
    if (requested === undefined || requested === null || normalizeUsername(requested) === acc.username) return acc;
    requireAdmin(acc);
    const target = await stores.accounts.get(normalizeUsername(requested), { type: 'json' });
    if (!target) fail(404, 'user_not_found');
    return target;
  }
  async function registerFailure(stores, acc) {
    acc.failedAttempts = (acc.failedAttempts || 0) + 1;
    if (acc.failedAttempts >= MAX_FAILED) {
      acc.lockedUntil = Date.now() + LOCK_MS;
      acc.failedAttempts = 0;
    }
    await stores.accounts.setJSON(acc.username, acc);
  }
  async function checkPasswordWithLock(stores, acc, password) {
    if (acc.lockedUntil && acc.lockedUntil > Date.now()) {
      fail(429, 'locked', { retryAfterSec: Math.ceil((acc.lockedUntil - Date.now()) / 1000) });
    }
    const ok = typeof password === 'string' && verifyPassword(password, acc.passwordHash);
    if (!ok) {
      await registerFailure(stores, acc);
      return false;
    }
    if (acc.failedAttempts || acc.lockedUntil) {
      acc.failedAttempts = 0; acc.lockedUntil = 0;
      await stores.accounts.setJSON(acc.username, acc);
    }
    return true;
  }
  async function readRoster(stores) {
    const rec = await stores.userdata.get(ROSTER_KEY, { type: 'json' });
    return rec && Array.isArray(rec.names) ? rec.names : [];
  }
  // Jména ze seznamu, ke kterým ještě neexistuje účet (porovnání podle profilu).
  async function availableRosterNames(stores) {
    const taken = new Set();
    for (const k of await listAccountKeys(stores.accounts)) {
      const a = await stores.accounts.get(k, { type: 'json' });
      if (a && a.profile) taken.add(nameKey(a.profile.firstName + ' ' + a.profile.lastName));
    }
    return (await readRoster(stores)).filter((n) => !taken.has(nameKey(n)));
  }
  // Společný (globální) zámek proti hádání kódu: 10 chybných pokusů → 15 min.
  async function checkActivationCode(stores, code) {
    const rec = (await stores.userdata.get(ACTIVATION_KEY, { type: 'json' })) || { code: '', fails: 0, lockedUntil: 0 };
    const now = Date.now();
    if (rec.lockedUntil && rec.lockedUntil > now) fail(429, 'locked', { retryAfterSec: Math.ceil((rec.lockedUntil - now) / 1000) });
    const real = String(rec.code || '').replace(/-/g, '');
    const given = String(typeof code === 'string' ? code : '').toUpperCase().replace(/[\s-]/g, '');
    const ok = real.length > 0 && given.length === real.length && timingSafeEqual(Buffer.from(given), Buffer.from(real));
    if (!ok) {
      rec.fails = (rec.fails || 0) + 1;
      if (rec.fails >= MAX_CODE_FAILS) { rec.lockedUntil = now + LOCK_MS; rec.fails = 0; }
      await stores.userdata.setJSON(ACTIVATION_KEY, rec);
      fail(403, 'bad_code');
    }
    if (rec.fails) { rec.fails = 0; await stores.userdata.setJSON(ACTIVATION_KEY, rec); }
  }
  async function adminCount(stores) {
    let n = 0;
    for (const k of await listAccountKeys(stores.accounts)) {
      const a = await stores.accounts.get(k, { type: 'json' });
      if (a && a.role === 'admin') n++;
    }
    return n;
  }

  const actions = {
    async status(stores) {
      return { needsSetup: (await countAccounts(stores.accounts)) === 0 };
    },

    async setup(stores, body) {
      if ((await countAccounts(stores.accounts)) !== 0) fail(403, 'already_set_up');
      // Klíč je krátký → zámek proti hádání: 10 chybných pokusů = 15 min pauza.
      const lock = (await stores.userdata.get(SETUP_LOCK_KEY, { type: 'json' })) || { fails: 0, lockedUntil: 0 };
      const now = Date.now();
      if (lock.lockedUntil && lock.lockedUntil > now) fail(429, 'locked', { retryAfterSec: Math.ceil((lock.lockedUntil - now) / 1000) });
      if (typeof body.setupKey !== 'string' || sha256(body.setupKey.trim()) !== setupKeyHash) {
        lock.fails = (lock.fails || 0) + 1;
        if (lock.fails >= MAX_CODE_FAILS) { lock.lockedUntil = now + LOCK_MS; lock.fails = 0; }
        await stores.userdata.setJSON(SETUP_LOCK_KEY, lock);
        fail(403, 'bad_setup_key');
      }
      const username = normalizeUsername(body.username);
      if (!validUsername(username)) fail(400, 'invalid_username');
      if (!validPassword(body.password)) fail(400, 'invalid_password');
      const acc = {
        username, role: 'admin', passwordHash: hashPassword(body.password), mustChangePassword: false,
        tokenVersion: 0, profile: sanitizeProfile(body), failedAttempts: 0, lockedUntil: 0, createdAt: Date.now()
      };
      await stores.accounts.setJSON(username, acc);
      const token = await issueSession(stores, acc);
      return { token, user: publicUser(acc) };
    },

    async login(stores, body) {
      const username = normalizeUsername(body.username);
      const acc = validUsername(username) ? await stores.accounts.get(username, { type: 'json' }) : null;
      if (!acc) {
        verifyPassword(typeof body.password === 'string' ? body.password : '', DUMMY_HASH);
        fail(401, 'invalid_credentials');
      }
      if (!(await checkPasswordWithLock(stores, acc, body.password))) fail(401, 'invalid_credentials');
      const token = await issueSession(stores, acc);
      return { token, user: publicUser(acc) };
    },

    async me(stores, body, auth) {
      return { user: publicUser(auth.acc) };
    },

    async logout(stores, body, auth) {
      await stores.sessions.delete(auth.sessionKey);
      return { ok: true };
    },

    async changePassword(stores, body, auth) {
      const acc = auth.acc;
      if (!validPassword(body.newPassword)) fail(400, 'invalid_password');
      if (!(await checkPasswordWithLock(stores, acc, body.oldPassword))) fail(401, 'invalid_credentials');
      acc.passwordHash = hashPassword(body.newPassword);
      acc.mustChangePassword = false;
      acc.tokenVersion = (acc.tokenVersion || 0) + 1;
      await stores.accounts.setJSON(acc.username, acc);
      const token = await issueSession(stores, acc);
      return { token, user: publicUser(acc) };
    },

    async getData(stores, body, auth) {
      const target = await resolveTarget(stores, auth.acc, body.user);
      const rec = await stores.userdata.get(target.username, { type: 'json' });
      return {
        user: target.username,
        profile: target.profile,
        shifts: rec ? rec.shifts : [],
        config: rec ? rec.config : {},
        lastModified: rec ? rec.lastModified : null
      };
    },

    async putData(stores, body, auth) {
      const target = await resolveTarget(stores, auth.acc, body.user);
      let shifts;
      try { shifts = sanitizeShifts(body.shifts); } catch (e) { fail(400, 'invalid_data', { detail: e.message }); }
      const incoming = {
        shifts,
        config: sanitizeConfig(body.config),
        baseLastModified: body.baseLastModified === undefined ? null : body.baseLastModified,
        updatedBy: auth.acc.username
      };
      const existing = await stores.userdata.get(target.username, { type: 'json' });
      const result = resolveWrite(existing, incoming);
      if (result.conflict) {
        throw new ApiError(409, 'conflict', {
          user: target.username, profile: target.profile,
          shifts: existing.shifts, config: existing.config, lastModified: existing.lastModified
        });
      }
      await stores.userdata.setJSON(target.username, result.record);
      return { lastModified: result.record.lastModified };
    },

    async listUsers(stores, body, auth) {
      requireAdmin(auth.acc);
      const out = [];
      for (const k of await listAccountKeys(stores.accounts)) {
        const a = await stores.accounts.get(k, { type: 'json' });
        if (a) out.push(publicUser(a));
      }
      out.sort((a, b) => a.username.localeCompare(b.username));
      return { users: out };
    },

    async createUser(stores, body, auth) {
      requireAdmin(auth.acc);
      const username = normalizeUsername(body.username);
      if (!validUsername(username)) fail(400, 'invalid_username');
      if (!validPassword(body.password)) fail(400, 'invalid_password');
      if (await stores.accounts.get(username, { type: 'json' })) fail(409, 'exists');
      const acc = {
        username, role: body.role === 'admin' ? 'admin' : 'user', passwordHash: hashPassword(body.password),
        mustChangePassword: true, tokenVersion: 0, profile: sanitizeProfile(body),
        failedAttempts: 0, lockedUntil: 0, createdAt: Date.now()
      };
      await stores.accounts.setJSON(username, acc);
      return { user: publicUser(acc) };
    },

    async updateUser(stores, body, auth) {
      requireAdmin(auth.acc);
      const acc = await stores.accounts.get(normalizeUsername(body.username), { type: 'json' });
      if (!acc) fail(404, 'user_not_found');
      acc.profile = sanitizeProfile(Object.assign({}, acc.profile, body));
      if (body.role === 'admin' || body.role === 'user') {
        if (acc.role === 'admin' && body.role === 'user' && (await adminCount(stores)) <= 1) fail(400, 'last_admin');
        acc.role = body.role;
      }
      await stores.accounts.setJSON(acc.username, acc);
      return { user: publicUser(acc) };
    },

    async resetPassword(stores, body, auth) {
      requireAdmin(auth.acc);
      if (!validPassword(body.newPassword)) fail(400, 'invalid_password');
      const acc = await stores.accounts.get(normalizeUsername(body.username), { type: 'json' });
      if (!acc) fail(404, 'user_not_found');
      acc.passwordHash = hashPassword(body.newPassword);
      acc.mustChangePassword = acc.username !== auth.acc.username;
      acc.tokenVersion = (acc.tokenVersion || 0) + 1;
      acc.failedAttempts = 0; acc.lockedUntil = 0;
      await stores.accounts.setJSON(acc.username, acc);
      if (acc.username === auth.acc.username) {
        const token = await issueSession(stores, acc);
        return { ok: true, token };
      }
      return { ok: true };
    },

    // Seznam montérů (jména, ze kterých admin vybírá při zakládání účtu
    // a ze kterých si kolegové vybírají při aktivaci). Ve store userdata pod
    // klíčem, který nemůže být uživatelským jménem.
    async getRoster(stores, body, auth) {
      requireAdmin(auth.acc);
      const act = await stores.userdata.get(ACTIVATION_KEY, { type: 'json' });
      return { roster: await readRoster(stores), activationCode: (act && act.code) || '' };
    },

    // Aktivační kód pro samoobslužné založení účtu kolegy: 'generate' = nový
    // kód (starý přestane platit), 'off' = aktivace vypnutá.
    async setActivation(stores, body, auth) {
      requireAdmin(auth.acc);
      const code = body.mode === 'generate' ? newActivationCode() : '';
      await stores.userdata.setJSON(ACTIVATION_KEY, { code, fails: 0, lockedUntil: 0 });
      return { activationCode: code };
    },

    // Veřejné (před přihlášením), ale jen se správným kódem: jména montérů,
    // kteří ještě nemají účet.
    async activationInfo(stores, body) {
      await checkActivationCode(stores, body.code);
      return { names: await availableRosterNames(stores) };
    },

    async activate(stores, body) {
      await checkActivationCode(stores, body.code);
      const wanted = nameKey(typeof body.name === 'string' ? body.name : '');
      const name = (await availableRosterNames(stores)).find((n) => nameKey(n) === wanted);
      if (!name) fail(409, 'name_unavailable');
      const username = normalizeUsername(body.username);
      if (!validUsername(username)) fail(400, 'invalid_username');
      if (!validPassword(body.password)) fail(400, 'invalid_password');
      if (await stores.accounts.get(username, { type: 'json' })) fail(409, 'exists');
      const i = name.indexOf(' ');
      const acc = {
        username, role: 'user', passwordHash: hashPassword(body.password), mustChangePassword: false,
        tokenVersion: 0, profile: sanitizeProfile({ firstName: i < 0 ? name : name.slice(0, i), lastName: i < 0 ? '' : name.slice(i + 1), weeklyNorm: 40 }),
        failedAttempts: 0, lockedUntil: 0, createdAt: Date.now()
      };
      await stores.accounts.setJSON(username, acc);
      const token = await issueSession(stores, acc);
      return { token, user: publicUser(acc) };
    },

    async setRoster(stores, body, auth) {
      requireAdmin(auth.acc);
      const names = sanitizeRoster(body.roster);
      await stores.userdata.setJSON(ROSTER_KEY, { names, lastModified: Date.now() });
      return { roster: names };
    },

    async deleteUser(stores, body, auth) {
      requireAdmin(auth.acc);
      const username = normalizeUsername(body.username);
      if (username === auth.acc.username) fail(400, 'cannot_delete_self');
      const acc = await stores.accounts.get(username, { type: 'json' });
      if (!acc) fail(404, 'user_not_found');
      acc.tokenVersion = (acc.tokenVersion || 0) + 1;
      await stores.accounts.delete(username);
      await stores.userdata.delete(username);
      return { ok: true };
    }
  };
  const PUBLIC = new Set(['status', 'setup', 'login', 'activationInfo', 'activate']);

  return async function handler(req) {
    try {
      if (req.method !== 'POST') fail(405, 'method_not_allowed');
      const text = await req.text();
      if (text.length > MAX_BODY_CHARS) fail(413, 'too_large');
      let body;
      try { body = JSON.parse(text); } catch (e) { fail(400, 'invalid_body'); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) fail(400, 'invalid_body');
      const action = body.action;
      if (typeof action !== 'string' || !Object.prototype.hasOwnProperty.call(actions, action)) fail(400, 'unknown_action');
      const stores = getStores();
      const auth = PUBLIC.has(action) ? null : await authenticate(stores, req);
      return json(await actions[action](stores, body, auth));
    } catch (e) {
      if (e instanceof ApiError) return json(Object.assign({ error: e.code }, e.extra || {}), e.status);
      console.error('api error:', e && e.message);
      return json({ error: 'server_error' }, 500);
    }
  };
}
