const SITE = 'https://ignitecontentlab.github.io';
const APP_VERSION = 'app-0.6';
const RESET_MS = 30 * 60 * 1000;
const PW_RULE = 'Password needs at least 8 characters, including 1 number and 1 special character (like ! or #).';
function pwOk(pw) {
  return typeof pw === 'string' && pw.length >= 8 && pw.length <= 200 && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
}
let migrated = null;
async function migrate(env) {
  if (migrated) return migrated;
  const st = { phoneUnique: false };
  try { await env.DB.prepare('DROP INDEX IF EXISTS users_phone').run(); } catch (e) {}
  await env.DB.prepare('CREATE TABLE IF NOT EXISTS password_resets(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)').run();
  try {
    const { results } = await env.DB.prepare('PRAGMA index_list(users)').all();
    for (const ix of results || []) {
      if (!ix.unique) continue;
      const cols = (await env.DB.prepare(`PRAGMA index_info("${String(ix.name).replace(/"/g, '')}")`).all()).results.map((c) => c.name);
      if (cols.length === 1 && cols[0] === 'phone') st.phoneUnique = true;
    }
  } catch (e) {}
  migrated = st;
  return st;
}
const emailOn = (env) => !!(env.BREVO_API_KEY && env.MAIL_FROM);
async function sendMail(env, to, subject, text, html) {
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: env.MAIL_NAME || 'Surf Fantasy Leagues', email: env.MAIL_FROM }, to: [{ email: to }], subject, textContent: text, htmlContent: html })
  });
  return r.ok;
}
const enc = new TextEncoder();
const SESSION_MS = 7 * 24 * 3600 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const CODE_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const iters = (env) => Math.min(100000, Math.max(10000, parseInt(env.PBKDF2_ITERATIONS, 10) || 100000));
async function derive(pw, salt, it) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: it }, k, 256);
}
async function hashPw(pw, env) {
  const it = iters(env);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${it}$${b64(salt)}$${b64(await derive(pw, salt, it))}`;
}
async function checkPw(pw, stored) {
  const p = String(stored).split('$');
  if (p.length !== 4 || p[0] !== 'pbkdf2') return false;
  const it = parseInt(p[1], 10);
  if (!(it >= 1000 && it <= 100000)) return false;
  return safeEq(b64(await derive(pw, unb64(p[2]), it)), p[3]);
}
function makeRecovery() {
  const r = crypto.getRandomValues(new Uint8Array(16));
  let s = '';
  for (let i = 0; i < 16; i++) {
    s += CODE_ALPHA[r[i] % 32];
    if (i % 4 === 3 && i < 15) s += '-';
  }
  return s;
}
function makeCode(n) {
  const r = crypto.getRandomValues(new Uint8Array(n));
  let s = '';
  for (let i = 0; i < n; i++) s += CODE_ALPHA[r[i] % 32];
  return s;
}
function normEmail(s) {
  const e = String(s || '').trim().toLowerCase();
  return e.length <= 254 && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e) ? e : null;
}
function normPhone(s) {
  let t = String(s || '').replace(/[\s().-]/g, '');
  if (/^\d{10}$/.test(t)) t = '+1' + t;
  else if (/^1\d{10}$/.test(t)) t = '+' + t;
  return /^\+[1-9]\d{7,14}$/.test(t) ? t : null;
}
function cleanText(v, min, max) {
  const s = String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim();
  return s.length >= min && s.length <= max ? s : null;
}
function cleanUrl(v) {
  const s = String(v || '').trim();
  if (!s) return '';
  if (s.length > 200) return null;
  try {
    const u = new URL(s);
    return u.protocol === 'https:' ? u.toString() : null;
  } catch (e) {
    return null;
  }
}

function baseHeaders(extra) {
  return Object.assign({
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'strict-transport-security': 'max-age=31536000'
  }, extra || {});
}
function json(data, status = 200, extra) {
  return new Response(JSON.stringify(data), {
    status,
    headers: baseHeaders(Object.assign({ 'content-type': 'application/json; charset=utf-8' }, extra))
  });
}
function getCookie(req, name) {
  const m = (req.headers.get('cookie') || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : null;
}
async function readJson(req) {
  if (!(req.headers.get('content-type') || '').startsWith('application/json')) return null;
  const o = req.headers.get('origin');
  if (o && o !== new URL(req.url).origin && o !== SITE) return null;
  try {
    const text = await req.text();
    if (text.length > 4096) return null;
    const v = JSON.parse(text);
    return v && typeof v === 'object' ? v : null;
  } catch (e) {
    return null;
  }
}
function bearer(req) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(req.headers.get('authorization') || '');
  return m ? m[1] : null;
}
const fromSite = (req) => req.headers.get('origin') === SITE;
async function currentUser(req, env) {
  const t = bearer(req) || getCookie(req, 'sp_session');
  if (!t || !/^[0-9a-f]{64}$/.test(t)) return null;
  return env.DB.prepare(
    'SELECT u.id, u.username, u.is_admin, u.email, u.phone, u.email_verified, u.phone_verified FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0'
  ).bind(await sha256(t), Date.now()).first();
}
async function startSession(env, userId) {
  const t = rand(32);
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions(token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(t), userId, now + SESSION_MS, new Date(now).toISOString()).run();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
  return { token: t, cookie: `sp_session=${t}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}` };
}
async function isLimited(env, buckets) {
  const now = Date.now();
  for (const b of buckets) {
    const r = await env.DB.prepare('SELECT failures, expires_at FROM login_limits WHERE bucket = ?').bind(b).first();
    if (r && r.expires_at > now && r.failures >= 5) return true;
  }
  return false;
}
async function addFailure(env, buckets) {
  const now = Date.now();
  for (const b of buckets) {
    await env.DB.prepare(
      'INSERT INTO login_limits(bucket, failures, expires_at) VALUES (?, 1, ?) ON CONFLICT(bucket) DO UPDATE SET failures = CASE WHEN expires_at < ? THEN 1 ELSE failures + 1 END, expires_at = ?'
    ).bind(b, now + LOCK_MS, now, now + LOCK_MS).run();
  }
}

async function register(req, env, ip) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const username = String(b.username || '').trim();
  const password = String(b.password || '');
  const code = String(b.code || '').trim();
  const email = normEmail(b.email);
  const phone = normPhone(b.phone);
  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) return json({ error: 'Username must be 3-24 letters, numbers or underscores.' }, 400);
  if (!pwOk(password)) return json({ error: PW_RULE }, 400);
  if (!email) return json({ error: 'Enter a valid email address.' }, 400);
  if (!phone) return json({ error: 'Enter a valid phone number, for example +15551234567.' }, 400);
  const buckets = ['reg:' + ip];
  if (await isLimited(env, buckets)) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);

  const count = (await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()).n;
  const max = parseInt(env.MAX_USERS, 10) || 10;
  if (count >= max) return json({ error: 'Registration is full.' }, 403);
  if (await env.DB.prepare('SELECT 1 AS x FROM users WHERE lower(username) = lower(?)').bind(username).first()) return json({ error: 'That username is taken. Try another.' }, 409);
  if (await env.DB.prepare('SELECT 1 AS x FROM users WHERE lower(email) = ?').bind(email).first()) return json({ error: 'An account with that email already exists. Sign in, or use Forgot password.' }, 409);
  if ((await migrate(env)).phoneUnique && await env.DB.prepare('SELECT 1 AS x FROM users WHERE phone = ?').bind(phone).first()) return json({ error: 'That phone number is already on another account.' }, 409);

  const now = new Date().toISOString();
  const recovery = makeRecovery();
  const pwHash = await hashPw(password, env);
  const recHash = await sha256(recovery);

  if (count === 0) {
    if (!env.BOOTSTRAP_CODE) return json({ error: 'The BOOTSTRAP_CODE secret is not set on this Worker.' }, 503);
    if (!safeEq(await sha256(code), await sha256(String(env.BOOTSTRAP_CODE)))) {
      await addFailure(env, buckets);
      return json({ error: 'Invalid setup code.' }, 403);
    }
    const r = await env.DB.prepare(
      'INSERT INTO users(username, email, phone, pw_hash, recovery_hash, is_admin, created_at) SELECT ?, ?, ?, ?, ?, 1, ? WHERE NOT EXISTS (SELECT 1 FROM users)'
    ).bind(username, email, phone, pwHash, recHash, now).run();
    if (!r.meta || r.meta.changes !== 1) return json({ error: 'Setup is already complete.' }, 409);
  } else {
    const u = await env.DB.prepare(
      'UPDATE invite_codes SET uses = uses + 1 WHERE code = ? AND disabled = 0 AND uses < max_uses AND (expires_at IS NULL OR expires_at > ?)'
    ).bind(code, Date.now()).run();
    if (!u.meta || u.meta.changes !== 1) {
      await addFailure(env, buckets);
      return json({ error: 'Invalid or used invite code.' }, 403);
    }
    try {
      await env.DB.prepare('INSERT INTO users(username, email, phone, pw_hash, recovery_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
        .bind(username, email, phone, pwHash, recHash, now).run();
    } catch (e) {
      await env.DB.prepare('UPDATE invite_codes SET uses = uses - 1 WHERE code = ?').bind(code).run();
      return json({ error: 'That username or email is already in use.' }, 409);
    }
  }
  const user = await env.DB.prepare('SELECT id, is_admin FROM users WHERE username = ?').bind(username).first();
  const ses = await startSession(env, user.id);
  const out = { ok: true, username, admin: !!user.is_admin };
  if (!emailOn(env)) out.recoveryCode = recovery;
  if (fromSite(req)) out.token = ses.token;
  return json(out, 200, { 'set-cookie': ses.cookie });
}

async function login(req, env, ip) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const username = String(b.username || '').trim().slice(0, 40);
  const password = String(b.password || '').slice(0, 200);
  const buckets = ['ip:' + ip, 'u:' + username.toLowerCase()];
  if (await isLimited(env, buckets)) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
  const row = await env.DB.prepare('SELECT id, pw_hash, disabled FROM users WHERE lower(username) = lower(?) OR (? LIKE \'%@%\' AND lower(email) = lower(?)) ORDER BY id LIMIT 1').bind(username, username, username).first();
  let ok = false;
  if (row) ok = await checkPw(password, row.pw_hash);
  else await derive(password, new Uint8Array(16), iters(env));
  if (!ok || row.disabled) {
    await addFailure(env, buckets);
    return json({ error: 'Wrong username, email or password.' }, 401);
  }
  await env.DB.prepare('DELETE FROM login_limits WHERE bucket = ?').bind('u:' + username.toLowerCase()).run();
  const ses = await startSession(env, row.id);
  const out = { ok: true };
  if (fromSite(req)) out.token = ses.token;
  return json(out, 200, { 'set-cookie': ses.cookie });
}

async function logout(req, env) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const t = bearer(req) || getCookie(req, 'sp_session');
  if (t && /^[0-9a-f]{64}$/.test(t)) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(t)).run();
  }
  return json({ ok: true }, 200, { 'set-cookie': 'sp_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' });
}

async function recover(req, env, ip) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const username = String(b.username || '').trim().slice(0, 40);
  const code = String(b.recoveryCode || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  const password = String(b.password || '');
  if (!pwOk(password)) return json({ error: PW_RULE }, 400);
  const buckets = ['rec:' + ip, 'recu:' + username.toLowerCase()];
  if (await isLimited(env, buckets)) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
  const row = await env.DB.prepare('SELECT id, recovery_hash, disabled FROM users WHERE username = ?').bind(username).first();
  const pretty = code.length === 16 ? code.match(/.{4}/g).join('-') : '';
  const ok = !!(row && !row.disabled && pretty && safeEq(await sha256(pretty), String(row.recovery_hash || '')));
  if (!ok) {
    await addFailure(env, buckets);
    return json({ error: 'That username and recovery code do not match.' }, 401);
  }
  const fresh = makeRecovery();
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pw_hash = ?, recovery_hash = ? WHERE id = ?').bind(await hashPw(password, env), await sha256(fresh), row.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(row.id)
  ]);
  const ses = await startSession(env, row.id);
  const out = { ok: true, recoveryCode: fresh };
  if (fromSite(req)) out.token = ses.token;
  return json(out, 200, { 'set-cookie': ses.cookie });
}
async function forgot(req, env, ip) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  if (!emailOn(env)) return json({ error: 'Email reset is not switched on yet. Use your recovery code, or ask the site admin.' }, 503);
  const email = normEmail(b.email);
  if (!email) return json({ error: 'Enter the email on your account.' }, 400);
  const buckets = ['fg:' + ip, 'fge:' + email];
  if (await isLimited(env, buckets)) return json({ error: 'Too many reset requests. Try again in 15 minutes.' }, 429);
  await addFailure(env, buckets);
  await migrate(env);
  const u = await env.DB.prepare('SELECT id, username FROM users WHERE lower(email) = ? AND disabled = 0').bind(email).first();
  if (u) {
    const t = rand(32), now = Date.now();
    await env.DB.prepare('INSERT INTO password_resets(token_hash, user_id, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)').bind(await sha256(t), u.id, now + RESET_MS, new Date(now).toISOString()).run();
    await env.DB.prepare('DELETE FROM password_resets WHERE expires_at < ?').bind(now - 86400000).run();
    const link = SITE + '/isa-peru-fantasy-2026/#reset/' + t;
    const text = `Hi ${u.username},\n\nSomeone asked to reset the password for your Surf Fantasy Leagues account. Open this link within 30 minutes to choose a new password:\n\n${link}\n\nIf you didn't ask for this, you can ignore this email. Your password stays the same.`;
    const html = `<div style="font-family:Arial,sans-serif;font-size:15px;color:#111;max-width:520px"><p>Hi ${u.username},</p><p>Someone asked to reset the password for your Surf Fantasy Leagues account. This link works for 30 minutes.</p><p><a href="${link}" style="display:inline-block;padding:12px 20px;border-radius:999px;background:#ef2fb0;color:#fff;text-decoration:none;font-weight:bold">Choose a new password</a></p><p style="font-size:12px;color:#555">Or paste this into your browser: ${link}</p><p style="font-size:12px;color:#555">If you didn't ask for this, ignore this email. Your password stays the same.</p></div>`;
    try { await sendMail(env, email, 'Reset your Surf Fantasy Leagues password', text, html); } catch (e) {}
  }
  return json({ ok: true });
}
async function resetPw(req, env) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const t = String(b.token || '');
  const password = String(b.password || '');
  if (!/^[0-9a-f]{64}$/.test(t)) return json({ error: 'This reset link is not valid. Ask for a new one.' }, 400);
  if (!pwOk(password)) return json({ error: PW_RULE }, 400);
  await migrate(env);
  const th = await sha256(t), now = Date.now();
  const r = await env.DB.prepare('UPDATE password_resets SET used = 1 WHERE token_hash = ? AND used = 0 AND expires_at > ?').bind(th, now).run();
  if (!r.meta || r.meta.changes !== 1) return json({ error: 'This reset link has expired or was already used. Ask for a new one.' }, 400);
  const row = await env.DB.prepare('SELECT u.id, u.username FROM password_resets p JOIN users u ON u.id = p.user_id WHERE p.token_hash = ? AND u.disabled = 0').bind(th).first();
  if (!row) return json({ error: 'This account is not available.' }, 400);
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET pw_hash = ? WHERE id = ?').bind(await hashPw(password, env), row.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(row.id)
  ]);
  const ses = await startSession(env, row.id);
  const out = { ok: true, username: row.username };
  if (fromSite(req)) out.token = ses.token;
  return json(out, 200, { 'set-cookie': ses.cookie });
}
async function inviteCols(env) {
  const { results } = await env.DB.prepare('PRAGMA table_info(invite_codes)').all();
  return results.map((r) => r.name);
}
async function inviteCreate(req, env, u) {
  if (!u.is_admin) return json({ error: 'Only the site admin can make invite codes.' }, 403);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const uses = Math.min(20, Math.max(1, parseInt(b.uses, 10) || 1));
  const days = Math.min(60, Math.max(1, parseInt(b.days, 10) || 14));
  const cols = await inviteCols(env);
  const note = cleanText(b.note || '', 0, 40) || '';
  for (let i = 0; i < 6; i++) {
    const code = makeCode(8);
    const vals = { code, uses: 0, max_uses: uses, disabled: 0, expires_at: Date.now() + days * 86400000, created_at: new Date().toISOString(), created_by: u.id, note };
    const keys = Object.keys(vals).filter((k) => cols.includes(k));
    try {
      await env.DB.prepare(`INSERT INTO invite_codes(${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`).bind(...keys.map((k) => vals[k])).run();
      return json({ ok: true, code, maxUses: uses, expiresAt: vals.expires_at });
    } catch (e) {
      if (i === 5) return json({ error: 'Could not make an invite code.' }, 500);
    }
  }
}
async function inviteList(env, u) {
  if (!u.is_admin) return json({ error: 'Only the site admin can see invite codes.' }, 403);
  const cols = await inviteCols(env);
  const want = ['code', 'uses', 'max_uses', 'disabled', 'expires_at', 'created_at', 'note'].filter((k) => cols.includes(k));
  const order = cols.includes('created_at') ? 'created_at DESC' : 'rowid DESC';
  const { results } = await env.DB.prepare(`SELECT ${want.join(', ')} FROM invite_codes ORDER BY ${order} LIMIT 30`).all();
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  return json({ invites: results, users: n.n, maxUsers: parseInt(env.MAX_USERS, 10) || 10 });
}
async function poolsList(env, u) {
  const { results } = await env.DB.prepare(
    'SELECT p.id, p.code, p.name, p.max_members, p.mode, p.joining_open, p.draft_status, c.title AS contest, m.role, m.team_name, (SELECT COUNT(*) FROM pool_members x WHERE x.pool_id = p.id) AS members FROM pool_members m JOIN pools p ON p.id = m.pool_id JOIN contests c ON c.id = p.contest_id WHERE m.user_id = ? AND p.cancelled_at IS NULL ORDER BY p.created_at DESC'
  ).bind(u.id).all();
  return json({ pools: results });
}
async function poolDetail(env, u, id) {
  const pid = parseInt(id, 10);
  if (!(pid > 0)) return json({ error: 'Pool not found.' }, 404);
  const p = await env.DB.prepare(
    'SELECT p.id, p.code, p.name, p.max_members, p.mode, p.chat_url, p.joining_open, p.draft_status, p.roster_men, p.roster_women, p.entry_fee_cents, c.title AS contest, c.location, c.start_date, c.end_date, m.role, m.team_name FROM pools p JOIN contests c ON c.id = p.contest_id JOIN pool_members m ON m.pool_id = p.id AND m.user_id = ? WHERE p.id = ? AND p.cancelled_at IS NULL'
  ).bind(u.id, pid).first();
  if (!p) return json({ error: 'Pool not found.' }, 404);
  const { results } = await env.DB.prepare('SELECT team_name, role, joined_at FROM pool_members WHERE pool_id = ? ORDER BY joined_at').bind(pid).all();
  return json({ pool: p, members: results });
}
async function poolCreate(req, env, u) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const name = cleanText(b.name, 3, 40);
  const team = cleanText(b.teamName, 2, 30);
  const size = parseInt(b.maxMembers, 10);
  const chat = cleanUrl(b.chatUrl);
  if (!name) return json({ error: 'Pool name must be 3-40 characters.' }, 400);
  if (!team) return json({ error: 'Team name must be 2-30 characters.' }, 400);
  if (!(size >= 2 && size <= 20)) return json({ error: 'A pool needs 2 to 20 teams.' }, 400);
  if (chat === null) return json({ error: 'The chat link must be a full https:// address.' }, 400);
  const c = await env.DB.prepare('SELECT id, end_date, results_json, pool_supported, published FROM contests WHERE id = ?').bind(String(b.contestId || '')).first();
  if (!c || !c.published || !c.pool_supported) return json({ error: 'That contest is not open for pools.' }, 400);
  const mode = c.results_json ? 'replay' : 'live';
  if (mode === 'live' && c.end_date && c.end_date < new Date().toISOString().slice(0, 10)) return json({ error: 'That contest has already finished.' }, 400);
  const owned = await env.DB.prepare('SELECT COUNT(*) AS n FROM pools WHERE owner_id = ? AND cancelled_at IS NULL').bind(u.id).first();
  if (owned.n >= 5) return json({ error: 'You can own up to 5 pools.' }, 403);
  const now = new Date().toISOString();
  for (let i = 0; i < 6; i++) {
    const code = makeCode(6);
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO pools(code, contest_id, owner_id, name, max_members, chat_url, mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(code, c.id, u.id, name, size, chat || null, mode, now),
        env.DB.prepare("INSERT INTO pool_members(pool_id, user_id, team_name, role, joined_at) SELECT id, ?, ?, 'owner', ? FROM pools WHERE code = ?")
          .bind(u.id, team, now, code)
      ]);
      const p = await env.DB.prepare('SELECT id FROM pools WHERE code = ?').bind(code).first();
      return json({ ok: true, poolId: p.id, code });
    } catch (e) {
      if (i === 5) break;
    }
  }
  return json({ error: 'Could not create the pool. Try again.' }, 500);
}
async function poolJoin(req, env, u) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const code = String(b.code || '').trim().toUpperCase();
  const team = cleanText(b.teamName, 2, 30);
  if (!/^[A-Z2-9]{6}$/.test(code)) return json({ error: 'Enter the 6-character join code.' }, 400);
  if (!team) return json({ error: 'Team name must be 2-30 characters.' }, 400);
  const buckets = ['join:' + u.id];
  if (await isLimited(env, buckets)) return json({ error: 'Too many wrong codes. Try again in 15 minutes.' }, 429);
  const r = await env.DB.prepare(
    "INSERT INTO pool_members(pool_id, user_id, team_name, role, joined_at) SELECT p.id, ?, ?, 'member', ? FROM pools p WHERE p.code = ? AND p.joining_open = 1 AND p.cancelled_at IS NULL AND p.draft_status = 'lobby' AND (SELECT COUNT(*) FROM pool_members m WHERE m.pool_id = p.id) < p.max_members AND NOT EXISTS (SELECT 1 FROM pool_members m WHERE m.pool_id = p.id AND (m.user_id = ? OR lower(m.team_name) = lower(?)))"
  ).bind(u.id, team, new Date().toISOString(), code, u.id, team).run();
  const p = await env.DB.prepare('SELECT id, joining_open, cancelled_at, draft_status, max_members FROM pools WHERE code = ?').bind(code).first();
  if (r.meta && r.meta.changes === 1) return json({ ok: true, poolId: p.id });
  if (!p || p.cancelled_at) {
    await addFailure(env, buckets);
    return json({ error: 'No pool found with that code.' }, 404);
  }
  if (await env.DB.prepare('SELECT 1 AS x FROM pool_members WHERE pool_id = ? AND user_id = ?').bind(p.id, u.id).first()) return json({ error: 'You are already in this pool.' }, 409);
  if (await env.DB.prepare('SELECT 1 AS x FROM pool_members WHERE pool_id = ? AND lower(team_name) = lower(?)').bind(p.id, team).first()) return json({ error: 'That team name is taken in this pool.' }, 409);
  if (!p.joining_open) return json({ error: 'This pool is closed to new teams.' }, 403);
  if (p.draft_status !== 'lobby') return json({ error: 'The draft has already started.' }, 403);
  return json({ error: 'This pool is full.' }, 403);
}
async function poolLeave(req, env, u) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const pid = parseInt(b.poolId, 10);
  const r = await env.DB.prepare("DELETE FROM pool_members WHERE pool_id = ? AND user_id = ? AND role = 'member' AND (SELECT draft_status FROM pools WHERE id = ?) = 'lobby'").bind(pid, u.id, pid).run();
  if (!r.meta || r.meta.changes !== 1) return json({ error: 'You cannot leave this pool.' }, 400);
  return json({ ok: true });
}
async function poolJoining(req, env, u) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const pid = parseInt(b.poolId, 10);
  const r = await env.DB.prepare("UPDATE pools SET joining_open = ? WHERE id = ? AND owner_id = ? AND draft_status = 'lobby' AND cancelled_at IS NULL").bind(b.open ? 1 : 0, pid, u.id).run();
  if (!r.meta || r.meta.changes !== 1) return json({ error: 'Only the owner can change this before the draft.' }, 403);
  return json({ ok: true, open: !!b.open });
}
function page() {
  const nonce = rand(16);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#080d29"><title>Surf Pools</title>
<style nonce="${nonce}">*{box-sizing:border-box}html{color-scheme:dark;-webkit-text-size-adjust:100%}
body{margin:0;background:radial-gradient(ellipse at top left,#2b1246,#080d29 65%) fixed;color:#f4f6ff;font:14px/1.45 system-ui,Arial,sans-serif;min-height:100vh}
header,main,footer{max-width:1040px;margin:auto;padding:14px}
h1{margin:0;font-size:28px;font-style:italic;letter-spacing:.5px}h1 span{color:#ff46bc}
header p{color:#afbdd8;font-size:12px;margin:3px 0 8px}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
h2{font-size:16px;margin:0 0 10px;color:#67eaff;text-transform:uppercase;font-style:italic}
button,select,input{font:inherit;font-size:13px;padding:9px 12px;border-radius:8px;border:1px solid #4b4a92;background:#16164a;color:#fff}
input,select{width:100%;margin:4px 0 12px}
input::placeholder{color:#7f8ab5}
button{cursor:pointer;background:#23235d}
button.on,button.go{background:linear-gradient(100deg,#f23ab8,#04dce9);color:#070d27;font-weight:800;border:0}
button.ghost{background:transparent}
nav{display:flex;gap:6px;padding-top:6px;overflow:auto}nav button{white-space:nowrap}
.who{display:flex;align-items:center;gap:10px;font-size:12px;color:#afbdd8}
#view{border:2px solid #1ee4f0;border-radius:14px;box-shadow:inset 0 0 0 2px #96247c;padding:14px;background:#100f30;min-height:240px}
section{border:1px solid #32305c;border-radius:10px;padding:12px;margin-top:12px}
#view>section:first-child,.grid>section{margin-top:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:12px;margin-top:12px}
.card{border:1px solid #32305c;border-left:3px solid #04dce9;border-radius:10px;padding:12px;background:#15143a;cursor:pointer}
.card.static{cursor:default}.card:hover{border-color:#ff46bc}.card.static:hover{border-color:#32305c}
.card h3{margin:0 0 4px;font-size:16px}
.muted{color:#a7b9d9;font-size:12px}
.badge{display:inline-block;font-size:10px;font-weight:750;font-style:italic;padding:2px 7px;border-radius:5px;background:#b91782;color:#fff;margin-left:8px;vertical-align:middle}
.badge.cy{background:#0a8f9a}
.code{font-size:36px;font-weight:900;font-style:italic;letter-spacing:7px;color:#ffda66;font-variant-numeric:tabular-nums}
.code.sm{font-size:22px;letter-spacing:3px;overflow-wrap:anywhere}
.team{display:grid;grid-template-columns:28px 1fr auto;gap:8px 12px;padding:10px 0;border-bottom:1px solid #30255c;align-items:center}
.rank{color:#ffda66;font-style:italic;font-weight:900;font-size:18px}
.toast{min-height:20px;font-size:13px;color:#72e2bb;margin:10px 4px 0}.toast.bad,.err{color:#ffb48e}
.tabs{display:flex;gap:6px;margin-bottom:14px}.tabs button{flex:1}
label{font-size:11px;color:#9fe9f2;text-transform:uppercase;letter-spacing:.5px}
.auth{max-width:420px;margin:8px auto}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.hide{display:none!important}
footer{font-size:11px;color:#92a8cb}
a{color:#66eaff}
@media(max-width:500px){header,main,footer{padding:10px}h1{font-size:23px}#view{padding:10px}.code{font-size:30px;letter-spacing:5px}}</style></head>
<body><header><div class="row"><div><h1>SURF <span>POOLS</span></h1><p>ISA World Surfing Games 2026 \u00b7 Punta Rocas, Peru</p></div><div id="who" class="who hide"><span id="uname"></span><button id="out" class="ghost">Log out</button></div></div><nav id="nav" class="hide"></nav></header>
<main><div id="view"></div><p id="toast" class="toast"></p></main>
<footer>Independent fantasy game. Not affiliated with the ISA. Always verify official results before settling any payout.</footer>
<script nonce="${nonce}">
const $=(i)=>document.getElementById(i);
function h(t,c){const e=document.createElement(t);if(c)e.className=c;for(let i=2;i<arguments.length;i++){const x=arguments[i];if(x==null||x===false)continue;e.append(x.nodeType?x:document.createTextNode(String(x)))}return e}
async function api(path,body){let r;try{r=await fetch(path,body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}:{})}catch(e){return{ok:false,d:{error:'Network error. Try again.'}}}let d={};try{d=await r.json()}catch(e){}return{ok:r.ok,d:d}}
function toast(t,bad){const m=$('toast');m.textContent=t||'';m.className=bad?'toast bad':'toast'}
function inp(ph,type,ac){const e=h('input');e.placeholder=ph||'';e.type=type||'text';if(ac)e.autocomplete=ac;return e}
function field(label,input){return h('div',null,h('label',null,label),input)}
function dates(a,b){const f=function(s){return new Date(s+'T00:00:00Z').toLocaleDateString('en-US',{month:'short',day:'numeric',timeZone:'UTC'})};return f(a)+' \u2013 '+f(b)}
let ME=null,CONTESTS=[],tab='pools';

const PWR='At least 8 characters, with 1 number and 1 special character.';
function pwOk(p){return p.length>=8&&p.length<=200&&/[0-9]/.test(p)&&/[^A-Za-z0-9]/.test(p)}
function authView(first,emailReset){
 let mode=first?'signup':'login';const v=$('view');
 function draw(){
  v.replaceChildren();const box=h('div','auth');
  const tabs=h('div','tabs');
  const a=h('button',mode==='login'?'on':'','Log in');const b=h('button',mode==='signup'?'on':'','Create account');
  a.onclick=function(){mode='login';toast('');draw()};b.onclick=function(){mode='signup';toast('');draw()};tabs.append(a,b);box.append(tabs);
  if(first)box.append(h('p','muted','Welcome. The first account becomes the admin and needs your setup code.'));
  const f=h('form');
  if(mode==='forgot'){
   const em=inp('you@example.com','email','email');
   f.append(h('p','muted','Enter the email on your account and we will send you a link to choose a new password.'),field('Email',em));
   const s=h('button','go','Send reset link');s.type='submit';f.append(s);
   const back=h('button','ghost','Back to log in');back.type='button';back.onclick=function(){mode='login';toast('');draw()};f.append(back);
   f.onsubmit=async function(e){e.preventDefault();toast('');const r=await api('/api/forgot',{email:em.value});if(!r.ok)return toast(r.d.error||'Could not send the email.',true);f.replaceChildren(h('p',null,'Check your email. If an account uses that address, a reset link is on its way. It works for 30 minutes.'),back)};
   box.append(f);v.append(box);return}
  const u=inp(mode==='login'?'Username or email':'Username','text','username');u.maxLength=mode==='login'?254:24;
  const p=inp(mode==='login'?'Password':'Create a password','password',mode==='login'?'current-password':'new-password');
  f.append(field(mode==='login'?'Username or email':'Username',u));
  let em,ph,cd,p2,hint;
  if(mode==='signup'){em=inp('Email','email','email');ph=inp('Phone, e.g. +15551234567','tel','tel');cd=inp(first?'Setup code':'Invite code','text','off');f.append(field('Email',em),field('Phone',ph))}
  f.append(field('Password',p));
  if(mode==='signup'){p2=inp('Type it again','password','new-password');hint=h('p','muted',PWR);f.append(hint,field('Confirm password',p2),field(first?'Setup code':'Invite code',cd));
   const chk=function(){const ok=pwOk(p.value);hint.textContent=(ok?'\u2713 ':'')+PWR;hint.style.color=p.value?(ok?'#5be3a0':'#ffb3c7'):''};p.oninput=chk}
  const s=h('button','go',mode==='login'?'Log in':'Create account');s.type='submit';f.append(s);
  if(mode==='login'){const fg=h('button','ghost','Forgot password?');fg.type='button';fg.onclick=function(){mode='forgot';toast('');draw()};f.append(fg)}
  f.onsubmit=async function(e){e.preventDefault();toast('');
   if(mode==='login'){const r=await api('/api/login',{username:u.value.trim(),password:p.value});if(!r.ok)return toast(r.d.error||'Could not log in.',true);boot()}
   else{if(!pwOk(p.value))return toast(PWR,true);if(p.value!==p2.value)return toast('The two passwords do not match.',true);
    const r=await api('/api/register',{username:u.value.trim(),password:p.value,email:em.value.trim(),phone:ph.value.trim(),code:cd.value.trim()});if(!r.ok)return toast(r.d.error||'Could not create account.',true);if(r.d.recoveryCode)recoveryView(r.d.recoveryCode);else boot()}};
  box.append(f);v.append(box)}
 draw()}

function recoveryView(code){
 const v=$('view');v.replaceChildren();
 const b=h('button','go','I saved it');b.onclick=boot;
 v.append(h('section',null,h('h2',null,'Save your recovery code'),h('p','muted','This is the only time it is shown. Keep it somewhere safe.'),h('div','code sm',code),h('div','actions',b)))}

function nav(){
 const n=$('nav');n.replaceChildren();const act=tab==='pool'?'pools':tab;
 [['pools','My pools'],['contests','Contests']].forEach(function(t){const b=h('button',act===t[0]?'on':'',t[1]);b.onclick=function(){go(t[0])};n.append(b)})}

async function go(t,id){tab=t;nav();toast('');if(t==='pools')await poolsView();else if(t==='pool')await poolView(id);else contestsView()}

function joinForm(){
 const s=h('section',null,h('h2',null,'Join a pool'));const f=h('form');
 const code=inp('6-character code');code.maxLength=6;code.autocapitalize='characters';
 const team=inp('Your team name');team.maxLength=30;
 const b=h('button','go','Join pool');b.type='submit';
 f.append(field('Join code',code),field('Team name',team),b);
 f.onsubmit=async function(e){e.preventDefault();const r=await api('/api/pools/join',{code:code.value,teamName:team.value});if(!r.ok)return toast(r.d.error||'Could not join.',true);go('pool',r.d.poolId);toast('You joined the pool.')};
 s.append(f);return s}

function createForm(){
 const s=h('section',null,h('h2',null,'Create a pool'));
 const open=CONTESTS.filter(function(c){return c.pool_supported});
 if(!open.length){s.append(h('p','muted','No contests are open for pools right now.'));return s}
 const f=h('form');
 const sel=h('select');open.forEach(function(c){const o=h('option',null,c.title+(c.has_results?' (replay)':' (live)'));o.value=c.id;sel.append(o)});
 const name=inp('Pool name');name.maxLength=40;
 const team=inp('Your team name');team.maxLength=30;
 const size=inp('Number of teams','number');size.min=2;size.max=20;size.value=10;
 const chat=inp('https://... (optional)','url');chat.maxLength=200;
 const b=h('button','go','Create pool');b.type='submit';
 f.append(field('Contest',sel),field('Pool name',name),field('Your team name',team),field('Teams allowed (2-20)',size),field('Group chat link (optional)',chat),b);
 f.onsubmit=async function(e){e.preventDefault();const r=await api('/api/pools/create',{contestId:sel.value,name:name.value,teamName:team.value,maxMembers:size.value,chatUrl:chat.value});if(!r.ok)return toast(r.d.error||'Could not create the pool.',true);go('pool',r.d.poolId);toast('Pool created. Share the code with your friends.')};
 s.append(f);return s}

async function poolsView(){
 const v=$('view');v.replaceChildren(h('p','muted','Loading...'));
 const r=await api('/api/pools');const list=r.d.pools||[];v.replaceChildren();
 const mine=h('section',null,h('h2',null,'My pools'));
 if(!list.length)mine.append(h('p','muted','You are not in a pool yet. Create one or join with a code.'));
 const g=h('div','grid');
 list.forEach(function(p){
  const c=h('div','card',h('h3',null,p.name,p.role==='owner'?h('span','badge','OWNER'):null),h('div','muted',p.contest),h('div','muted',p.members+' of '+p.max_members+' teams \u00b7 '+(p.mode==='live'?'Live':'Replay')+' \u00b7 code '+p.code));
  c.onclick=function(){go('pool',p.id)};g.append(c)});
 mine.append(g);v.append(mine);
 const two=h('div','grid');two.append(joinForm(),createForm());v.append(two)}

async function poolView(id){
 const v=$('view');v.replaceChildren(h('p','muted','Loading...'));
 const r=await api('/api/pool?id='+encodeURIComponent(id));
 if(!r.ok){toast(r.d.error||'Pool not found.',true);return go('pools')}
 const p=r.d.pool,m=r.d.members;v.replaceChildren();
 const back=h('button','ghost','\u2190 All pools');back.onclick=function(){go('pools')};
 v.append(h('section',null,h('div','row',h('div',null,h('h2',null,p.name),h('div','muted',p.contest+' \u00b7 '+p.location+' \u00b7 '+dates(p.start_date,p.end_date)+' \u00b7 '+(p.mode==='live'?'Live':'Replay')+' pool')),back)));
 const codeBox=h('section',null,h('h2',null,'Join code'),h('div','code',p.code),h('p','muted',p.joining_open?'Friends enter this code under Join a pool.':'This pool is closed to new teams.'));
 if(p.chat_url){const a=h('a',null,'Open group chat');a.href=p.chat_url;a.target='_blank';a.rel='noopener noreferrer';codeBox.append(a)}
 v.append(codeBox);
 const teams=h('section',null,h('h2',null,'Teams ('+m.length+' of '+p.max_members+')'));
 m.forEach(function(x,i){teams.append(h('div','team',h('div','rank',i+1),h('div',null,h('strong',null,x.team_name),x.role==='owner'?h('span','badge','OWNER'):null),h('div','muted',p.roster_men+' men \u00b7 '+p.roster_women+' women')))});
 v.append(teams);
 v.append(h('section',null,h('h2',null,'Draft'),h('p','muted','Each team drafts '+p.roster_men+' men and '+p.roster_women+' women. The draft room is coming soon.')));
 const act=h('div','actions');
 if(p.role==='owner'&&p.draft_status==='lobby'){
  const t=h('button',null,p.joining_open?'Close pool to new teams':'Reopen pool');
  t.onclick=async function(){const q=await api('/api/pools/joining',{poolId:p.id,open:!p.joining_open});if(!q.ok)return toast(q.d.error||'Could not update.',true);go('pool',p.id)};act.append(t)}
 if(p.role==='member'&&p.draft_status==='lobby'){
  const l=h('button',null,'Leave pool');
  l.onclick=async function(){if(!confirm('Leave this pool?'))return;const q=await api('/api/pools/leave',{poolId:p.id});if(!q.ok)return toast(q.d.error||'Could not leave.',true);go('pools');toast('You left the pool.')};act.append(l)}
 if(act.children.length)v.append(act)}

function contestsView(){
 const v=$('view');v.replaceChildren();const s=h('section',null,h('h2',null,'Contests'));const g=h('div','grid');
 CONTESTS.forEach(function(c){
  g.append(h('div','card static',h('h3',null,c.title,c.pool_supported?h('span','badge cy','POOLS OPEN'):null),h('div','muted',c.location+' \u00b7 '+dates(c.start_date,c.end_date)),c.pool_supported?null:h('div','muted',c.pool_note||'Pools are not available for this contest yet.')))});
 s.append(g);v.append(s)}

async function boot(){
 const me=await api('/api/me');
 if(me.ok&&me.d.user){
  ME=me.d.user;$('uname').textContent=ME.username+(ME.admin?' (admin)':'');$('who').classList.remove('hide');$('nav').classList.remove('hide');
  const c=await api('/api/contests');CONTESTS=c.d.contests||[];go('pools')}
 else{
  ME=null;$('who').classList.add('hide');$('nav').classList.add('hide');
  const cfg=await api('/api/config');authView(!!cfg.d.firstRun,!!cfg.d.emailReset)}}
$('out').onclick=async function(){await api('/api/logout',{});toast('');boot()};
boot();
</script></body></html>`;
  return new Response(html, {
    headers: baseHeaders({
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
    })
  });
}

function withCors(req, res) {
  if (req.headers.get('origin') !== SITE) return res;
  const h = new Headers(res.headers);
  h.set('access-control-allow-origin', SITE);
  h.set('vary', 'Origin');
  h.delete('set-cookie');
  return new Response(res.body, { status: res.status, headers: h });
}
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      if (request.headers.get('origin') !== SITE) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: { 'access-control-allow-origin': SITE, 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'Content-Type, Authorization', 'access-control-max-age': '86400', vary: 'Origin' } });
    }
    return withCors(request, await handle(request, env));
  }
};
async function handle(request, env) {
  {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (path === '/health') return json({ ok: true, version: APP_VERSION, realMoney: false });
    if (!env.DB) return json({ error: 'Database is not connected. Add a D1 binding named DB.' }, 503);
    try {
      if (request.method === 'GET') {
        if (path === '/') return page();
        if (path === '/api/config') {
          const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM contests').first();
          const u = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
          return json({ appName: 'Surf Pools', contests: c.n, firstRun: u.n === 0, emailReset: emailOn(env), passwordRule: PW_RULE });
        }
        if (path === '/api/contests') {
          const { results } = await env.DB.prepare(
            'SELECT id, title, location, start_date, end_date, pool_supported, pool_note, (results_json IS NOT NULL) AS has_results FROM contests WHERE published = 1 ORDER BY start_date DESC'
          ).all();
          return json({ contests: results });
        }
        if (path === '/api/me') {
          const u = await currentUser(request, env);
          return json({ user: u ? { username: u.username, admin: !!u.is_admin, email: u.email, phone: u.phone, emailVerified: !!u.email_verified, phoneVerified: !!u.phone_verified } : null });
        }
        if (path === '/api/pools' || path === '/api/pool') {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          return path === '/api/pools' ? await poolsList(env, u) : await poolDetail(env, u, url.searchParams.get('id'));
        }
        if (path === '/api/invites') {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          return await inviteList(env, u);
        }
      } else if (request.method === 'POST') {
        if (path === '/api/register') { await migrate(env); return await register(request, env, ip); }
        if (path === '/api/login') return await login(request, env, ip);
        if (path === '/api/logout') return await logout(request, env);
        if (path === '/api/recover') return await recover(request, env, ip);
        if (path === '/api/forgot') return await forgot(request, env, ip);
        if (path === '/api/reset') return await resetPw(request, env);
        if (path === '/api/invites/create') {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          return await inviteCreate(request, env, u);
        }
        if (path.startsWith('/api/pools/')) {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          if (path === '/api/pools/create') return await poolCreate(request, env, u);
          if (path === '/api/pools/join') return await poolJoin(request, env, u);
          if (path === '/api/pools/leave') return await poolLeave(request, env, u);
          if (path === '/api/pools/joining') return await poolJoining(request, env, u);
        }
      }
    } catch (e) {
      return json({ error: 'Something went wrong on the server. Please try again.' }, 500);
    }
    return json({ error: 'Not found' }, 404);
  }
};


