const SITE = 'https://ignitecontentlab.github.io';
const APP_VERSION = 'app-0.10.0';
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
    if (text.length > 32768) return null;
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
    'SELECT u.id, u.username, u.is_admin, u.admin_level, u.email, u.phone, u.email_verified, u.phone_verified FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0'
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
  const code = String(b.code || '').trim().toUpperCase();
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
  } else if (b.claim && claimOpen(await claimByToken(env, b.claim)) && !(await claimByToken(env, b.claim)).user_id) {
    // a surfer opening their private claim link can make an account without an invite code
    try {
      await env.DB.prepare('INSERT INTO users(username, email, phone, pw_hash, recovery_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
        .bind(username, email, phone, pwHash, recHash, now).run();
    } catch (e) {
      return json({ error: 'That username or email is already in use.' }, 409);
    }
  } else {
    if (!(await toggle(env, 'signups'))) return json({ error: 'New sign-ups are paused right now. Try again later.' }, 403);
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
  const uses = Math.min(100, Math.max(1, parseInt(b.uses, 10) || 1));
  const days = Math.min(90, Math.max(1, parseInt(b.days, 10) || 14));
  const cols = await inviteCols(env);
  const note = cleanText(b.note || '', 0, 40) || '';
  let custom = String(b.code || '').trim().toUpperCase();
  if (custom) {
    if (!/^[A-Z0-9]{4,8}$/.test(custom)) return json({ error: 'Your own code must be 4 to 8 letters or numbers.' }, 400);
    if (await env.DB.prepare('SELECT 1 AS x FROM invite_codes WHERE code = ?').bind(custom).first()) return json({ error: 'That code is already in use. Pick another.' }, 409);
  }
  for (let i = 0; i < 6; i++) {
    const code = custom || makeCode(8);
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
  await migrateDrafts(env);
  const { results } = await env.DB.prepare(
    'SELECT p.id, p.code, p.name, p.max_members, p.mode, p.joining_open, p.draft_status, p.contest_id, c.title AS contest, c.start_date, c.end_date, m.role, m.team_name, r.draft_at, r.status AS draft_state, (SELECT COUNT(*) FROM pool_members x WHERE x.pool_id = p.id) AS members FROM pool_members m JOIN pools p ON p.id = m.pool_id JOIN contests c ON c.id = p.contest_id LEFT JOIN pool_rules r ON r.pool_id = p.id WHERE m.user_id = ? AND p.cancelled_at IS NULL ORDER BY p.created_at DESC'
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
// ---------- Drafts, contest catalog and public drafts (app-0.9) ----------
const CATALOG_URL = SITE + '/isa-peru-fantasy-2026/data/contests.json';
const DAY = 86400000;
const CLOCKS = [30, 45, 60, 90, 120, 180, 300, 600, 1800, 3600, 14400, 28800, 86400];
const GEN = { men: 3, women: 2 };
let draftsReady = false;
async function migrateDrafts(env) {
  if (draftsReady) return;
  const q = [
    'CREATE TABLE IF NOT EXISTS catalog(contest_id TEXT PRIMARY KEY, name TEXT, org TEXT, location TEXT, start_date TEXT, end_date TEXT, status TEXT, draftable INTEGER NOT NULL DEFAULT 0, roster_json TEXT, roster_source TEXT, roster_note TEXT, conflicts_json TEXT, results_json TEXT, manual INTEGER NOT NULL DEFAULT 0, updated_at INTEGER)',
    "CREATE TABLE IF NOT EXISTS pool_rules(pool_id INTEGER PRIMARY KEY, rules_json TEXT NOT NULL, draft_at INTEGER, status TEXT NOT NULL DEFAULT 'scheduled', order_json TEXT, pick_no INTEGER NOT NULL DEFAULT 0, deadline INTEGER, started_at INTEGER, ended_at INTEGER)",
    'CREATE TABLE IF NOT EXISTS draft_picks(pool_id INTEGER NOT NULL, pick_no INTEGER NOT NULL, user_id INTEGER NOT NULL, surfer TEXT NOT NULL, division TEXT NOT NULL, auto INTEGER NOT NULL DEFAULT 0, at INTEGER NOT NULL, PRIMARY KEY(pool_id, pick_no), UNIQUE(pool_id, surfer))',
    'CREATE TABLE IF NOT EXISTS draft_queue(pool_id INTEGER NOT NULL, user_id INTEGER NOT NULL, queue_json TEXT NOT NULL, PRIMARY KEY(pool_id, user_id))',
    'CREATE TABLE IF NOT EXISTS gdrafts(contest_id TEXT PRIMARY KEY, opens_at INTEGER NOT NULL, closes_at INTEGER NOT NULL, wildcard_rank INTEGER NOT NULL, men INTEGER NOT NULL, women INTEGER NOT NULL, closed_reason TEXT, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS gentries(contest_id TEXT NOT NULL, user_id INTEGER NOT NULL, team_name TEXT NOT NULL, joined_at INTEGER NOT NULL, picks_json TEXT, combo TEXT, locked_at INTEGER, PRIMARY KEY(contest_id, user_id))',
    'CREATE UNIQUE INDEX IF NOT EXISTS gentries_combo ON gentries(contest_id, combo)',
    'CREATE UNIQUE INDEX IF NOT EXISTS gentries_team ON gentries(contest_id, team_name COLLATE NOCASE)',
    'CREATE TABLE IF NOT EXISTS app_state(k TEXT PRIMARY KEY, v TEXT)'
  ];
  await env.DB.batch(q.map((s) => env.DB.prepare(s)));
  draftsReady = true;
}
const endMs = (d) => Date.parse(d + 'T23:59:59Z');
const startMs = (d) => Date.parse(d + 'T00:00:00Z');
const rnd = (n) => crypto.getRandomValues(new Uint32Array(1))[0] % n;
function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = rnd(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }
const pj = (s, d) => { try { return s ? JSON.parse(s) : d; } catch (e) { return d; } };

// ---------- catalog sync ----------
async function contestCols(env) {
  const { results } = await env.DB.prepare('PRAGMA table_info(contests)').all();
  return results;
}
async function syncCatalog(env, force) {
  await migrateDrafts(env);
  const st = await env.DB.prepare("SELECT v FROM app_state WHERE k = 'catalog_sync'").first();
  const last = st ? parseInt(st.v, 10) : 0;
  if (!force && Date.now() - last < 15 * 60000) return { skipped: true };
  await env.DB.prepare("INSERT INTO app_state(k, v) VALUES ('catalog_sync', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(String(Date.now())).run();
  let doc;
  try {
    const r = await fetch(CATALOG_URL + '?t=' + Date.now(), { headers: { 'user-agent': 'surf-pools-app' } });
    if (!r.ok) throw new Error('catalog http ' + r.status);
    doc = await r.json();
    if (!doc || !Array.isArray(doc.contests)) throw new Error('catalog has no contests');
  } catch (e) {
    // try again in about a minute instead of waiting the full 15
    await env.DB.prepare("UPDATE app_state SET v = ? WHERE k = 'catalog_sync'").bind(String(Date.now() - 14 * 60000)).run();
    return { error: String(e.message || e) };
  }
  const list = Array.isArray(doc.contests) ? doc.contests : [];
  const info = await contestCols(env);
  const cols = info.map((c) => c.name);
  const now = Date.now();
  const stmts = [], mirror = [];
  for (const c of list) {
    if (!c || !/^[a-z0-9-]{3,60}$/.test(c.id || '')) continue;
    const roster = c.roster && Array.isArray(c.roster.men) && Array.isArray(c.roster.women) ? c.roster : null;
    stmts.push(env.DB.prepare(
      `INSERT INTO catalog(contest_id, name, org, location, start_date, end_date, status, draftable, roster_json, roster_source, roster_note, conflicts_json, results_json, manual, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
       ON CONFLICT(contest_id) DO UPDATE SET name = excluded.name, org = excluded.org, location = excluded.location, start_date = excluded.start_date, end_date = excluded.end_date, status = excluded.status,
         draftable = CASE WHEN catalog.manual = 1 THEN (excluded.status != 'finished') ELSE excluded.draftable END,
         roster_json = CASE WHEN catalog.manual = 1 THEN catalog.roster_json ELSE excluded.roster_json END,
         roster_source = CASE WHEN catalog.manual = 1 THEN catalog.roster_source ELSE excluded.roster_source END,
         roster_note = CASE WHEN catalog.manual = 1 THEN catalog.roster_note ELSE excluded.roster_note END,
         conflicts_json = excluded.conflicts_json, results_json = COALESCE(excluded.results_json, catalog.results_json), updated_at = excluded.updated_at`
    ).bind(c.id, String(c.name || c.id).slice(0, 120), c.org || '', c.location || '', c.start, c.end, c.status || 'upcoming', c.draftable ? 1 : 0,
      roster ? JSON.stringify(roster) : null, c.roster_source || null, c.roster_note || '', JSON.stringify(c.conflicts || []), c.results ? JSON.stringify(c.results) : null, now));
    // keep the legacy contests table in step so pools can reference the contest
    const vals = { id: c.id, title: String(c.name || c.id).slice(0, 120), location: c.location || '', start_date: c.start || '', end_date: c.end || '', pool_supported: c.draftable ? 1 : 0, pool_note: c.roster_note || '', published: 1 };
    // fill any other required column the live table has (for example created_at)
    for (const col of info) if (col.notnull && col.dflt_value == null && !(col.name in vals) && !col.pk) vals[col.name] = /INT|REAL|NUM/i.test(col.type || '') ? (/_at$/.test(col.name) ? now : 0) : (/_at$|date/.test(col.name) ? new Date(now).toISOString() : '');
    const keys = Object.keys(vals).filter((k) => cols.includes(k));
    mirror.push(env.DB.prepare(`INSERT INTO contests(${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')}) ON CONFLICT(id) DO UPDATE SET ${keys.filter((k) => k !== 'id').map((k) => `${k} = excluded.${k}`).join(', ')}`).bind(...keys.map((k) => vals[k])));
  }
  try {
    for (let i = 0; i < stmts.length; i += 40) await env.DB.batch(stmts.slice(i, i + 40));
  } catch (e) {
    console.error('catalog save failed', String(e && e.message || e));
    await env.DB.prepare("UPDATE app_state SET v = ? WHERE k = 'catalog_sync'").bind(String(Date.now() - 14 * 60000)).run();
    return { error: 'catalog save failed: ' + String(e && e.message || e) };
  }
  let mirrorErr = null;
  for (const m of mirror) { try { await m.run(); } catch (e) { mirrorErr = String(e && e.message || e); } }
  if (mirrorErr) console.error('contests mirror failed', mirrorErr);
  try { await ensureGeneral(env); } catch (e) { console.error('public drafts failed', String(e && e.message || e)); }
  return { ok: true, contests: list.length, mirrorErr };
}
async function ensureGeneral(env) {
  const now = Date.now();
  const { results } = await env.DB.prepare("SELECT contest_id, start_date, end_date FROM catalog WHERE draftable = 1 AND status != 'finished' AND contest_id NOT IN (SELECT contest_id FROM gdrafts)").all();
  for (const c of results) {
    const s = startMs(c.start_date);
    const closes = Math.min(s + 2 * DAY, endMs(c.end_date));
    if (!(closes > now)) continue;
    await env.DB.prepare('INSERT OR IGNORE INTO gdrafts(contest_id, opens_at, closes_at, wildcard_rank, men, women, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(c.contest_id, s - 3 * DAY, closes, 1 + rnd(10), GEN.men, GEN.women, now).run();
  }
}
async function catalogRow(env, id) {
  return env.DB.prepare('SELECT * FROM catalog WHERE contest_id = ?').bind(String(id || '')).first();
}
function rosterOf(row) {
  const r = pj(row && row.roster_json, null);
  if (!r) return null;
  const fix = (a) => (a || []).filter((s) => s && s.key && s.name).map((s, i) => ({ key: String(s.key), name: String(s.name), country: String(s.country || ''), rank: s.rank || i + 1, ...(s.out ? { out: true } : {}) }));
  return { men: fix(r.men), women: fix(r.women) };
}
function alive(a) {
  return (a || []).filter((s) => !s.out);
}
async function contestsList(env) {
  await migrateDrafts(env);
  await syncCatalog(env, false);
  const today = new Date().toISOString().slice(0, 10);
  const { results } = await env.DB.prepare('SELECT contest_id, name, org, location, start_date, end_date, status, draftable, roster_json, roster_note FROM catalog WHERE end_date >= ? ORDER BY start_date').bind(today).all();
  return json({
    contests: results.map((c) => {
      const r = rosterOf(c);
      return { id: c.contest_id, title: c.name, org: c.org, location: c.location, start_date: c.start_date, end_date: c.end_date, status: c.status, draftable: !!c.draftable, men: r ? alive(r.men).length : 0, women: r ? alive(r.women).length : 0, note: c.roster_note || '' };
    })
  });
}

// ---------- pool rules ----------
function cleanRules(b, contest, members) {
  const n = (v, lo, hi, d) => { const x = parseInt(v, 10); return Number.isFinite(x) ? Math.min(hi, Math.max(lo, x)) : d; };
  const r = {
    men: n(b.men, 1, 6, 3), women: n(b.women, 0, 4, 2),
    clock: CLOCKS.includes(parseInt(b.clock, 10)) ? parseInt(b.clock, 10) : 120,
    auto: b.auto === 'random' ? 'random' : 'best',
    snake: b.snake !== false, flipWomen: b.flipWomen !== false,
    buyIn: n(b.buyIn, 0, 1000, 0), bonus: n(b.bonus, 0, 10000, 0),
    payout: { men: n(b.payout && b.payout.men, 0, 100, 60), women: n(b.payout && b.payout.women, 0, 100, 25), team: n(b.payout && b.payout.team, 0, 100, 15) },
    note: cleanText(String(b.note || '').slice(0, 300), 0, 300) || ''
  };
  if (r.women === 0) r.flipWomen = false;
  if (r.payout.men + r.payout.women + r.payout.team !== 100) return { error: 'The payout split has to add up to 100%.' };
  const at = parseInt(b.draftAt, 10);
  if (!Number.isFinite(at)) return { error: 'Pick a draft date and time.' };
  if (at < Date.now() - 5 * 60000) return { error: 'The draft time is in the past. Pick a time from now on.' };
  if (contest && at > endMs(contest.end_date)) return { error: 'The draft has to happen before the contest ends on ' + contest.end_date + '.' };
  const ros = rosterOf(contest);
  if (ros && members) {
    if (members * r.men > alive(ros.men).length) return { error: `Not enough men in the roster for ${members} teams x ${r.men} picks.` };
    if (members * r.women > alive(ros.women).length) return { error: `Not enough women in the roster for ${members} teams x ${r.women} picks.` };
  }
  return { rules: r, draftAt: at };
}
function sequence(rules, n) {
  // returns [{seat, division, round}] for every pick
  const seq = [];
  const base = [...Array(n).keys()];
  let dir = 1, lastDir = 1;
  for (let r = 0; r < rules.men; r++) {
    const ord = dir === 1 ? base : [...base].reverse();
    ord.forEach((s) => seq.push({ seat: s, division: 'men', round: r + 1 }));
    lastDir = dir;
    if (rules.snake) dir = -dir;
  }
  // women: flipped order means the team that made the last men's pick starts
  let wdir = rules.flipWomen ? -lastDir : 1;
  for (let r = 0; r < rules.women; r++) {
    const ord = wdir === 1 ? base : [...base].reverse();
    ord.forEach((s) => seq.push({ seat: s, division: 'women', round: rules.men + r + 1 }));
    if (rules.snake) wdir = -wdir;
  }
  return seq;
}
function rulesText(r) {
  const fmt = (s) => s >= 3600 ? (s / 3600) + ' hour' + (s > 3600 ? 's' : '') : s >= 60 ? (s / 60) + ' minute' + (s > 60 ? 's' : '') : s + ' seconds';
  const out = [
    `${r.men} round${r.men > 1 ? 's' : ''} of men, then ${r.women} round${r.women !== 1 ? 's' : ''} of women.`,
    'Pick order is a random draw when the draft starts.',
    r.snake ? 'Snake draft: the order reverses every round.' : 'Same order every round.',
    r.women ? (r.flipWomen ? 'The order flips for the women, so the last men\'s pick picks first for women.' : 'Women start in the original order.') : '',
    `Each pick has a ${fmt(r.clock)} clock. If time runs out, the app picks for you: ${r.auto === 'random' ? 'a random available surfer' : 'the best-ranked available surfer'} (your queue is used first).`,
    'Every surfer can only be on one team in this pool.',
    'Men\'s and women\'s winners: the team with the highest individual finish. Team winner: most total points.',
    r.buyIn ? `Buy-in $${r.buyIn} per team${r.bonus ? ` plus $${r.bonus} added to the pot` : ''}. Payout: ${r.payout.men}% men's winner, ${r.payout.women}% women's winner, ${r.payout.team}% overall team. Money is settled outside the app.` : 'No buy-in.',
    r.note || ''
  ];
  return out.filter(Boolean);
}
async function poolRow(env, pid) {
  return env.DB.prepare('SELECT p.*, c.end_date, c.start_date FROM pools p JOIN contests c ON c.id = p.contest_id WHERE p.id = ? AND p.cancelled_at IS NULL').bind(pid).first();
}
async function members(env, pid) {
  const { results } = await env.DB.prepare('SELECT m.user_id, m.team_name, m.role, m.joined_at, u.username FROM pool_members m JOIN users u ON u.id = m.user_id WHERE m.pool_id = ? ORDER BY m.joined_at').bind(pid).all();
  return results;
}

// ---------- draft engine ----------
async function tick(env, pid) {
  const pr = await env.DB.prepare('SELECT * FROM pool_rules WHERE pool_id = ?').bind(pid).first();
  if (!pr) return null;
  const rules = pj(pr.rules_json, {});
  const now = Date.now();
  if (pr.status === 'scheduled') {
    if (!(pr.draft_at && pr.draft_at <= now)) return pr;
    const ms = await members(env, pid);
    if (ms.length < 2) return pr;
    const order = shuffle(ms.map((m) => m.user_id));
    const r = await env.DB.prepare("UPDATE pool_rules SET status = 'live', order_json = ?, pick_no = 0, deadline = ?, started_at = ? WHERE pool_id = ? AND status = 'scheduled'")
      .bind(JSON.stringify(order), now + rules.clock * 1000, now, pid).run();
    if (r.meta.changes === 1) await env.DB.prepare("UPDATE pools SET draft_status = 'live', joining_open = 0 WHERE id = ?").bind(pid).run();
    return env.DB.prepare('SELECT * FROM pool_rules WHERE pool_id = ?').bind(pid).first();
  }
  if (pr.status !== 'live') return pr;
  let cur = pr;
  for (let guard = 0; guard < 400 && cur.status === 'live' && cur.deadline <= Date.now(); guard++) {
    await autoPick(env, pid, cur, rules);
    cur = await env.DB.prepare('SELECT * FROM pool_rules WHERE pool_id = ?').bind(pid).first();
  }
  return cur;
}
async function autoPick(env, pid, pr, rules) {
  const order = pj(pr.order_json, []);
  const seq = sequence(rules, order.length);
  const slot = seq[pr.pick_no];
  if (!slot) return finishIfDone(env, pid, pr, seq.length);
  const uid = order[slot.seat];
  const pool = await poolRow(env, pid);
  const ros = rosterOf(await catalogRow(env, pool.contest_id));
  const taken = new Set((await env.DB.prepare('SELECT surfer FROM draft_picks WHERE pool_id = ?').bind(pid).all()).results.map((x) => x.surfer));
  const avail = ((ros && ros[slot.division]) || []).filter((s) => !s.out && !taken.has(s.key));
  let pick = null;
  const q = await env.DB.prepare('SELECT queue_json FROM draft_queue WHERE pool_id = ? AND user_id = ?').bind(pid, uid).first();
  for (const k of pj(q && q.queue_json, [])) { const s = avail.find((a) => a.key === k); if (s) { pick = s; break; } }
  if (!pick && avail.length) pick = rules.auto === 'random' ? avail[rnd(avail.length)] : [...avail].sort((a, b) => a.rank - b.rank)[0];
  return commitPick(env, pid, pr, seq, uid, slot, pick ? pick.key : '__none__' + pr.pick_no, 1, rules);
}
async function commitPick(env, pid, pr, seq, uid, slot, surfer, auto, rules) {
  const now = Date.now();
  const next = pr.pick_no + 1;
  const done = next >= seq.length;
  try {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO draft_picks(pool_id, pick_no, user_id, surfer, division, auto, at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(pid, pr.pick_no, uid, surfer, slot.division, auto, now),
      env.DB.prepare(`UPDATE pool_rules SET pick_no = ?, deadline = ?, status = ?, ended_at = ? WHERE pool_id = ? AND pick_no = ? AND status = 'live'`)
        .bind(next, done ? null : now + rules.clock * 1000, done ? 'done' : 'live', done ? now : null, pid, pr.pick_no)
    ]);
  } catch (e) { return false; }
  if (done) await env.DB.prepare("UPDATE pools SET draft_status = 'done' WHERE id = ?").bind(pid).run();
  return true;
}
async function finishIfDone(env, pid, pr, total) {
  if (pr.pick_no >= total) {
    await env.DB.prepare("UPDATE pool_rules SET status = 'done', deadline = NULL, ended_at = ? WHERE pool_id = ? AND status = 'live'").bind(Date.now(), pid).run();
    await env.DB.prepare("UPDATE pools SET draft_status = 'done' WHERE id = ?").bind(pid).run();
  }
}
async function cronTick(env) {
  await migrateDrafts(env);
  const now = Date.now();
  const { results } = await env.DB.prepare("SELECT pool_id FROM pool_rules WHERE (status = 'live' AND deadline <= ?) OR (status = 'scheduled' AND draft_at <= ?) LIMIT 50").bind(now, now).all();
  for (const r of results) { try { await tick(env, r.pool_id); } catch (e) {} }
  // close public drafts that ran out of time or combinations
  try { const r = await syncCatalog(env, false); if (r && r.error) console.error('catalog sync', r.error); } catch (e) { console.error('cron sync', String(e && e.stack || e)); }
}

// ---------- scoring ----------
function scoreTeam(keys, res, divOf) {
  const t = { men: { best: null, pts: 0 }, women: { best: null, pts: 0 }, total: 0 };
  for (const k of keys) {
    const d = divOf[k];
    if (!d) continue;
    const r = res[k];
    if (!r) continue;
    t[d].pts += r.points || 0;
    t.total += r.points || 0;
    if (r.place && (t[d].best === null || r.place < t[d].best)) t[d].best = r.place;
  }
  return t;
}
function rankBy(teams, cat) {
  const b = (x) => x === null ? 9999 : x;
  const cmp = {
    men: (a, c) => b(a.s.men.best) - b(c.s.men.best) || c.s.men.pts - a.s.men.pts || c.s.total - a.s.total || a.tie - c.tie,
    women: (a, c) => b(a.s.women.best) - b(c.s.women.best) || c.s.women.pts - a.s.women.pts || c.s.total - a.s.total || a.tie - c.tie,
    team: (a, c) => c.s.total - a.s.total || b(Math.min(b(a.s.men.best), b(a.s.women.best))) - b(Math.min(b(c.s.men.best), b(c.s.women.best))) || a.tie - c.tie,
    menTeam: (a, c) => c.s.men.pts - a.s.men.pts || c.s.total - a.s.total || a.tie - c.tie,
    womenTeam: (a, c) => c.s.women.pts - a.s.women.pts || c.s.total - a.s.total || a.tie - c.tie
  }[cat];
  return [...teams].sort(cmp);
}

// ---------- pool API ----------
async function poolCreate2(req, env, u) {
  await migrateDrafts(env);
  if (!u.admin_level && !u.is_admin && !(await toggle(env, 'poolCreate'))) return json({ error: 'New pools are paused right now. Try again later.' }, 403);
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
  await syncCatalog(env, false);
  const c = await catalogRow(env, b.contestId);
  if (!c || !c.draftable || endMs(c.end_date) < Date.now()) return json({ error: 'That contest is not open for drafts. Only upcoming or live contests with a roster can start one.' }, 400);
  const ros = rosterOf(c);
  const cr = cleanRules(b.rules || {}, c, size);
  if (cr.error) return json({ error: cr.error }, 400);
  const owned = await env.DB.prepare('SELECT COUNT(*) AS n FROM pools WHERE owner_id = ? AND cancelled_at IS NULL').bind(u.id).first();
  if (owned.n >= 10) return json({ error: 'You can run up to 10 pools at once.' }, 403);
  const now = new Date().toISOString();
  for (let i = 0; i < 6; i++) {
    const code = makeCode(6);
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO pools(code, contest_id, owner_id, name, max_members, chat_url, mode, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(code, c.contest_id, u.id, name, size, chat || null, 'live', now),
        env.DB.prepare("INSERT INTO pool_members(pool_id, user_id, team_name, role, joined_at) SELECT id, ?, ?, 'owner', ? FROM pools WHERE code = ?").bind(u.id, team, now, code),
        env.DB.prepare("INSERT INTO pool_rules(pool_id, rules_json, draft_at, status) SELECT id, ?, ?, 'scheduled' FROM pools WHERE code = ?").bind(JSON.stringify(cr.rules), cr.draftAt, code)
      ]);
      const p = await env.DB.prepare('SELECT id FROM pools WHERE code = ?').bind(code).first();
      return json({ ok: true, poolId: p.id, code, roster: { men: alive(ros.men).length, women: alive(ros.women).length } });
    } catch (e) { if (i === 5) break; }
  }
  return json({ error: 'Could not create the pool. Try again.' }, 500);
}
async function poolPreview(env, code) {
  await migrateDrafts(env);
  code = String(code || '').trim().toUpperCase();
  if (!/^[A-Z2-9]{6}$/.test(code)) return json({ error: 'Enter the 6-character join code.' }, 400);
  const p = await env.DB.prepare('SELECT p.id, p.name, p.max_members, p.joining_open, p.draft_status, p.contest_id, c.title, c.start_date, c.end_date, u.username AS owner, (SELECT COUNT(*) FROM pool_members m WHERE m.pool_id = p.id) AS members, r.rules_json, r.draft_at, r.status FROM pools p JOIN contests c ON c.id = p.contest_id JOIN users u ON u.id = p.owner_id LEFT JOIN pool_rules r ON r.pool_id = p.id WHERE p.code = ? AND p.cancelled_at IS NULL').bind(code).first();
  if (!p) return json({ error: 'No pool found with that code.' }, 404);
  const rules = pj(p.rules_json, null);
  return json({ pool: { name: p.name, contest: p.title, start: p.start_date, end: p.end_date, owner: p.owner, members: p.members, max: p.max_members, open: !!p.joining_open && p.draft_status === 'lobby', draftAt: p.draft_at, rules, rulesText: rules ? rulesText(rules) : ['The pool owner has not set draft rules yet.'] } });
}
async function poolJoin2(req, env, u) {
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  if (!b.acceptRules) return json({ error: 'Read the pool rules and tick the box to join.' }, 400);
  return poolJoin(new Request(req.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }), env, u);
}
async function draftState(env, u, pid) {
  await migrateDrafts(env);
  pid = parseInt(pid, 10);
  const me = await env.DB.prepare('SELECT role FROM pool_members WHERE pool_id = ? AND user_id = ?').bind(pid, u.id).first();
  if (!me) return json({ error: 'Pool not found.' }, 404);
  await tick(env, pid);
  const pool = await poolRow(env, pid);
  if (!pool) return json({ error: 'Pool not found.' }, 404);
  const pr = await env.DB.prepare('SELECT * FROM pool_rules WHERE pool_id = ?').bind(pid).first();
  const cat = await catalogRow(env, pool.contest_id);
  const ros = rosterOf(cat) || { men: [], women: [] };
  const ms = await members(env, pid);
  const rules = pr ? pj(pr.rules_json, null) : null;
  const order = pr ? pj(pr.order_json, []) : [];
  const picks = (await env.DB.prepare('SELECT pick_no, user_id, surfer, division, auto, at FROM draft_picks WHERE pool_id = ? ORDER BY pick_no').bind(pid).all()).results;
  const q = await env.DB.prepare('SELECT queue_json FROM draft_queue WHERE pool_id = ? AND user_id = ?').bind(pid, u.id).first();
  const team = (id) => { const m = ms.find((x) => x.user_id === id); return m ? m.team_name : 'Left the pool'; };
  const seq = rules && order.length ? sequence(rules, order.length) : [];
  const onClock = pr && pr.status === 'live' && seq[pr.pick_no] ? order[seq[pr.pick_no].seat] : null;
  const res = pj(cat && cat.results_json, null);
  let standings = null;
  if (res && picks.length) {
    const divOf = {};
    ros.men.forEach((s) => divOf[s.key] = 'men'); ros.women.forEach((s) => divOf[s.key] = 'women');
    const teams = ms.map((m, i) => ({ team: m.team_name, uid: m.user_id, tie: i, s: scoreTeam(picks.filter((p) => p.user_id === m.user_id).map((p) => p.surfer), res, divOf) }));
    const pot = rules ? rules.buyIn * ms.length + rules.bonus : 0;
    standings = ['men', 'women', 'team'].map((cat2) => ({ cat: cat2, pay: rules && pot ? Math.round(pot * rules.payout[cat2]) / 100 : 0, rows: rankBy(teams, cat2).map((t) => ({ team: t.team, best: cat2 === 'team' ? null : t.s[cat2].best, points: cat2 === 'team' ? t.s.total : t.s[cat2].pts })) }));
  }
  return json({
    serverNow: Date.now(),
    pool: { id: pool.id, name: pool.name, code: pool.code, contestId: pool.contest_id, start: pool.start_date, end: pool.end_date, max: pool.max_members, chat: pool.chat_url, owner: me.role === 'owner' },
    contest: cat ? { name: cat.name, location: cat.location, note: cat.roster_note, source: cat.roster_source, hasResults: !!res } : null,
    rules, rulesText: rules ? rulesText(rules) : null,
    draft: pr ? { status: pr.status, at: pr.draft_at, pickNo: pr.pick_no, total: seq.length, deadline: pr.deadline, onClock: onClock ? team(onClock) : null, myTurn: onClock === u.id, order: order.map(team), seq: seq.map((s) => ({ team: team(order[s.seat]), division: s.division, round: s.round })) } : null,
    members: ms.map((m) => ({ team: m.team_name, user: m.username, role: m.role, me: m.user_id === u.id })),
    picks: picks.map((p) => ({ n: p.pick_no, team: team(p.user_id), mine: p.user_id === u.id, surfer: p.surfer, division: p.division, auto: !!p.auto })),
    roster: ros, queue: pj(q && q.queue_json, []), results: res, standings
  });
}
async function draftPick(req, env, u) {
  await migrateDrafts(env);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const pid = parseInt(b.poolId, 10);
  if (!(await env.DB.prepare('SELECT 1 AS x FROM pool_members WHERE pool_id = ? AND user_id = ?').bind(pid, u.id).first())) return json({ error: 'Pool not found.' }, 404);
  const pr = await tick(env, pid);
  if (!pr || pr.status !== 'live') return json({ error: 'The draft is not running right now.' }, 409);
  const rules = pj(pr.rules_json, {});
  const order = pj(pr.order_json, []);
  const seq = sequence(rules, order.length);
  const slot = seq[pr.pick_no];
  if (!slot || order[slot.seat] !== u.id) return json({ error: 'It is not your pick yet.' }, 409);
  const pool = await poolRow(env, pid);
  const ros = rosterOf(await catalogRow(env, pool.contest_id));
  const s = ((ros && ros[slot.division]) || []).find((x) => x.key === String(b.surfer || ''));
  if (!s) return json({ error: `This pick has to be one of the ${slot.division === 'men' ? 'men' : 'women'} in the roster.` }, 400);
  if (s.out) return json({ error: s.name + ' has already been eliminated from this contest.' }, 409);
  if (await env.DB.prepare('SELECT 1 AS x FROM draft_picks WHERE pool_id = ? AND surfer = ?').bind(pid, s.key).first()) return json({ error: s.name + ' is already taken.' }, 409);
  const ok = await commitPick(env, pid, pr, seq, u.id, slot, s.key, 0, rules);
  if (!ok) return json({ error: 'That pick did not go through. The board changed; try again.' }, 409);
  return json({ ok: true });
}
async function draftQueue(req, env, u) {
  await migrateDrafts(env);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const pid = parseInt(b.poolId, 10);
  if (!(await env.DB.prepare('SELECT 1 AS x FROM pool_members WHERE pool_id = ? AND user_id = ?').bind(pid, u.id).first())) return json({ error: 'Pool not found.' }, 404);
  const q = (Array.isArray(b.queue) ? b.queue : []).map(String).filter((k) => /^[a-z0-9-]{1,80}$/.test(k)).slice(0, 60);
  await env.DB.prepare('INSERT INTO draft_queue(pool_id, user_id, queue_json) VALUES (?, ?, ?) ON CONFLICT(pool_id, user_id) DO UPDATE SET queue_json = excluded.queue_json').bind(pid, u.id, JSON.stringify(q)).run();
  return json({ ok: true, queue: q });
}
async function poolRules(req, env, u) {
  await migrateDrafts(env);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const pid = parseInt(b.poolId, 10);
  const pool = await poolRow(env, pid);
  if (!pool || pool.owner_id !== u.id) return json({ error: 'Only the pool owner can change the rules.' }, 403);
  const pr = await env.DB.prepare('SELECT status FROM pool_rules WHERE pool_id = ?').bind(pid).first();
  if (pr && pr.status !== 'scheduled') return json({ error: 'The draft has started, so the rules are locked.' }, 409);
  const cat = await catalogRow(env, pool.contest_id);
  const cr = cleanRules(b.rules || {}, cat, pool.max_members);
  if (cr.error) return json({ error: cr.error }, 400);
  await env.DB.prepare("INSERT INTO pool_rules(pool_id, rules_json, draft_at, status) VALUES (?, ?, ?, 'scheduled') ON CONFLICT(pool_id) DO UPDATE SET rules_json = excluded.rules_json, draft_at = excluded.draft_at").bind(pid, JSON.stringify(cr.rules), cr.draftAt).run();
  return json({ ok: true });
}
async function draftStart(req, env, u) {
  await migrateDrafts(env);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const pid = parseInt(b.poolId, 10);
  const pool = await poolRow(env, pid);
  if (!pool || pool.owner_id !== u.id) return json({ error: 'Only the pool owner can start the draft.' }, 403);
  const ms = await members(env, pid);
  if (ms.length < 2) return json({ error: 'You need at least 2 teams to start.' }, 409);
  if (endMs(pool.end_date) < Date.now()) return json({ error: 'This contest has ended.' }, 409);
  const r = await env.DB.prepare("UPDATE pool_rules SET draft_at = ? WHERE pool_id = ? AND status = 'scheduled'").bind(Date.now(), pid).run();
  if (r.meta.changes !== 1) return json({ error: 'The draft already started.' }, 409);
  await tick(env, pid);
  return json({ ok: true });
}

// ---------- public drafts ----------
async function generalList(env, u) {
  await migrateDrafts(env);
  await syncCatalog(env, false);
  const now = Date.now();
  const { results } = await env.DB.prepare('SELECT g.*, c.name, c.location, c.start_date, c.end_date, (SELECT COUNT(*) FROM gentries e WHERE e.contest_id = g.contest_id) AS entries, (SELECT COUNT(*) FROM gentries e WHERE e.contest_id = g.contest_id AND e.locked_at IS NOT NULL) AS locked FROM gdrafts g JOIN catalog c ON c.contest_id = g.contest_id WHERE c.end_date >= ? ORDER BY g.opens_at').bind(new Date(now - 14 * DAY).toISOString().slice(0, 10)).all();
  const mine = u ? (await env.DB.prepare('SELECT contest_id, team_name, locked_at FROM gentries WHERE user_id = ?').bind(u.id).all()).results : [];
  return json({
    serverNow: now,
    drafts: results.map((g) => {
      const m = mine.find((x) => x.contest_id === g.contest_id);
      return { contestId: g.contest_id, name: g.name, location: g.location, start: g.start_date, end: g.end_date, opensAt: g.opens_at, closesAt: g.closes_at, status: gstatus(g, now), entries: g.entries, locked: g.locked, wildcard: now >= g.opens_at ? g.wildcard_rank : null, men: g.men, women: g.women, me: m ? { team: m.team_name, locked: !!m.locked_at } : null };
    })
  });
}
function gstatus(g, now) { return g.closed_reason ? 'closed' : now < g.opens_at ? 'upcoming' : now < g.closes_at ? 'open' : 'closed'; }
function nCr(n, k) { if (k > n) return 0; let r = 1; for (let i = 1; i <= k; i++) r = r * (n - k + i) / i; return Math.round(r); }
async function generalOne(env, u, cid) {
  await migrateDrafts(env);
  const g = await env.DB.prepare('SELECT * FROM gdrafts WHERE contest_id = ?').bind(String(cid || '')).first();
  if (!g) return json({ error: 'No public draft for that contest.' }, 404);
  const cat = await catalogRow(env, g.contest_id);
  const ros = rosterOf(cat) || { men: [], women: [] };
  const now = Date.now();
  const status = gstatus(g, now);
  const rows = (await env.DB.prepare('SELECT e.user_id, e.team_name, e.picks_json, e.locked_at, e.joined_at, u.username FROM gentries e JOIN users u ON u.id = e.user_id WHERE e.contest_id = ? ORDER BY COALESCE(e.locked_at, e.joined_at)').bind(g.contest_id).all()).results;
  const res = pj(cat.results_json, null);
  const divOf = {};
  ros.men.forEach((s) => divOf[s.key] = 'men'); ros.women.forEach((s) => divOf[s.key] = 'women');
  let winners = null;
  const locked = rows.filter((r) => r.locked_at);
  if (res && locked.length) {
    const teams = locked.map((r, i) => ({ team: r.team_name, user: r.username, tie: r.locked_at, s: scoreTeam(pj(r.picks_json, []), res, divOf) }));
    const overall = rankBy(teams, 'team');
    const wcIdx = Math.min(g.wildcard_rank, overall.length) - 1;
    const pickW = (cat2, label) => { const t = rankBy(teams, cat2)[0]; return { label, team: t.team, user: t.user }; };
    winners = [pickW('men', "Men's top finish"), pickW('women', "Women's top finish"), pickW('team', 'Overall team'), pickW('menTeam', "Men's team points"), pickW('womenTeam', "Women's team points"),
      { label: `Wild card (${ordinal(g.wildcard_rank)} place overall)`, team: overall[wcIdx].team, user: overall[wcIdx].user }];
    winners.overall = overall.map((t, i) => ({ rank: i + 1, team: t.team, user: t.user, points: t.s.total, men: t.s.men.pts, women: t.s.women.pts }));
  }
  const me = u ? rows.find((r) => r.user_id === u.id) : null;
  const reveal = status === 'closed';
  return json({
    serverNow: now,
    draft: { contestId: g.contest_id, name: cat.name, location: cat.location, start: cat.start_date, end: cat.end_date, opensAt: g.opens_at, closesAt: g.closes_at, status, men: g.men, women: g.women, wildcard: now >= g.opens_at ? g.wildcard_rank : null, combos: nCr(alive(ros.men).length, g.men) * nCr(alive(ros.women).length, g.women), note: cat.roster_note, source: cat.roster_source },
    rules: [
      `Free to play, no payout. Open to every signed-in user.`,
      `Sign up any time. Picks open 3 days before the contest and close at the end of day 2 (${new Date(g.closes_at).toUTCString().slice(0, 22)} UTC).`,
      `Pick ${g.men} men and ${g.women} women. Once you lock your team it cannot be changed.`,
      'No two teams can be exactly the same: your team has to differ from every locked team by at least one surfer.',
      'The draft also closes early if every possible team has been taken.',
      'Six winners: men\'s top finish, women\'s top finish, overall team points, men\'s team points, women\'s team points, and a wild card.',
      'The wild card place (somewhere in the top 10 overall) is drawn at random and announced when picks open.'
    ],
    roster: ros,
    entries: rows.map((r) => ({ team: r.team_name, user: r.username, locked: !!r.locked_at, mine: !!(u && r.user_id === u.id), picks: reveal || (u && r.user_id === u.id) ? pj(r.picks_json, []) : null })),
    me: me ? { team: me.team_name, locked: !!me.locked_at, picks: pj(me.picks_json, []) } : null,
    results: res, winners, overall: winners ? winners.overall : null
  });
}
function ordinal(n) { const s = ['th', 'st', 'nd', 'rd'], v = n % 100; return n + (s[(v - 20) % 10] || s[v] || s[0]); }
async function generalJoin(req, env, u) {
  await migrateDrafts(env);
  if (!u.admin_level && !u.is_admin && !(await toggle(env, 'publicDrafts'))) return json({ error: 'Public drafts are paused right now. Try again later.' }, 403);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const g = await env.DB.prepare('SELECT * FROM gdrafts WHERE contest_id = ?').bind(String(b.contestId || '')).first();
  if (!g) return json({ error: 'No public draft for that contest.' }, 404);
  if (gstatus(g, Date.now()) === 'closed') return json({ error: 'This draft is closed.' }, 409);
  const team = cleanText(b.teamName, 2, 30);
  if (!team) return json({ error: 'Team name must be 2-30 characters.' }, 400);
  try {
    await env.DB.prepare('INSERT INTO gentries(contest_id, user_id, team_name, joined_at) VALUES (?, ?, ?, ?)').bind(g.contest_id, u.id, team, Date.now()).run();
  } catch (e) {
    if (await env.DB.prepare('SELECT 1 AS x FROM gentries WHERE contest_id = ? AND user_id = ?').bind(g.contest_id, u.id).first()) return json({ error: 'You are already signed up.' }, 409);
    return json({ error: 'That team name is taken in this draft. Try another.' }, 409);
  }
  return json({ ok: true });
}
async function generalPick(req, env, u) {
  await migrateDrafts(env);
  if (!u.admin_level && !u.is_admin && !(await toggle(env, 'publicDrafts'))) return json({ error: 'Public drafts are paused right now. Try again later.' }, 403);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const g = await env.DB.prepare('SELECT * FROM gdrafts WHERE contest_id = ?').bind(String(b.contestId || '')).first();
  if (!g) return json({ error: 'No public draft for that contest.' }, 404);
  const st = gstatus(g, Date.now());
  if (st === 'upcoming') return json({ error: 'Picks open ' + new Date(g.opens_at).toUTCString().slice(0, 16) + '.' }, 409);
  if (st === 'closed') return json({ error: 'This draft is closed.' }, 409);
  const ros = rosterOf(await catalogRow(env, g.contest_id));
  const men = [...new Set((b.men || []).map(String))], women = [...new Set((b.women || []).map(String))];
  if (men.length !== g.men || women.length !== g.women) return json({ error: `Pick exactly ${g.men} different men and ${g.women} different women.` }, 400);
  if (!men.every((k) => alive(ros.men).some((s) => s.key === k)) || !women.every((k) => alive(ros.women).some((s) => s.key === k))) return json({ error: 'One of those surfers is not in this roster or has already been eliminated.' }, 400);
  const keys = [...men, ...women];
  const combo = [...keys].sort().join('|');
  let r;
  try {
    r = await env.DB.prepare('UPDATE gentries SET picks_json = ?, combo = ?, locked_at = ? WHERE contest_id = ? AND user_id = ? AND locked_at IS NULL').bind(JSON.stringify(keys), combo, Date.now(), g.contest_id, u.id).run();
  } catch (e) {
    return json({ error: 'Someone already locked that exact team. Change at least one surfer.' }, 409);
  }
  if (r.meta.changes !== 1) {
    const e = await env.DB.prepare('SELECT locked_at FROM gentries WHERE contest_id = ? AND user_id = ?').bind(g.contest_id, u.id).first();
    return json({ error: e ? 'Your team is already locked.' : 'Sign up for this draft first.' }, 409);
  }
  const total = nCr(alive(ros.men).length, g.men) * nCr(alive(ros.women).length, g.women);
  const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM gentries WHERE contest_id = ? AND locked_at IS NOT NULL').bind(g.contest_id).first();
  if (n.n >= total) await env.DB.prepare("UPDATE gdrafts SET closes_at = ?, closed_reason = 'All possible teams are taken.' WHERE contest_id = ?").bind(Date.now(), g.contest_id).run();
  return json({ ok: true });
}

// ---------- admin ----------
async function adminCatalog(env, u) {
  if (!u.is_admin) return json({ error: 'Admins only.' }, 403);
  await migrateDrafts(env);
  const st = await env.DB.prepare("SELECT v FROM app_state WHERE k = 'catalog_sync'").first();
  const { results } = await env.DB.prepare('SELECT contest_id, name, start_date, end_date, status, draftable, roster_json, roster_source, roster_note, conflicts_json, manual, (results_json IS NOT NULL) AS has_results FROM catalog ORDER BY start_date').all();
  return json({ lastSync: st ? parseInt(st.v, 10) : null, contests: results.map((c) => { const r = rosterOf(c); return { id: c.contest_id, name: c.name, start: c.start_date, end: c.end_date, status: c.status, draftable: !!c.draftable, men: r ? alive(r.men).length : 0, women: r ? alive(r.women).length : 0, out: r ? r.men.length + r.women.length - alive(r.men).length - alive(r.women).length : 0, source: c.roster_source, note: c.roster_note, conflicts: pj(c.conflicts_json, []), manual: !!c.manual, hasResults: !!c.has_results }; }) });
}
async function adminRoster(req, env, u) {
  if (!u.is_admin) return json({ error: 'Admins only.' }, 403);
  await migrateDrafts(env);
  const b = await readJson(req);
  if (!b) return json({ error: 'Bad request.' }, 400);
  const c = await catalogRow(env, b.contestId);
  if (!c) return json({ error: 'Contest not found.' }, 404);
  if (b.clear) {
    await env.DB.prepare('UPDATE catalog SET manual = 0 WHERE contest_id = ?').bind(c.contest_id).run();
    await syncCatalog(env, true);
    return json({ ok: true });
  }
  const R = { men: [], women: [] };
  const slug = (s) => s.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  for (const line of String(b.text || '').split(/\r?\n/).slice(0, 400)) {
    const parts = line.split(',').map((x) => x.trim());
    if (parts.length < 2 || !parts[0]) continue;
    const d = /^w/i.test(parts[parts.length - 1]) ? 'women' : /^m/i.test(parts[parts.length - 1]) ? 'men' : null;
    if (!d) continue;
    const name = parts[0].slice(0, 60);
    R[d].push({ key: slug(name), name, country: parts.length > 2 ? parts[1].slice(0, 30) : '', rank: R[d].length + 1 });
  }
  if (!R.men.length || !R.women.length) return json({ error: 'Add at least one man and one woman, one per line: Name, Country, M or W.' }, 400);
  await env.DB.prepare("UPDATE catalog SET roster_json = ?, roster_source = 'manual', roster_note = 'Roster entered by the site admin.', manual = 1, draftable = (status != 'finished') WHERE contest_id = ?").bind(JSON.stringify(R), c.contest_id).run();
  await env.DB.prepare('UPDATE contests SET pool_supported = 1 WHERE id = ?').bind(c.contest_id).run().catch(() => {});
  await ensureGeneral(env);
  return json({ ok: true, men: R.men.length, women: R.women.length });
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
   const mt=h('p','muted','');f.insertBefore(mt,f.children[[].indexOf.call(f.children,p2.parentNode)+1]);
   const chk=function(){const ok=pwOk(p.value);hint.textContent=(ok?'\u2713 Strong enough. ':'')+PWR;hint.style.color=p.value?(ok?'#5be3a0':'#ffb3c7'):'';
    const a=p.value,c=p2.value;if(!c){mt.textContent='';return}if(a===c){mt.textContent='\u2713 Passwords match';mt.style.color='#5be3a0'}else if(a.startsWith(c)){mt.textContent='Keep typing\u2026';mt.style.color=''}else{mt.textContent='\u2715 Passwords do not match yet';mt.style.color='#ffb3c7'}};p.oninput=chk;p2.oninput=chk}
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

// ---------- Admin levels, surfer profiles, site controls, bug reports (app-0.10) ----------
// Levels: 0 member, 1 editor (surfer profiles, claims, bug reports), 2 admin (everything except the admin team),
// 3 owner (the original account: the only one who can add or remove admins and editors; cannot be removed).
const LEVELS = { 0: 'Member', 1: 'Editor', 2: 'Admin', 3: 'Owner' };
const SITE_URL = SITE + '/isa-peru-fantasy-2026/';
const CLAIM_DAYS = 14;
const SOCIAL_KEYS = ['instagram', 'tiktok', 'youtube', 'x', 'facebook', 'website', 'wsl', 'isa', 'strava', 'linktree'];
const SOCIAL_HOSTS = {
  instagram: ['instagram.com'], tiktok: ['tiktok.com'], youtube: ['youtube.com', 'youtu.be'], x: ['x.com', 'twitter.com'],
  facebook: ['facebook.com', 'fb.com'], wsl: ['worldsurfleague.com'], isa: ['isasurf.org'], strava: ['strava.com'], linktree: ['linktr.ee'], website: null
};
const DEFAULT_SITE = {
  banner: { text: '', level: 'info', until: null },
  ticker: { text: '', on: false },
  toggles: { signups: true, poolCreate: true, publicDrafts: true, surferEdits: true, bugReports: true }
};
let adminMigrated = false;
let ownerSet = false;
async function migrateAdmin(env) {
  if (adminMigrated && ownerSet) return;
  if (adminMigrated) return ensureOwner(env);
  try { await env.DB.prepare('ALTER TABLE users ADD COLUMN admin_level INTEGER NOT NULL DEFAULT 0').run(); } catch (e) {}
  const S = [
    'CREATE TABLE IF NOT EXISTS app_state(k TEXT PRIMARY KEY, v TEXT)',
    'CREATE TABLE IF NOT EXISTS admin_log(id INTEGER PRIMARY KEY, at INTEGER NOT NULL, user_id INTEGER, username TEXT, action TEXT NOT NULL, detail TEXT)',
    "CREATE TABLE IF NOT EXISTS surfer_claims(id INTEGER PRIMARY KEY, surfer_key TEXT NOT NULL, surfer_name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, code TEXT NOT NULL, contact TEXT, created_by INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'sent', user_id INTEGER, proof_url TEXT, auto TEXT, note TEXT, decided_by INTEGER, decided_at INTEGER)",
    'CREATE TABLE IF NOT EXISTS surfer_links(surfer_key TEXT PRIMARY KEY, user_id INTEGER UNIQUE NOT NULL, verified_at INTEGER NOT NULL, claim_id INTEGER)',
    'CREATE TABLE IF NOT EXISTS surfer_profiles(surfer_key TEXT PRIMARY KEY, name TEXT, bio TEXT, links_json TEXT, photo TEXT, photo_at INTEGER, updated_at INTEGER, updated_by INTEGER, hidden INTEGER NOT NULL DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS profile_edits(id INTEGER PRIMARY KEY, surfer_key TEXT NOT NULL, at INTEGER NOT NULL, user_id INTEGER, username TEXT, before_json TEXT, after_json TEXT)',
    "CREATE TABLE IF NOT EXISTS bug_reports(id INTEGER PRIMARY KEY, at INTEGER NOT NULL, user_id INTEGER, username TEXT, page TEXT, text TEXT NOT NULL, ua TEXT, status TEXT NOT NULL DEFAULT 'open', admin_note TEXT, updated_at INTEGER)"
  ];
  for (const q of S) await env.DB.prepare(q).run();
  adminMigrated = true;
  return ensureOwner(env);
}
async function ensureOwner(env) {
  // the original account is the owner: the first admin ever created
  let own = await env.DB.prepare("SELECT v FROM app_state WHERE k = 'owner_id'").first();
  if (!own) {
    const first = await env.DB.prepare('SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1').first();
    if (first) {
      await env.DB.prepare("INSERT OR IGNORE INTO app_state(k, v) VALUES ('owner_id', ?)").bind(String(first.id)).run();
      own = { v: String(first.id) };
    }
  }
  if (own) {
    await env.DB.prepare('UPDATE users SET admin_level = 3, is_admin = 1 WHERE id = ?').bind(parseInt(own.v, 10)).run();
    await env.DB.prepare('UPDATE users SET admin_level = 2 WHERE is_admin = 1 AND admin_level < 2 AND id != ?').bind(parseInt(own.v, 10)).run();
    ownerSet = true;
  }
}
const lvl = (u) => (u ? Math.max(u.admin_level || 0, u.is_admin ? 2 : 0) : 0);
async function ownerId(env) {
  const r = await env.DB.prepare("SELECT v FROM app_state WHERE k = 'owner_id'").first();
  return r ? parseInt(r.v, 10) : null;
}
async function logA(env, u, action, detail) {
  await env.DB.prepare('INSERT INTO admin_log(at, user_id, username, action, detail) VALUES (?, ?, ?, ?, ?)')
    .bind(Date.now(), u ? u.id : null, u ? u.username : 'system', action, String(detail || '').slice(0, 500)).run();
}
async function siteSettings(env) {
  const r = await env.DB.prepare("SELECT v FROM app_state WHERE k = 'site'").first();
  const s = pj(r && r.v, {});
  return { banner: { ...DEFAULT_SITE.banner, ...(s.banner || {}) }, ticker: { ...DEFAULT_SITE.ticker, ...(s.ticker || {}) }, toggles: { ...DEFAULT_SITE.toggles, ...(s.toggles || {}) } };
}
async function toggle(env, k) {
  return (await siteSettings(env)).toggles[k] !== false;
}
async function notifyAdmins(env, subject, lines, hash, minLevel = 1) {
  if (!emailOn(env)) return false;
  const { results } = await env.DB.prepare('SELECT email FROM users WHERE disabled = 0 AND (admin_level >= ? OR is_admin = 1) AND email IS NOT NULL').bind(minLevel).all();
  const link = SITE_URL + '#admin' + (hash ? '/' + hash : '');
  const text = lines.join('\n') + '\n\nOpen it in the admin panel: ' + link;
  const html = lines.map((l) => '<p>' + escH(l) + '</p>').join('') + `<p><a href="${link}">Open it in the admin panel</a></p>`;
  for (const r of results) { try { await sendMail(env, r.email, subject, text, html); } catch (e) {} }
  return true;
}
function escH(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }
function skey(s) { return String(s || '').toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80); }
function cleanBio(v) {
  const s = String(v == null ? '' : v).replace(/[\u0000-\u0009\u000b-\u001f\u007f<>]/g, '').replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  return s.length <= 1500 ? s : null;
}
function cleanLinks(o) {
  const out = {};
  for (const k of SOCIAL_KEYS) {
    let v = String((o && o[k]) || '').trim();
    if (!v) continue;
    if (k === 'instagram' && /^@?[A-Za-z0-9._]{1,30}$/.test(v)) v = 'https://www.instagram.com/' + v.replace(/^@/, '') + '/';
    if (k === 'tiktok' && /^@?[A-Za-z0-9._]{1,30}$/.test(v)) v = 'https://www.tiktok.com/@' + v.replace(/^@/, '');
    if (k === 'x' && /^@?[A-Za-z0-9_]{1,15}$/.test(v)) v = 'https://x.com/' + v.replace(/^@/, '');
    if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
    const u = cleanUrl(v.replace(/^http:/i, 'https:'));
    if (!u) return { error: `The ${k} link is not a valid web address.` };
    const hosts = SOCIAL_HOSTS[k];
    const host = new URL(u).hostname.replace(/^www\.|^m\./, '');
    if (hosts && !hosts.some((h) => host === h || host.endsWith('.' + h))) return { error: `The ${k} link has to be on ${hosts[0]}.` };
    out[k] = u;
  }
  return { links: out };
}
function photoOk(p) {
  return typeof p === 'string' && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p) && p.length <= 700000;
}
async function claimByToken(env, t) {
  if (!t || !/^[0-9a-f]{48}$/.test(String(t))) return null;
  return env.DB.prepare('SELECT * FROM surfer_claims WHERE token_hash = ?').bind(await sha256(String(t))).first();
}
const claimOpen = (c) => c && ['sent', 'pending'].includes(c.status) && c.expires_at > Date.now();
// Best-effort automatic check: is the claim code visible at the proof link (a public post, profile or bio page)?
async function autoCheck(url, code) {
  if (!url) return 'no-link';
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    const tries = [url];
    const ig = /instagram\.com$/.test(host) && (new URL(url).pathname.split('/').filter(Boolean)[0] || '');
    if (ig && !['p', 'reel', 'stories', 'tv'].includes(ig)) tries.unshift('https://i.instagram.com/api/v1/users/web_profile_info/?username=' + encodeURIComponent(ig));
    for (const u of tries) {
      const r = await fetch(u, { headers: { 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36', 'x-ig-app-id': '936619743392459', accept: 'text/html,application/json' }, redirect: 'follow', cf: { cacheTtl: 0 } });
      if (!r.ok) continue;
      const body = (await r.text()).slice(0, 2000000);
      if (body.toUpperCase().includes(code.toUpperCase())) return 'found';
    }
    return 'not-found';
  } catch (e) {
    return 'error';
  }
}
async function linkOf(env, uid) {
  return env.DB.prepare('SELECT l.surfer_key, c.surfer_name FROM surfer_links l LEFT JOIN surfer_claims c ON c.id = l.claim_id WHERE l.user_id = ?').bind(uid).first();
}
async function profileRow(env, k) {
  return env.DB.prepare('SELECT * FROM surfer_profiles WHERE surfer_key = ?').bind(k).first();
}
function profileOut(p, verified) {
  return { key: p.surfer_key, name: p.name || '', bio: p.bio || '', links: pj(p.links_json, {}), photo: p.photo ? `/api/surfers/photo?k=${encodeURIComponent(p.surfer_key)}&v=${p.photo_at || 0}` : null, updatedAt: p.updated_at, verified: !!verified };
}
async function saveProfile(env, u, k, name, b) {
  const old = await profileRow(env, k);
  const bio = b.bio === undefined ? (old ? old.bio : '') : cleanBio(b.bio);
  if (bio === null) return { error: 'The bio can be up to 1,500 characters.' };
  let links = old ? pj(old.links_json, {}) : {};
  if (b.links !== undefined) { const L = cleanLinks(b.links); if (L.error) return L; links = L.links; }
  let photo = old ? old.photo : null, photoAt = old ? old.photo_at : null;
  if (b.photo === null) { photo = null; photoAt = null; }
  else if (b.photo && b.photo !== 'keep') { if (!photoOk(b.photo)) return { error: 'The photo has to be a JPEG, PNG or WebP under about 500 KB.' }; photo = b.photo; photoAt = Date.now(); }
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO surfer_profiles(surfer_key, name, bio, links_json, photo, photo_at, updated_at, updated_by, hidden) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
     ON CONFLICT(surfer_key) DO UPDATE SET name = excluded.name, bio = excluded.bio, links_json = excluded.links_json, photo = excluded.photo, photo_at = excluded.photo_at, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
    .bind(k, name || (old && old.name) || '', bio, JSON.stringify(links), photo, photoAt, now, u.id).run();
  const snap = (p) => p ? { bio: p.bio || '', links: pj(p.links_json, {}), photo: !!p.photo, photo_at: p.photo_at || null } : null;
  await env.DB.prepare('INSERT INTO profile_edits(surfer_key, at, user_id, username, before_json, after_json) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(k, now, u.id, u.username, JSON.stringify(snap(old)), JSON.stringify({ bio, links, photo: !!photo, photo_at: photoAt })).run();
  return { ok: true };
}

async function adminRoutes(request, env, url, path, ip) {
  if (!path.startsWith('/api/site') && !path.startsWith('/api/surfer') && !path.startsWith('/api/claim') && !path.startsWith('/api/bugs') && !path.startsWith('/api/admin/') && path !== '/api/me') return null;
  await migrateAdmin(env);
  const G = request.method === 'GET', P = request.method === 'POST';
  // ----- public -----
  if (G && path === '/api/site') return json(await siteSettings(env), 200, { 'cache-control': 'public, max-age=30' });
  if (G && path === '/api/surfers/profiles') {
    const { results } = await env.DB.prepare('SELECT p.*, (SELECT 1 FROM surfer_links l WHERE l.surfer_key = p.surfer_key) AS v FROM surfer_profiles p WHERE p.hidden = 0').all();
    const out = {};
    for (const p of results) out[p.surfer_key] = profileOut(p, p.v);
    const { results: L } = await env.DB.prepare('SELECT surfer_key FROM surfer_links').all();
    for (const l of L) if (!out[l.surfer_key]) out[l.surfer_key] = { key: l.surfer_key, verified: true, links: {}, bio: '', photo: null };
    return json({ profiles: out }, 200, { 'cache-control': 'public, max-age=60' });
  }
  if (G && path === '/api/surfers/photo') {
    const p = await env.DB.prepare('SELECT photo FROM surfer_profiles WHERE surfer_key = ? AND hidden = 0').bind(String(url.searchParams.get('k') || '')).first();
    const m = p && p.photo && /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/.exec(p.photo);
    if (!m) return new Response('Not found', { status: 404 });
    return new Response(unb64(m[2]), { headers: { 'content-type': m[1], 'cache-control': 'public, max-age=86400', 'access-control-allow-origin': '*', 'x-content-type-options': 'nosniff' } });
  }
  if (P && path === '/api/bugs') {
    if (!(await toggle(env, 'bugReports'))) return json({ error: 'Problem reports are turned off right now.' }, 403);
    const b = await readJson(request);
    const text = b && cleanBio(b.text);
    if (!text || text.length < 5) return json({ error: 'Tell us a little about what went wrong (at least 5 characters).' }, 400);
    if (await isLimited(env, ['bug:' + ip])) return json({ error: 'Too many reports from here. Try again later.' }, 429);
    await addFailure(env, ['bug:' + ip]);
    const u = await currentUser(request, env);
    const r = await env.DB.prepare('INSERT INTO bug_reports(at, user_id, username, page, text, ua) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(Date.now(), u ? u.id : null, u ? u.username : null, String(b.page || '').slice(0, 200), text, String(request.headers.get('user-agent') || '').slice(0, 200)).run();
    await notifyAdmins(env, 'New problem report on Surf Fantasy Leagues', ['From: ' + (u ? u.username : 'a visitor'), 'Page: ' + String(b.page || '').slice(0, 200), text.slice(0, 600)], 'bugs/' + (r.meta && r.meta.last_row_id));
    return json({ ok: true });
  }
  if (G && path === '/api/claim') {
    const c = await claimByToken(env, url.searchParams.get('t'));
    if (!c) return json({ error: 'This claim link is not valid. Ask the site admin for a new one.' }, 404);
    const u = await currentUser(request, env);
    const mine = u && c.user_id === u.id;
    const expired = c.expires_at < Date.now() && ['sent', 'pending'].includes(c.status);
    return json({ claim: { surfer: c.surfer_name, key: c.surfer_key, status: expired ? 'expired' : c.status, expiresAt: c.expires_at, code: c.code, mine: !!mine, taken: !!c.user_id && !mine, proofUrl: mine ? c.proof_url : null, auto: mine ? c.auto : null } });
  }
  // ----- /api/me (adds level and the linked surfer) -----
  if (G && path === '/api/me') {
    const u = await currentUser(request, env);
    if (!u) return json({ user: null });
    const l = await linkOf(env, u.id);
    const L = lvl(u);
    return json({ user: { username: u.username, admin: L >= 2, level: L, levelName: LEVELS[L], owner: L === 3, email: u.email, phone: u.phone, emailVerified: !!u.email_verified, phoneVerified: !!u.phone_verified, surfer: l ? { key: l.surfer_key, name: l.surfer_name } : null } });
  }
  const u = await currentUser(request, env);
  if (!u) return json({ error: 'Please log in.' }, 401);
  const L = lvl(u);
  const b = P ? await readJson(request.clone()) : null;
  if (P && !b) return json({ error: 'Bad request.' }, 400);
  // ----- surfer claims (the surfer's side) -----
  if (P && path === '/api/claim/accept') {
    const c = await claimByToken(env, b.t);
    if (!claimOpen(c)) return json({ error: 'This claim link has expired or was already used. Ask the site admin for a new one.' }, 409);
    if (c.user_id && c.user_id !== u.id) return json({ error: 'Another account already started this claim.' }, 409);
    if (await env.DB.prepare('SELECT 1 AS x FROM surfer_links WHERE user_id = ? AND surfer_key != ?').bind(u.id, c.surfer_key).first()) return json({ error: 'This account is already verified as a different surfer.' }, 409);
    const proof = cleanUrl(String(b.proofUrl || '').trim().replace(/^http:/i, 'https:')) || '';
    if (!proof) return json({ error: 'Paste the https link to the post or profile where you put the code.' }, 400);
    const auto = await autoCheck(proof, c.code);
    await env.DB.prepare("UPDATE surfer_claims SET user_id = ?, proof_url = ?, auto = ?, status = 'pending' WHERE id = ?").bind(u.id, proof, auto, c.id).run();
    await logA(env, u, 'claim.submitted', `${c.surfer_name}: ${proof} (auto check: ${auto})`);
    await notifyAdmins(env, `Surfer claim to review: ${c.surfer_name}`, [`${u.username} says they are ${c.surfer_name}.`, `Proof link: ${proof}`, `Code to look for: ${c.code}`, `Automatic check: ${auto === 'found' ? 'code found on the page' : auto === 'not-found' ? 'code not found (the site may hide it from robots, so check by hand)' : 'could not read the page, check by hand'}`], 'claims/' + c.id);
    return json({ ok: true, auto });
  }
  // ----- profile editing (verified surfer for their own profile, editors and up for any) -----
  if (G && path === '/api/surfer/mine') {
    const k = String(url.searchParams.get('k') || '');
    const l = await linkOf(env, u.id);
    const key = k && L >= 1 ? k : l && l.surfer_key;
    if (!key) return json({ error: 'Your account is not linked to a surfer profile yet.' }, 404);
    const p = await profileRow(env, key);
    const ver = await env.DB.prepare('SELECT 1 AS x FROM surfer_links WHERE surfer_key = ?').bind(key).first();
    return json({ profile: p ? profileOut(p, ver) : { key, name: l && l.surfer_key === key ? l.surfer_name : '', bio: '', links: {}, photo: null, verified: !!ver }, canEdit: true, socialKeys: SOCIAL_KEYS });
  }
  if (P && path === '/api/surfer/profile') {
    const l = await linkOf(env, u.id);
    const k = skey(b.key || (l && l.surfer_key));
    if (!k) return json({ error: 'Pick a surfer.' }, 400);
    const own = l && l.surfer_key === k;
    if (!own && L < 1) return json({ error: 'You can only edit your own verified profile.' }, 403);
    if (own && L < 1 && !(await toggle(env, 'surferEdits'))) return json({ error: 'Profile editing is paused right now. Try again later.' }, 403);
    const name = cleanText(b.name || (l && l.surfer_name) || '', 0, 80) || '';
    const r = await saveProfile(env, u, k, name, b);
    if (r.error) return json(r, 400);
    await logA(env, u, own ? 'profile.self-edit' : 'profile.admin-edit', k);
    if (own && L < 1) await notifyAdmins(env, `${name || k} updated their surfer profile`, [`${u.username} (verified as ${name || k}) changed their profile. It is live now; you can undo it from the admin panel.`], 'profiles/' + k);
    return json({ ok: true });
  }
  // ----- admin panel (editor and up) -----
  if (!path.startsWith('/api/admin/')) return null;
  if (L < 1) return json({ error: 'Admins only.' }, 403);
  const need = (n) => L >= n ? null : json({ error: n >= 3 ? 'Only the original owner account can do that.' : 'You need the Admin level for that.' }, 403);
  if (G && path === '/api/admin/overview') {
    const q = async (s, ...a) => (await env.DB.prepare(s).bind(...a).first()).n;
    const st = await env.DB.prepare("SELECT v FROM app_state WHERE k = 'catalog_sync'").first();
    return json({
      me: { username: u.username, level: L, levelName: LEVELS[L] }, version: APP_VERSION, email: emailOn(env), lastSync: st ? parseInt(st.v, 10) : null,
      counts: {
        users: await q('SELECT COUNT(*) AS n FROM users'), maxUsers: parseInt(env.MAX_USERS, 10) || 10,
        pools: await q('SELECT COUNT(*) AS n FROM pools WHERE cancelled_at IS NULL'),
        claimsPending: await q("SELECT COUNT(*) AS n FROM surfer_claims WHERE status = 'pending'"),
        verified: await q('SELECT COUNT(*) AS n FROM surfer_links'),
        bugsOpen: await q("SELECT COUNT(*) AS n FROM bug_reports WHERE status = 'open'"),
        profiles: await q('SELECT COUNT(*) AS n FROM surfer_profiles')
      },
      site: await siteSettings(env), levels: LEVELS
    });
  }
  if (G && path === '/api/admin/claims') {
    const { results } = await env.DB.prepare('SELECT c.id, c.surfer_key, c.surfer_name, c.code, c.contact, c.created_at, c.expires_at, c.status, c.proof_url, c.auto, c.note, c.decided_at, u.username AS user, a.username AS by FROM surfer_claims c LEFT JOIN users u ON u.id = c.user_id LEFT JOIN users a ON a.id = c.created_by ORDER BY (c.status = \'pending\') DESC, c.id DESC LIMIT 100').all();
    const { results: V } = await env.DB.prepare('SELECT l.surfer_key, l.verified_at, u.username FROM surfer_links l JOIN users u ON u.id = l.user_id ORDER BY l.verified_at DESC').all();
    return json({ claims: results.map((c) => ({ ...c, expired: ['sent', 'pending'].includes(c.status) && c.expires_at < Date.now() })), verified: V });
  }
  if (P && path === '/api/admin/claims/create') {
    const name = cleanText(b.surferName, 2, 80);
    const k = skey(b.surferKey || name);
    if (!name || !k) return json({ error: 'Pick the surfer.' }, 400);
    const contact = String(b.contact || '').trim().slice(0, 120);
    const t = rand(24), code = 'SFL-' + makeCode(5);
    const now = Date.now();
    const r = await env.DB.prepare('INSERT INTO surfer_claims(surfer_key, surfer_name, token_hash, code, contact, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(k, name, await sha256(t), code, contact, u.id, now, now + CLAIM_DAYS * 86400000).run();
    const link = SITE_URL + '#claim/' + t;
    let emailed = false;
    const em = normEmail(contact);
    if (b.sendEmail && em && emailOn(env)) {
      emailed = await sendMail(env, em, `Claim your surfer profile on Surf Fantasy Leagues`,
        `Hi ${name},\n\nSurf Fantasy Leagues would like you to manage your own surfer profile: your photo, bio and social links.\n\nOpen this private link (it works for ${CLAIM_DAYS} days):\n${link}\n\nTo confirm it is really you, we will ask you to post the code ${code} on one of your public social accounts for a moment.\n\nThis does not enter you in any fantasy draft.`,
        `<p>Hi ${escH(name)},</p><p>Surf Fantasy Leagues would like you to manage your own surfer profile: your photo, bio and social links.</p><p><a href="${link}">Open your private claim link</a> (it works for ${CLAIM_DAYS} days).</p><p>To confirm it is really you, we will ask you to post the code <b>${code}</b> on one of your public social accounts for a moment.</p><p>This does not enter you in any fantasy draft.</p>`);
    }
    await logA(env, u, 'claim.created', `${name} (${k})${contact ? ' for ' + contact : ''}${emailed ? ', emailed' : ''}`);
    return json({ ok: true, id: r.meta && r.meta.last_row_id, link, code, emailed, emailOn: emailOn(env) });
  }
  if (P && path === '/api/admin/claims/decide') {
    const c = await env.DB.prepare('SELECT * FROM surfer_claims WHERE id = ?').bind(parseInt(b.id, 10)).first();
    if (!c) return json({ error: 'Claim not found.' }, 404);
    const note = cleanText(b.note || '', 0, 300) || '';
    if (b.action === 'revoke') {
      await env.DB.prepare("UPDATE surfer_claims SET status = 'revoked', note = ?, decided_by = ?, decided_at = ? WHERE id = ?").bind(note, u.id, Date.now(), c.id).run();
      await env.DB.prepare('DELETE FROM surfer_links WHERE claim_id = ?').bind(c.id).run();
      await logA(env, u, 'claim.revoked', c.surfer_name);
      return json({ ok: true });
    }
    if (c.status !== 'pending' || !c.user_id) return json({ error: 'Only claims waiting for review can be approved or turned down.' }, 409);
    if (b.action === 'approve') {
      const other = await env.DB.prepare('SELECT user_id FROM surfer_links WHERE surfer_key = ?').bind(c.surfer_key).first();
      if (other && other.user_id !== c.user_id) return json({ error: 'Another account is already verified for this surfer. Revoke that one first.' }, 409);
      await env.DB.prepare('DELETE FROM surfer_links WHERE user_id = ?').bind(c.user_id).run();
      await env.DB.prepare('INSERT OR REPLACE INTO surfer_links(surfer_key, user_id, verified_at, claim_id) VALUES (?, ?, ?, ?)').bind(c.surfer_key, c.user_id, Date.now(), c.id).run();
      await env.DB.prepare("UPDATE surfer_claims SET status = 'approved', note = ?, decided_by = ?, decided_at = ? WHERE id = ?").bind(note, u.id, Date.now(), c.id).run();
      if (!(await profileRow(env, c.surfer_key))) await env.DB.prepare('INSERT INTO surfer_profiles(surfer_key, name, bio, links_json, updated_at, updated_by) VALUES (?, ?, \'\', \'{}\', ?, ?)').bind(c.surfer_key, c.surfer_name, Date.now(), u.id).run();
      const su = await env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(c.user_id).first();
      if (su && su.email && emailOn(env)) await sendMail(env, su.email, 'Your surfer profile is verified', `You are verified as ${c.surfer_name}. You can now add your photo, bio and social links: ${SITE_URL}#myprofile`, `<p>You are verified as <b>${escH(c.surfer_name)}</b>.</p><p><a href="${SITE_URL}#myprofile">Add your photo, bio and social links</a></p>`);
      await logA(env, u, 'claim.approved', c.surfer_name);
      return json({ ok: true });
    }
    if (b.action === 'reject') {
      await env.DB.prepare("UPDATE surfer_claims SET status = 'rejected', note = ?, decided_by = ?, decided_at = ? WHERE id = ?").bind(note, u.id, Date.now(), c.id).run();
      await logA(env, u, 'claim.rejected', `${c.surfer_name}${note ? ': ' + note : ''}`);
      return json({ ok: true });
    }
    if (b.action === 'recheck') {
      const auto = await autoCheck(c.proof_url, c.code);
      await env.DB.prepare('UPDATE surfer_claims SET auto = ? WHERE id = ?').bind(auto, c.id).run();
      return json({ ok: true, auto });
    }
    return json({ error: 'Unknown action.' }, 400);
  }
  if (G && path === '/api/admin/profiles') {
    const { results } = await env.DB.prepare('SELECT p.surfer_key, p.name, p.updated_at, p.hidden, (p.photo IS NOT NULL) AS has_photo, length(p.bio) AS bio_len, u.username AS by, (SELECT 1 FROM surfer_links l WHERE l.surfer_key = p.surfer_key) AS verified FROM surfer_profiles p LEFT JOIN users u ON u.id = p.updated_by ORDER BY p.updated_at DESC LIMIT 200').all();
    const k = url.searchParams.get('k');
    const edits = k ? (await env.DB.prepare('SELECT id, at, username, before_json, after_json FROM profile_edits WHERE surfer_key = ? ORDER BY id DESC LIMIT 30').bind(k).all()).results : [];
    return json({ profiles: results, edits });
  }
  if (P && path === '/api/admin/profiles/action') {
    const k = skey(b.key);
    const p = await profileRow(env, k);
    if (!p) return json({ error: 'Profile not found.' }, 404);
    if (b.action === 'hide' || b.action === 'show') {
      await env.DB.prepare('UPDATE surfer_profiles SET hidden = ? WHERE surfer_key = ?').bind(b.action === 'hide' ? 1 : 0, k).run();
      await logA(env, u, 'profile.' + b.action, k);
      return json({ ok: true });
    }
    if (b.action === 'undo') {
      const e = await env.DB.prepare('SELECT * FROM profile_edits WHERE id = ? AND surfer_key = ?').bind(parseInt(b.editId, 10), k).first();
      if (!e) return json({ error: 'Edit not found.' }, 404);
      const before = pj(e.before_json, null) || { bio: '', links: {}, photo: false };
      const r = await saveProfile(env, u, k, p.name, { bio: before.bio, links: before.links, photo: before.photo ? 'keep' : null });
      if (r.error) return json(r, 400);
      await logA(env, u, 'profile.undo', `${k} edit #${e.id}`);
      return json({ ok: true, note: before.photo && !p.photo ? 'Text and links restored; the earlier photo is no longer stored.' : '' });
    }
    return json({ error: 'Unknown action.' }, 400);
  }
  if (G && path === '/api/admin/bugs') {
    const { results } = await env.DB.prepare("SELECT * FROM bug_reports ORDER BY (status = 'open') DESC, id DESC LIMIT 200").all();
    return json({ bugs: results });
  }
  if (P && path === '/api/admin/bugs/update') {
    const st = ['open', 'working', 'fixed', 'wontfix'].includes(b.status) ? b.status : null;
    if (!st) return json({ error: 'Pick a status.' }, 400);
    await env.DB.prepare('UPDATE bug_reports SET status = ?, admin_note = ?, updated_at = ? WHERE id = ?').bind(st, cleanText(b.note || '', 0, 300) || '', Date.now(), parseInt(b.id, 10)).run();
    await logA(env, u, 'bug.' + st, '#' + b.id);
    return json({ ok: true });
  }
  // ----- Admin level and up -----
  if (P && path === '/api/admin/site') {
    const n = need(2); if (n) return n;
    const cur = await siteSettings(env);
    const bt = b.banner ? cleanText(b.banner.text || '', 0, 240) : cur.banner.text;
    if (bt === null) return json({ error: 'The banner message can be up to 240 characters.' }, 400);
    const tt = b.ticker ? cleanText(b.ticker.text || '', 0, 200) : cur.ticker.text;
    if (tt === null) return json({ error: 'The ticker message can be up to 200 characters.' }, 400);
    const until = b.banner && b.banner.hours ? Date.now() + Math.min(720, Math.max(1, parseInt(b.banner.hours, 10) || 0)) * 3600000 : b.banner ? null : cur.banner.until;
    const next = {
      banner: { text: bt || '', level: b.banner && ['info', 'warn', 'live'].includes(b.banner.level) ? b.banner.level : cur.banner.level, until },
      ticker: { text: tt || '', on: b.ticker ? !!b.ticker.on && !!tt : cur.ticker.on },
      toggles: { ...cur.toggles }
    };
    for (const k of Object.keys(DEFAULT_SITE.toggles)) if (b.toggles && typeof b.toggles[k] === 'boolean') next.toggles[k] = b.toggles[k];
    await env.DB.prepare("INSERT INTO app_state(k, v) VALUES ('site', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(JSON.stringify(next)).run();
    await logA(env, u, 'site.controls', JSON.stringify(next).slice(0, 400));
    return json({ ok: true, site: next });
  }
  if (G && path === '/api/admin/users') {
    const n = need(2); if (n) return n;
    const { results } = await env.DB.prepare('SELECT u.id, u.username, u.email, u.created_at, u.disabled, u.admin_level, u.is_admin, l.surfer_key FROM users u LEFT JOIN surfer_links l ON l.user_id = u.id ORDER BY u.id').all();
    const own = await ownerId(env);
    return json({ users: results.map((x) => ({ username: x.username, email: L >= 3 ? x.email : x.email ? x.email.replace(/^(.).*(@.*)$/, '$1***$2') : '', created: x.created_at, disabled: !!x.disabled, level: x.id === own ? 3 : Math.max(x.admin_level || 0, x.is_admin ? 2 : 0), owner: x.id === own, surfer: x.surfer_key })), canManageTeam: L >= 3 });
  }
  if (P && path === '/api/admin/users/disable') {
    const n = need(2); if (n) return n;
    const t = await env.DB.prepare('SELECT id, admin_level, is_admin FROM users WHERE lower(username) = lower(?)').bind(String(b.username || '')).first();
    if (!t) return json({ error: 'No account with that username.' }, 404);
    if (t.id === await ownerId(env)) return json({ error: 'The owner account cannot be turned off.' }, 403);
    if (t.id === u.id) return json({ error: 'You cannot turn off your own account here.' }, 403);
    if (Math.max(t.admin_level || 0, t.is_admin ? 2 : 0) >= 1 && L < 3) return json({ error: 'Only the owner can turn off another admin or editor.' }, 403);
    await env.DB.prepare('UPDATE users SET disabled = ? WHERE id = ?').bind(b.disabled ? 1 : 0, t.id).run();
    if (b.disabled) await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(t.id).run();
    await logA(env, u, b.disabled ? 'user.disabled' : 'user.enabled', b.username);
    return json({ ok: true });
  }
  if (G && path === '/api/admin/log') {
    const n = need(2); if (n) return n;
    const { results } = await env.DB.prepare('SELECT at, username, action, detail FROM admin_log ORDER BY id DESC LIMIT 200').all();
    return json({ log: results });
  }
  // ----- Owner only: the admin team -----
  if (P && path === '/api/admin/team') {
    const n = need(3); if (n) return n;
    const level = parseInt(b.level, 10);
    if (![0, 1, 2].includes(level)) return json({ error: 'Pick Member, Editor or Admin.' }, 400);
    const t = await env.DB.prepare('SELECT id, username, disabled FROM users WHERE lower(username) = lower(?)').bind(String(b.username || '').trim()).first();
    if (!t) return json({ error: 'No account with that username. They need to create an account first.' }, 404);
    if (t.id === await ownerId(env)) return json({ error: 'The owner account always keeps full access.' }, 403);
    await env.DB.prepare('UPDATE users SET admin_level = ?, is_admin = ? WHERE id = ?').bind(level, level >= 2 ? 1 : 0, t.id).run();
    await logA(env, u, 'team.level', `${t.username} -> ${LEVELS[level]}`);
    return json({ ok: true, username: t.username, level, levelName: LEVELS[level] });
  }
  return null;
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
  },
  async scheduled(event, env, ctx) {
    if (env.DB) ctx.waitUntil(cronTick(env));
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
      await migrateAdmin(env);
      const ar = await adminRoutes(request, env, url, path, ip);
      if (ar) return ar;
      if (request.method === 'GET') {
        if (path === '/') return new Response(null, { status: 302, headers: { location: SITE + '/isa-peru-fantasy-2026/#account', 'cache-control': 'no-store' } });
        if (path === '/classic') return page();
        if (path === '/api/config') {
          const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM contests').first();
          const u = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
          return json({ appName: 'Surf Pools', contests: c.n, firstRun: u.n === 0, emailReset: emailOn(env), passwordRule: PW_RULE });
        }
        if (path === '/api/contests') return await contestsList(env);
        if (path === '/api/general') return await generalList(env, await currentUser(request, env));
        if (path === '/api/general/one') return await generalOne(env, await currentUser(request, env), url.searchParams.get('id'));
        if (path === '/api/draft' || path === '/api/pools/preview' || path === '/api/admin/catalog') {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          if (path === '/api/draft') return await draftState(env, u, url.searchParams.get('id'));
          if (path === '/api/pools/preview') return await poolPreview(env, url.searchParams.get('code'));
          return await adminCatalog(env, u);
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
        if (path.startsWith('/api/draft/') || path.startsWith('/api/general/') || path.startsWith('/api/admin/')) {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          if (path === '/api/draft/pick') return await draftPick(request, env, u);
          if (path === '/api/draft/queue') return await draftQueue(request, env, u);
          if (path === '/api/draft/start') return await draftStart(request, env, u);
          if (path === '/api/general/join') return await generalJoin(request, env, u);
          if (path === '/api/general/pick') return await generalPick(request, env, u);
          if (path === '/api/admin/roster') return await adminRoster(request, env, u);
          if (path === '/api/admin/sync') { if (!u.is_admin) return json({ error: 'Admins only.' }, 403); return json(await syncCatalog(env, true)); }
        }
        if (path.startsWith('/api/pools/')) {
          const u = await currentUser(request, env);
          if (!u) return json({ error: 'Please log in.' }, 401);
          if (path === '/api/pools/create') return await poolCreate2(request, env, u);
          if (path === '/api/pools/join') return await poolJoin2(request, env, u);
          if (path === '/api/pools/rules') return await poolRules(request, env, u);
          if (path === '/api/pools/leave') return await poolLeave(request, env, u);
          if (path === '/api/pools/joining') return await poolJoining(request, env, u);
        }
      }
    } catch (e) {
      console.error('server error', path, String(e && e.stack || e));
      return json({ error: 'Something went wrong on the server. Please try again.' }, 500);
    }
    return json({ error: 'Not found' }, 404);
  }
};


