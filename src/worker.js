/*
  মুহাসিব — Cloudflare Workers সংস্করণ (D1 ডাটাবেসসহ)
  কাজ: রেজিস্ট্রেশন + অ্যাডমিন অনুমোদন, অ্যাপ কেবল অনুমোদিতদের কাছে পাঠানো, ডেটা সিঙ্ক / ব্যাকআপ / রিকভারি।
*/
const SESSION_DAYS = 90, MAX_USER_CHARS = 25 * 1024 * 1024, CHUNK = 500000;
const KEY_RE = /^(hisab-(v1|debt-v1|sv-v1|sg-v1|nf|budget)(@[A-Za-z0-9_-]+)?|hisab-profile|hisab-accts|idb:notes)$/;
const PUBLIC_FILES = new Set(['/login.html', '/sw.js', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png']);
const enc = new TextEncoder();

/* ---------- ক্রিপ্টো (Web Crypto) ---------- */
const b2h = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
const h2b = hex => new Uint8Array(hex.match(/../g).map(x => parseInt(x, 16)));
const sha = async s => b2h(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const rnd = n => b2h(crypto.getRandomValues(new Uint8Array(n)));
async function pbkdf2(pw, saltHex, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(String(pw)), 'PBKDF2', false, ['deriveBits']);
  return b2h(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: h2b(saltHex), iterations: iter }, key, 256));
}
function same(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
const iterOf = env => Math.min(100000, Math.max(10000, parseInt(env.PBKDF2_ITER) || 60000));
async function checkPw(pw, u, env) {
  const h = await pbkdf2(pw, u ? u.salt : '00'.repeat(16), u ? u.iter : iterOf(env));
  return !!u && same(h, u.hash);
}

/* ---------- হেল্পার ---------- */
function normIdent(raw) {
  let s = String(raw || '').trim().replace(/[০-৯]/g, d => '০১২৩৪৫৬৭৮৯'.indexOf(d));
  if (!s) return null;
  if (s.includes('@')) { s = s.toLowerCase(); return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 120 ? { type: 'email', id: s } : null; }
  let p = s.replace(/[\s\-()]/g, '');
  if (p.startsWith('+88')) p = p.slice(3); else if (p.startsWith('88') && p.length === 13) p = p.slice(2);
  if (/^01\d{9}$/.test(p)) return { type: 'phone', id: p };
  if (/^\+?\d{8,15}$/.test(p)) return { type: 'phone', id: p };
  return null;
}
const jsonSafe = o => JSON.stringify(o).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' };
function reply(body, code, headers) {
  const isObj = typeof body === 'object' && body !== null;
  return new Response(isObj ? JSON.stringify(body) : body, {
    status: code || 200,
    headers: Object.assign({ 'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }, SEC, headers || {})
  });
}
const parseCookies = h => Object.fromEntries(String(h || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]).map(a => [a[0], a.slice(1).join('=')]));
const cookie = (url, token, maxAge) => `mh_s=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${url.protocol === 'https:' ? '; Secure' : ''}`;
const ipOf = req => String(req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || '').split(',')[0].trim();
const pub = u => ({ uid: u.uid, ident: u.ident, type: u.type, name: u.name, role: u.role, status: u.status });

async function limited(db, key, max, win) {
  const now = Date.now();
  const r = await db.prepare('SELECT c, reset FROM rl WHERE k=?').bind(key).first();
  if (!r || r.reset < now) { await db.prepare('INSERT OR REPLACE INTO rl(k,c,reset) VALUES(?,?,?)').bind(key, 1, now + win).run(); return false; }
  await db.prepare('UPDATE rl SET c=c+1 WHERE k=?').bind(key).run();
  return r.c + 1 > max;
}

/* ---------- অ্যাডমিন তৈরি/আপডেট (ADMIN_ID, ADMIN_PASSWORD সিক্রেট থেকে) ---------- */
let adminChecked = '';
async function ensureAdmin(env) {
  if (!env.ADMIN_ID || !env.ADMIN_PASSWORD) return;
  const iter = iterOf(env), fp = await sha(env.ADMIN_ID + '|' + env.ADMIN_PASSWORD + '|' + iter);
  if (adminChecked === fp) return;
  const db = env.DB, m = await db.prepare("SELECT v FROM meta WHERE k='admin_fp'").first();
  if (m && m.v === fp) { adminChecked = fp; return; }
  let idn = normIdent(env.ADMIN_ID) || { type: 'email', id: String(env.ADMIN_ID).toLowerCase() };
  const salt = rnd(16), hash = await pbkdf2(env.ADMIN_PASSWORD, salt, iter), now = Date.now();
  const u = await db.prepare('SELECT uid FROM users WHERE ident=?').bind(idn.id).first();
  if (!u) {
    await db.prepare("INSERT INTO users(uid,ident,type,name,salt,hash,iter,role,status,created_at,approved_at) VALUES(?,?,?,?,?,?,?, 'admin','approved',?,?)")
      .bind(rnd(9), idn.id, idn.type, env.ADMIN_NAME || 'অ্যাডমিন', salt, hash, iter, now, now).run();
  } else {
    await db.batch([
      db.prepare("UPDATE users SET salt=?,hash=?,iter=?,role='admin',status='approved' WHERE uid=?").bind(salt, hash, iter, u.uid),
      db.prepare('DELETE FROM sessions WHERE uid=?').bind(u.uid)
    ]);
  }
  await db.prepare("INSERT OR REPLACE INTO meta(k,v) VALUES('admin_fp',?)").bind(fp).run();
  adminChecked = fp;
}

/* ---------- সেশন ---------- */
async function auth(req, env) {
  const t = parseCookies(req.headers.get('cookie')).mh_s; if (!t) return null;
  const th = await sha(t), now = Date.now();
  const s = await env.DB.prepare('SELECT uid, exp FROM sessions WHERE th=?').bind(th).first();
  if (!s || s.exp < now) return null;
  const u = await env.DB.prepare('SELECT * FROM users WHERE uid=?').bind(s.uid).first();
  if (!u) return null;
  if (now - (u.last_seen || 0) > 120000) await env.DB.prepare('UPDATE users SET last_seen=? WHERE uid=?').bind(now, u.uid).run();
  u._th = th; return u;
}
async function startSession(env, url, uid) {
  const t = rnd(32), now = Date.now();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO sessions(th,uid,exp) VALUES(?,?,?)').bind(await sha(t), uid, now + SESSION_DAYS * 864e5),
    env.DB.prepare('UPDATE users SET last_seen=? WHERE uid=?').bind(now, uid),
    env.DB.prepare('DELETE FROM sessions WHERE exp<?').bind(now)
  ]);
  return cookie(url, t, SESSION_DAYS * 86400);
}
const notify = (env, ctx, text) => {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  try { ctx.waitUntil(fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text }) }).catch(() => {})); } catch (e) {}
};

/* ---------- ডেটা (items টেবিল, বড় মান ভাগ করে) ---------- */
function assemble(rows) {
  const out = {};
  for (const r of rows) {
    const o = out[r.k] || (out[r.k] = { v: '', t: r.t, del: 0 });
    if (r.del) o.del = 1; else o.v += r.v;
  }
  for (const k in out) { const o = out[k]; out[k] = { v: o.del ? null : o.v, t: o.t }; }
  return out;
}
const inList = n => '(' + Array(n).fill('?').join(',') + ')';
async function doSync(env, user, body) {
  const db = env.DB, since = +body.since || 0, items = body.items && typeof body.items === 'object' ? body.items : {};
  const now = Date.now(), accepted = new Set(), conflicts = [];
  const keys = Object.keys(items).filter(k => KEY_RE.test(k) && items[k] && (items[k].v === null || typeof items[k].v === 'string'));
  let incoming = 0; for (const k of keys) if (items[k].v) incoming += items[k].v.length;
  if (incoming > 0) {
    const r = await db.prepare('SELECT COALESCE(SUM(LENGTH(v)),0) s FROM items WHERE uid=?').bind(user.uid).first();
    if ((r.s || 0) + incoming > MAX_USER_CHARS) return reply({ error: 'quota' }, 413);
  }
  const curT = {};
  for (let i = 0; i < keys.length; i += 80) {
    const part = keys.slice(i, i + 80);
    const q = await db.prepare(`SELECT k,t FROM items WHERE uid=? AND part=0 AND k IN ${inList(part.length)}`).bind(user.uid, ...part).all();
    for (const r of q.results || []) curT[r.k] = r.t;
  }
  const stmts = [];
  for (const k of keys) {
    const it = items[k], t = +it.t || 0, cur = curT[k];
    if (cur !== undefined && !(t > cur)) { conflicts.push(k); continue; }
    accepted.add(k);
    stmts.push(db.prepare('DELETE FROM items WHERE uid=? AND k=?').bind(user.uid, k));
    if (it.v === null) stmts.push(db.prepare("INSERT INTO items(uid,k,part,v,t,ts,del) VALUES(?,?,0,'',?,?,1)").bind(user.uid, k, t, now));
    else {
      const n = Math.max(1, Math.ceil(it.v.length / CHUNK));
      for (let p = 0; p < n; p++) stmts.push(db.prepare('INSERT INTO items(uid,k,part,v,t,ts,del) VALUES(?,?,?,?,?,?,0)').bind(user.uid, k, p, it.v.slice(p * CHUNK, (p + 1) * CHUNK), t, now));
    }
  }
  for (let i = 0; i < stmts.length; i += 90) await db.batch(stmts.slice(i, i + 90));
  const rows = (await db.prepare('SELECT k,part,v,t,del FROM items WHERE uid=? AND k IN (SELECT DISTINCT k FROM items WHERE uid=? AND ts>?) ORDER BY k,part').bind(user.uid, user.uid, since).all()).results || [];
  const back = assemble(rows);
  for (const k of accepted) delete back[k];
  const need = conflicts.filter(k => !back[k]);
  for (let i = 0; i < need.length; i += 80) {
    const part = need.slice(i, i + 80);
    const q = await db.prepare(`SELECT k,part,v,t,del FROM items WHERE uid=? AND k IN ${inList(part.length)} ORDER BY k,part`).bind(user.uid, ...part).all();
    Object.assign(back, assemble(q.results || []));
  }
  return reply({ ok: true, t: now, items: back });
}
async function backupOf(env, uid) {
  const rows = (await env.DB.prepare('SELECT k,part,v,t,del FROM items WHERE uid=? ORDER BY k,part').bind(uid).all()).results || [];
  const all = assemble(rows), items = {};
  for (const k in all) if (all[k].v !== null) items[k] = all[k];
  return items;
}

/* ---------- API ---------- */
async function api(req, env, ctx, url) {
  const p = url.pathname, m = req.method, db = env.DB;
  let body = {};
  if (m === 'POST') {
    if (!/application\/json/.test(req.headers.get('content-type') || '')) return reply({ error: 'type' }, 415);
    try { body = await req.json(); } catch (e) { return reply({ error: 'json' }, 400); }
  }
  await ensureAdmin(env);

  if (p === '/api/register' && m === 'POST') {
    if (await limited(db, 'reg:' + ipOf(req), 8, 3600e3)) return reply({ error: 'rate' }, 429);
    const name = String(body.name || '').trim().slice(0, 60), idn = normIdent(body.id), pw = String(body.password || '');
    if (name.length < 2) return reply({ error: 'name' }, 400);
    if (!idn) return reply({ error: 'ident' }, 400);
    if (pw.length < 6 || pw.length > 200) return reply({ error: 'pw' }, 400);
    if (await db.prepare('SELECT 1 x FROM users WHERE ident=?').bind(idn.id).first()) return reply({ error: 'exists' }, 409);
    const uid = rnd(9), salt = rnd(16), iter = iterOf(env), hash = await pbkdf2(pw, salt, iter), now = Date.now();
    await db.prepare("INSERT INTO users(uid,ident,type,name,salt,hash,iter,role,status,created_at) VALUES(?,?,?,?,?,?,?,'user','pending',?)").bind(uid, idn.id, idn.type, name, salt, hash, iter, now).run();
    const ck = await startSession(env, url, uid);
    notify(env, ctx, `🆕 মুহাসিব — নতুন রেজিস্ট্রেশন রিকোয়েস্ট\nনাম: ${name}\n${idn.type === 'email' ? 'ইমেইল' : 'মোবাইল'}: ${idn.id}\nঅ্যাডমিন প্যানেল থেকে অনুমোদন দিন।`);
    return reply({ ok: true, status: 'pending' }, 200, { 'Set-Cookie': ck });
  }

  if (p === '/api/login' && m === 'POST') {
    const idn = normIdent(body.id), ip = ipOf(req);
    if (await limited(db, 'login:' + ip + ':' + (idn ? idn.id : ''), 10, 15 * 60e3) || await limited(db, 'login:' + ip, 40, 15 * 60e3)) return reply({ error: 'rate' }, 429);
    const u = idn ? await db.prepare('SELECT * FROM users WHERE ident=?').bind(idn.id).first() : null;
    if (!(await checkPw(String(body.password || ''), u, env))) return reply({ error: 'bad' }, 401);
    return reply({ ok: true, status: u.status }, 200, { 'Set-Cookie': await startSession(env, url, u.uid) });
  }

  if (p === '/api/logout' && m === 'POST') {
    const t = parseCookies(req.headers.get('cookie')).mh_s;
    if (t) await db.prepare('DELETE FROM sessions WHERE th=?').bind(await sha(t)).run();
    return reply({ ok: true }, 200, { 'Set-Cookie': cookie(url, '', 0) });
  }

  const user = await auth(req, env);
  if (!user) return reply({ error: 'auth' }, 401);
  if (p === '/api/me' && m === 'GET') return reply(pub(user));
  if (user.status !== 'approved') return reply({ error: user.status }, 403);

  if (p === '/api/sync' && m === 'POST') return doSync(env, user, body);

  if (p === '/api/backup' && m === 'GET') {
    const items = await backupOf(env, user.uid);
    return reply(JSON.stringify({ app: 'muhasib', version: 1, exportedAt: new Date().toISOString(), user: { name: user.name, ident: user.ident }, items }), 200,
      { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="muhasib-backup-${new Date().toISOString().slice(0, 10)}.json"` });
  }

  if (p === '/api/password' && m === 'POST') {
    if (await limited(db, 'pw:' + user.uid, 8, 15 * 60e3)) return reply({ error: 'rate' }, 429);
    if (!(await checkPw(String(body.old || ''), user, env))) return reply({ error: 'bad' }, 401);
    const np = String(body.new || ''); if (np.length < 6 || np.length > 200) return reply({ error: 'pw' }, 400);
    const salt = rnd(16), iter = iterOf(env), hash = await pbkdf2(np, salt, iter);
    await db.batch([
      db.prepare('UPDATE users SET salt=?,hash=?,iter=? WHERE uid=?').bind(salt, hash, iter, user.uid),
      db.prepare('DELETE FROM sessions WHERE uid=? AND th<>?').bind(user.uid, user._th)
    ]);
    return reply({ ok: true });
  }

  /* ----- অ্যাডমিন ----- */
  if (p.startsWith('/api/admin/')) {
    if (user.role !== 'admin') return reply({ error: 'admin' }, 403);
    if (p === '/api/admin/users' && m === 'GET') {
      const rows = (await db.prepare('SELECT u.uid,u.name,u.ident,u.type,u.role,u.status,u.created_at,u.approved_at,u.last_seen,COALESCE(SUM(LENGTH(i.v)),0) size FROM users u LEFT JOIN items i ON i.uid=u.uid GROUP BY u.uid ORDER BY u.created_at DESC').all()).results || [];
      return reply({ users: rows.map(r => ({ uid: r.uid, name: r.name, ident: r.ident, type: r.type, role: r.role, status: r.status, createdAt: r.created_at, approvedAt: r.approved_at, lastSeen: r.last_seen, size: r.size })) });
    }
    if (p === '/api/admin/user' && m === 'POST') {
      const t = await db.prepare('SELECT * FROM users WHERE uid=?').bind(String(body.uid || '')).first();
      if (!t) return reply({ error: 'nouser' }, 404);
      if (t.role === 'admin') return reply({ error: 'admin' }, 400);
      const a = body.action, now = Date.now();
      if (a === 'approve' || a === 'unblock') await db.prepare("UPDATE users SET status='approved', approved_at=? WHERE uid=?").bind(now, t.uid).run();
      else if (a === 'reject' || a === 'block') await db.batch([db.prepare('UPDATE users SET status=? WHERE uid=?').bind(a === 'reject' ? 'rejected' : 'blocked', t.uid), db.prepare('DELETE FROM sessions WHERE uid=?').bind(t.uid)]);
      else if (a === 'resetpw') {
        const np = String(body.password || ''); if (np.length < 6) return reply({ error: 'pw' }, 400);
        const salt = rnd(16), iter = iterOf(env), hash = await pbkdf2(np, salt, iter);
        await db.batch([db.prepare('UPDATE users SET salt=?,hash=?,iter=? WHERE uid=?').bind(salt, hash, iter, t.uid), db.prepare('DELETE FROM sessions WHERE uid=?').bind(t.uid)]);
      } else if (a === 'delete') await db.batch([db.prepare('DELETE FROM sessions WHERE uid=?').bind(t.uid), db.prepare('DELETE FROM items WHERE uid=?').bind(t.uid), db.prepare('DELETE FROM users WHERE uid=?').bind(t.uid)]);
      else return reply({ error: 'action' }, 400);
      return reply({ ok: true });
    }
    if (p === '/api/admin/backup' && m === 'GET') {
      const t = await db.prepare('SELECT * FROM users WHERE uid=?').bind(url.searchParams.get('uid') || '').first();
      if (!t) return reply({ error: 'nouser' }, 404);
      const items = await backupOf(env, t.uid);
      return reply(JSON.stringify({ app: 'muhasib', version: 1, exportedAt: new Date().toISOString(), user: { name: t.name, ident: t.ident }, items }), 200,
        { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="muhasib-${t.ident.replace(/[^\w.@-]/g, '_')}.json"` });
    }
  }
  return reply({ error: 'nf' }, 404);
}

/* ---------- পেজ ও স্ট্যাটিক ফাইল ---------- */
async function asset(env, req, path) {
  const u = new URL(req.url); u.pathname = path; u.search = '';
  return env.ASSETS.fetch(new Request(u.toString(), { method: 'GET' }));
}
async function page(req, env) {
  const user = await auth(req, env);
  if (user && user.status === 'approved') {
    const r = await asset(env, req, '/app.html'); if (!r.ok) return reply('app.html missing', 500);
    const html = (await r.text()).replace('<!--MUH-->', `<script>window.MUH=${jsonSafe({ uid: user.uid, ident: user.ident, name: user.name, role: user.role })}</script>`);
    return reply(html, 200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Muh': 'app' });
  }
  const r = await asset(env, req, '/login.html'); if (!r.ok) return reply('login.html missing', 500);
  const html = (await r.text()).replace('<!--STATE-->', `<script>window.MUH_STATE=${jsonSafe(user ? { status: user.status, name: user.name, ident: user.ident } : null)}</script>`);
  return reply(html, 200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Muh': 'login' });
}

export default {
  async fetch(req, env, ctx) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith('/api/')) return await api(req, env, ctx, url);
      if (req.method !== 'GET' && req.method !== 'HEAD') return reply('Method Not Allowed', 405);
      if (url.pathname === '/' || url.pathname === '/index.html') { await ensureAdmin(env); return await page(req, env); }
      if (PUBLIC_FILES.has(url.pathname)) {
        const r = await asset(env, req, url.pathname);
        const h = new Headers(r.headers); for (const k in SEC) h.set(k, SEC[k]);
        if (url.pathname === '/sw.js') { h.set('Cache-Control', 'no-cache'); h.set('Service-Worker-Allowed', '/'); }
        else h.set('Cache-Control', 'public, max-age=3600');
        return new Response(r.body, { status: r.status, headers: h });
      }
      return reply('Not found', 404);
    } catch (e) {
      const msg = String(e && e.message || e);
      if (/no such table/i.test(msg)) return reply('ডাটাবেস সেটআপ হয়নি — schema.sql একবার চালান (README দেখুন)।', 503);
      console.error(e);
      return reply({ error: 'server' }, 500);
    }
  }
};
