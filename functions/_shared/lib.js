// ============================================
// SearchCuve server-side shared helpers
// Runs on Cloudflare Pages Functions (Workers runtime)
// ============================================

export const PRICE_MONTHLY = 9900;
export const PRICE_ONCE = 11900;
export const TRIAL_DAYS = 3;

export function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

export function bad(message, status) {
  return json({ error: message }, status || 400);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBuf(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr.buffer;
}

export function randomHex(nBytes) {
  const arr = new Uint8Array(nBytes);
  crypto.getRandomValues(arr);
  return bufToHex(arr.buffer);
}

// PBKDF2-HMAC-SHA256, 100000 iterations, 256-bit output — matches Node's
// crypto.pbkdf2Sync(password, Buffer.from(saltHex,'hex'), 100000, 32, 'sha256')
export async function pbkdf2Hex(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return bufToHex(bits);
}

export async function hashPassword(password) {
  const salt = randomHex(16);
  const hash = await pbkdf2Hex(password, salt);
  return { salt, hash };
}

export async function verifyPassword(password, salt, hash) {
  const computed = await pbkdf2Hex(password, salt);
  // constant-time-ish compare
  if (computed.length !== hash.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ hash.charCodeAt(i);
  return diff === 0;
}

export function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---------- KV helpers ----------
export function userKey(email) { return 'user:' + String(email).toLowerCase().trim(); }
export function sessionKey(token) { return 'sess:' + token; }
export function rateKey(name, id) { return 'rl:' + name + ':' + id; }

export async function kvGetJSON(kv, key) {
  const v = await kv.get(key);
  return v ? JSON.parse(v) : null;
}
export async function kvPutJSON(kv, key, value, opts) {
  await kv.put(key, JSON.stringify(value), opts || {});
}

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

export async function createSession(kv, email, extra) {
  const token = randomHex(32);
  await kvPutJSON(kv, sessionKey(token), Object.assign({ email }, extra || {}), { expirationTtl: SESSION_TTL_SECONDS });
  return token;
}

export async function getSession(kv, token) {
  if (!token) return null;
  return await kvGetJSON(kv, sessionKey(token));
}

export function getBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

// Simple fixed-window rate limiter stored in KV.
// Returns true if the action is allowed, false if the caller should be throttled.
export async function checkRateLimit(kv, name, id, limit, windowSeconds) {
  const key = rateKey(name, id);
  const rec = (await kvGetJSON(kv, key)) || { count: 0 };
  if (rec.count >= limit) return false;
  rec.count += 1;
  await kvPutJSON(kv, key, rec, { expirationTtl: windowSeconds });
  return true;
}

// ---------- Subscription business rules ----------
// Mirrors the client-side MrfAuth logic in index.html so both sides agree.
function addDays(date, days) {
  const d = new Date(date);
  d.setDate(d.getDate() + days);
  return d;
}

// Builds a brand-new subscription object for a plan purchase.
// `trialUsed` — if true and planType is monthly, skip the free trial and
// charge immediately (prevents unlimited trial resets once localStorage is
// no longer the source of truth).
export function buildSubscription(planType, opts) {
  const now = new Date();
  opts = opts || {};
  const cardLast4 = opts.cardLast4 || '';
  if (planType === 'once') {
    return {
      status: 'once',
      plan: 'once',
      startDate: now.toISOString(),
      periodStart: now.toISOString(),
      periodEnd: addDays(now, 30).toISOString(),
      cardLast4: cardLast4,
      amount: PRICE_ONCE
    };
  }
  if (opts.trialUsed) {
    return {
      status: 'active',
      plan: 'monthly',
      startDate: now.toISOString(),
      periodStart: now.toISOString(),
      periodEnd: addDays(now, 30).toISOString(),
      cardLast4: cardLast4,
      amount: PRICE_MONTHLY
    };
  }
  return {
    status: 'trial',
    plan: 'monthly',
    startDate: now.toISOString(),
    trialStart: now.toISOString(),
    trialEnd: addDays(now, TRIAL_DAYS).toISOString(),
    periodStart: now.toISOString(),
    periodEnd: addDays(now, TRIAL_DAYS).toISOString(),
    cardLast4: cardLast4,
    amount: PRICE_MONTHLY
  };
}

// ---------- Admin (unlimited-use) account ----------
// A single admin account (identified by verified OAuth email, never a
// separate password) always has unlimited access. Configure the email via
// the ADMIN_EMAIL Cloudflare env var; falls back to the owner's own address
// if that var isn't set.
export function isAdminEmail(env, email) {
  const admin = String((env && env.ADMIN_EMAIL) || 'freelyfree@gmail.com').toLowerCase().trim();
  return String(email || '').toLowerCase().trim() === admin;
}

// A permanent, always-active subscription (far-future period end) for the
// admin account. Re-applied on every login/session check so the admin
// account can never drift into 'expired'/'trial'/'cancelled' no matter what
// happens to it.
export function buildAdminSubscription() {
  const now = new Date();
  const far = new Date(now);
  far.setFullYear(far.getFullYear() + 100);
  return {
    status: 'active',
    plan: 'admin',
    startDate: now.toISOString(),
    periodStart: now.toISOString(),
    periodEnd: far.toISOString(),
    cardLast4: '',
    amount: 0
  };
}

export function makePaymentEntry(entry) {
  return {
    id: 'pay_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8),
    date: entry.date || new Date().toISOString(),
    planName: entry.planName || '',
    amount: entry.amount || 0,
    cardLast4: entry.cardLast4 || '',
    method: entry.method || '카드',
    status: entry.status || '결제완료'
  };
}
