// POST /api/auth/login â email + password login, including the master account.
// The master account's credentials never ship to the client: they live only
// as encrypted environment variables (MASTER_EMAIL / MASTER_PW_SALT / MASTER_PW_HASH)
// on this Cloudflare Pages project, checked here, server-side.
import {
  json, bad, isValidEmail, userKey, kvGetJSON,
  createSession, checkRateLimit, verifyPassword
} from '../../_shared/lib.js';

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('ìë² ì ì¥ìê° ì¤ì ëì§ ìììµëë¤.', 500);

  let body;
  try { body = await request.json(); } catch (e) { return bad('ìëª»ë ìì²­ìëë¤.'); }

  const email = (body.email || '').toLowerCase().trim();
  const password = String(body.password || '');
  if (!isValidEmail(email) || !password) return bad('ì´ë©ì¼ê³¼ ë¹ë°ë²í¸ë¥¼ íì¸í´ì£¼ì¸ì.');

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'login', email + ':' + ip, 10, 15 * 60);
  if (!okRate) return bad('ë¡ê·¸ì¸ ìëê° ëë¬´ ë§ìµëë¤. 15ë¶ í ë¤ì ìëí´ì£¼ì¸ì.', 429);

  // ---------- Master account (server-side only, never in client code) ----------
  const masterEmail = (env.MASTER_EMAIL || '').toLowerCase().trim();
  if (masterEmail && email === masterEmail) {
    const ok = env.MASTER_PW_SALT && env.MASTER_PW_HASH
      ? await verifyPassword(password, env.MASTER_PW_SALT, env.MASTER_PW_HASH)
      : false;
    if (!ok) return bad('ì´ë©ì¼ ëë ë¹ë°ë²í¸ê° ì¬ë°ë¥´ì§ ììµëë¤.', 401);

    const far = new Date();
    far.setFullYear(far.getFullYear() + 100);
    const masterSub = {
      status: 'active', plan: 'master',
      trialEnd: far.toISOString(), periodStart: new Date().toISOString(), periodEnd: far.toISOString()
    };
    const token = await createSession(kv, email, { master: true });
    return json({ token, user: { email, master: true }, subscription: masterSub, payments: [] });
  }

  // ---------- Normal account ----------
  const user = await kvGetJSON(kv, userKey(email));
  if (!user) return bad('ê°ìë ê³ì ì ì°¾ì ì ììµëë¤.', 404);
  if (!user.passwordHash) return bad('ì´ ê³ì ì ìì ë¡ê·¸ì¸ ì ì©ìëë¤. ì¹´ì¹´ì¤/Googleë¡ ë¡ê·¸ì¸í´ì£¼ì¸ì.', 400);

  const ok = await verifyPassword(password, user.salt, user.passwordHash);
  if (!ok) return bad('ì´ë©ì¼ ëë ë¹ë°ë²í¸ê° ì¬ë°ë¥´ì§ ììµëë¤.', 401);

  const token = await createSession(kv, email);
  return json({
    token,
    user: { email: user.email, provider: user.provider, name: user.name || '' },
    subscription: user.subscription || null,
    payments: user.payments || []
  });
}
