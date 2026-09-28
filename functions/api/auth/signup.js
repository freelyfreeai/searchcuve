// POST /api/auth/signup â brand-new email/password account + first plan.
// Called from the card-registration step of the signup modal.
import {
  json, bad, isValidEmail, userKey, kvGetJSON, kvPutJSON,
  createSession, checkRateLimit, hashPassword, buildSubscription, makePaymentEntry, PRICE_ONCE
} from '../../_shared/lib.js';

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('ìë² ì ì¥ìê° ì¤ì ëì§ ìììµëë¤.', 500);

  let body;
  try { body = await request.json(); } catch (e) { return bad('ìëª»ë ìì²­ìëë¤.'); }

  const email = (body.email || '').toLowerCase().trim();
  const password = String(body.password || '');
  const planType = body.planType === 'once' ? 'once' : 'monthly';
  const cardLast4 = String(body.cardLast4 || '').slice(-4);

  if (!isValidEmail(email)) return bad('ì´ë©ì¼ íìì íì¸í´ì£¼ì¸ì.');
  if (password.length < 6) return bad('ë¹ë°ë²í¸ë 6ì ì´ìì´ì´ì¼ í©ëë¤.');

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'signup', ip, 20, 60 * 60);
  if (!okRate) return bad('ìì²­ì´ ëë¬´ ë§ìµëë¤. ì ì í ë¤ì ìëí´ì£¼ì¸ì.', 429);

  const key = userKey(email);
  const existing = await kvGetJSON(kv, key);
  if (existing && existing.passwordHash) {
    return bad('ì´ë¯¸ ê°ìë ì´ë©ì¼ìëë¤. ë¡ê·¸ì¸í´ì£¼ì¸ì.', 409);
  }

  const { salt, hash } = await hashPassword(password);
  const subscription = buildSubscription(planType, { cardLast4 });
  const payments = [];
  if (planType === 'once') {
    payments.push(makePaymentEntry({ planName: 'Pro 1ê°ì ì´ì©ê¶', amount: PRICE_ONCE, cardLast4 }));
  }

  const user = existing || {};
  user.email = email;
  user.passwordHash = hash;
  user.salt = salt;
  user.provider = 'email';
  user.createdAt = user.createdAt || new Date().toISOString();
  user.subscription = subscription;
  user.payments = payments;
  user.trialUsed = planType === 'monthly' ? true : !!user.trialUsed;

  await kvPutJSON(kv, key, user);
  const token = await createSession(kv, email);

  return json({
    token,
    user: { email: user.email, provider: user.provider },
    subscription,
    payments
  });
}
