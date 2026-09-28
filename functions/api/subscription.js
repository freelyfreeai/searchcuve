// POST /api/subscription â authenticated subscription actions: start a plan
// (first purchase for an already-logged-in user, e.g. after a free trial
// expired, or a Kakao/Google user who never had a plan), cancel, or
// reactivate. Mirrors the business rules that used to live only in the
// client's MrfAuth, now enforced server-side so they can't be bypassed by
// clearing localStorage (e.g. the "clear cookies to get another free trial"
// exploit).
import {
  json, bad, getBearerToken, getSession, userKey, kvGetJSON, kvPutJSON,
  buildSubscription, makePaymentEntry, PRICE_ONCE, checkRateLimit
} from '../_shared/lib.js';

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('ìë² ì ì¥ìê° ì¤ì ëì§ ìììµëë¤.', 500);

  const token = getBearerToken(request);
  const session = await getSession(kv, token);
  if (!session) return bad('ì¸ìì´ ë§ë£ëììµëë¤. ë¤ì ë¡ê·¸ì¸í´ì£¼ì¸ì.', 401);

  const masterEmail = (env.MASTER_EMAIL || '').toLowerCase().trim();
  if (session.master || (masterEmail && session.email === masterEmail)) {
    return bad('ë§ì¤í° ê³ì ì êµ¬ë ìíë¥¼ ë³ê²½í  ì ììµëë¤.', 400);
  }

  let body;
  try { body = await request.json(); } catch (e) { return bad('ìëª»ë ìì²­ìëë¤.'); }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'subaction', session.email + ':' + ip, 30, 60 * 60);
  if (!okRate) return bad('ìì²­ì´ ëë¬´ ë§ìµëë¤. ì ì í ë¤ì ìëí´ì£¼ì¸ì.', 429);

  const key = userKey(session.email);
  const user = await kvGetJSON(kv, key);
  if (!user) return bad('ê³ì ì ì°¾ì ì ììµëë¤.', 404);

  const action = body.action;
  const sub = user.subscription;

  if (action === 'start') {
    const planType = body.planType === 'once' ? 'once' : 'monthly';
    const cardLast4 = String(body.cardLast4 || '').slice(-4);
    const newSub = buildSubscription(planType, { cardLast4, trialUsed: planType === 'monthly' ? !!user.trialUsed : false });
    user.subscription = newSub;
    user.payments = user.payments || [];
    if (planType === 'once') {
      user.payments.unshift(makePaymentEntry({ planName: 'Pro 1ê°ì ì´ì©ê¶', amount: PRICE_ONCE, cardLast4 }));
    }
    if (planType === 'monthly') user.trialUsed = true;
    await kvPutJSON(kv, key, user);
    return json({ subscription: user.subscription, payments: user.payments });
  }

  if (!sub) return bad('êµ¬ë ì ë³´ê° ììµëë¤.', 400);

  if (action === 'confirmCancel') {
    if (sub.status === 'trial') {
      sub.status = 'expired';
    } else {
      sub.status = 'cancelled';
    }
    sub.cancelledAt = new Date().toISOString();
    user.subscription = sub;
    await kvPutJSON(kv, key, user);
    return json({ subscription: sub, payments: user.payments || [] });
  }

  if (action === 'reactivate') {
    if (sub.status === 'cancelled' && new Date(sub.periodEnd).getTime() > Date.now()) {
      sub.status = 'active';
      delete sub.cancelledAt;
      user.subscription = sub;
      await kvPutJSON(kv, key, user);
    }
    return json({ subscription: sub, payments: user.payments || [] });
  }

  return bad('ì ì ìë action ìëë¤.');
}
