// POST /api/subscription — authenticated subscription actions: start a plan
// (first purchase for an already-logged-in user, e.g. after a free trial
// expired, or a Kakao/Google user who never had a plan), cancel, or
// reactivate. Mirrors the business rules that used to live only in the
// client's MrfAuth, now enforced server-side so they can't be bypassed by
// clearing localStorage (e.g. the "clear cookies to get another free trial"
// exploit).
import {
  json, bad, getBearerToken, getSession, userKey, kvGetJSON, kvPutJSON,
  buildSubscription, makePaymentEntry, PRICE_ONCE, checkRateLimit,
  isAdminEmail, buildAdminSubscription
} from '../_shared/lib.js';

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('서버 저장소가 설정되지 않았습니다.', 500);

  const token = getBearerToken(request);
  const session = await getSession(kv, token);
  if (!session) return bad('세션이 만료되었습니다. 다시 로그인해주세요.', 401);

  let body;
  try { body = await request.json(); } catch (e) { return bad('잘못된 요청입니다.'); }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'subaction', session.email + ':' + ip, 30, 60 * 60);
  if (!okRate) return bad('요청이 너무 많습니다. 잠시 후 다시 시도해주세요.', 429);

  const key = userKey(session.email);
  const user = await kvGetJSON(kv, key);
  if (!user) return bad('계정을 찾을 수 없습니다.', 404);

  // The admin account's unlimited access can't be changed through this
  // endpoint (no cancelling, no downgrading) — it's always kept active.
  if (isAdminEmail(env, user.email)) {
    user.subscription = buildAdminSubscription();
    await kvPutJSON(kv, key, user);
    return json({ subscription: user.subscription, payments: user.payments || [] });
  }

  const action = body.action;
  const sub = user.subscription;

  if (action === 'start') {
    const planType = body.planType === 'once' ? 'once' : 'monthly';
    const cardLast4 = String(body.cardLast4 || '').slice(-4);
    const newSub = buildSubscription(planType, { cardLast4, trialUsed: planType === 'monthly' ? !!user.trialUsed : false });
    user.subscription = newSub;
    user.payments = user.payments || [];
    if (planType === 'once') {
      user.payments.unshift(makePaymentEntry({ planName: 'Pro 1개월 이용권', amount: PRICE_ONCE, cardLast4 }));
    }
    if (planType === 'monthly') user.trialUsed = true;
    await kvPutJSON(kv, key, user);
    return json({ subscription: user.subscription, payments: user.payments });
  }

  if (!sub) return bad('구독 정보가 없습니다.', 400);

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

  return bad('알 수 없는 action 입니다.');
}
