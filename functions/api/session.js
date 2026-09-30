// GET /api/session — refresh the client's cached user/subscription/payments
// from the server on page load, using the bearer session token.
import { json, bad, getBearerToken, getSession, userKey, kvGetJSON, kvPutJSON, isAdminEmail, buildAdminSubscription, buildSubscription } from '../_shared/lib.js';

export async function onRequestGet({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('서버 저장소가 설정되지 않았습니다.', 500);

  const token = getBearerToken(request);
  const session = await getSession(kv, token);
  if (!session) return bad('세션이 만료되었습니다.', 401);

  const key = userKey(session.email);
  const user = await kvGetJSON(kv, key);
  if (!user) return bad('계정을 찾을 수 없습니다.', 404);

  // The admin account (ADMIN_EMAIL env var) always reports unlimited
  // access, re-applied here too in case it ever drifts.
  if (isAdminEmail(env, user.email)) {
    const sub = user.subscription;
    const alreadyUnlimited = sub && sub.plan === 'admin' && sub.status === 'active'
      && new Date(sub.periodEnd).getTime() - Date.now() > 1000 * 60 * 60 * 24 * 365 * 10;
    if (!alreadyUnlimited) {
      user.subscription = buildAdminSubscription();
      await kvPutJSON(kv, key, user);
    }
  } else if (!user.subscription) {
    // Heal accounts stuck with subscription: null from before the OAuth
    // trial-grant fix — without this, a user who's already logged in (and
    // so never hits /api/auth/oauth again) would see the signup wall
    // re-triggered on every search, forever, since their cached status
    // permanently resolves to 'none'. Grant the trial they should have
    // gotten originally the next time their session refreshes here.
    user.subscription = buildSubscription('monthly', { trialUsed: !!user.trialUsed });
    user.trialUsed = true;
    await kvPutJSON(kv, key, user);
  }

  return json({
    user: { email: user.email, provider: user.provider, name: user.name || '' },
    subscription: user.subscription || null,
    payments: user.payments || []
  });
}
