// POST /api/auth/oauth — verifies a Google/Kakao access token *server-side*
// (never trusts the client's claimed email) and gets-or-creates the matching
// account, so social-login users also get a durable, cross-device account.
import { json, bad, userKey, kvGetJSON, kvPutJSON, createSession, checkRateLimit, buildSubscription, isAdminEmail, buildAdminSubscription } from '../../_shared/lib.js';

// Accepts either an OAuth2 access_token (implicit-flow popup) or an id_token
// (GIS one-tap JWT credential) — the client sends whichever it has.
async function verifyGoogle(token, tokenKind, expectedClientId) {
  const param = tokenKind === 'id_token' ? 'id_token' : 'access_token';
  const r = await fetch('https://oauth2.googleapis.com/tokeninfo?' + param + '=' + encodeURIComponent(token));
  if (!r.ok) return null;
  const info = await r.json();
  if (!info.email) return null;
  if (expectedClientId && info.aud && info.aud !== expectedClientId) return null;
  return { email: info.email.toLowerCase(), name: info.name || '' };
}

async function verifyKakao(accessToken) {
  const infoRes = await fetch('https://kapi.kakao.com/v1/user/access_token_info', {
    headers: { Authorization: 'Bearer ' + accessToken }
  });
  if (!infoRes.ok) return null; // token invalid/expired
  const meRes = await fetch('https://kapi.kakao.com/v2/user/me', {
    headers: { Authorization: 'Bearer ' + accessToken }
  });
  if (!meRes.ok) return null;
  const me = await meRes.json();
  const account = me.kakao_account || {};
  const profile = account.profile || {};
  const email = account.email || ('kakao_' + me.id + '@kakao.local');
  return { email: email.toLowerCase(), name: profile.nickname || '' };
}

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('서버 저장소가 설정되지 않았습니다.', 500);

  let body;
  try { body = await request.json(); } catch (e) { return bad('잘못된 요청입니다.'); }

  const provider = body.provider === 'kakao' ? 'kakao' : (body.provider === 'google' ? 'google' : null);
  const accessToken = String(body.accessToken || body.idToken || '');
  const tokenKind = body.idToken ? 'id_token' : 'access_token';
  if (!provider || !accessToken) return bad('잘못된 요청입니다.');

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'oauth', ip, 30, 60 * 60);
  if (!okRate) return bad('요청이 너무 많습니다. 잠시 후 다시 시도해주세요.', 429);

  let identity = null;
  try {
    identity = provider === 'google'
      ? await verifyGoogle(accessToken, tokenKind, env.GOOGLE_CLIENT_ID)
      : await verifyKakao(accessToken);
  } catch (e) {
    identity = null;
  }
  if (!identity || !identity.email) return bad(provider + ' 인증에 실패했습니다.', 401);

  const key = userKey(identity.email);
  let user = await kvGetJSON(kv, key);
  const isNew = !user;
  const isAdmin = isAdminEmail(env, identity.email);
  if (!user) {
    // New social-login accounts get the same 3-day free trial as
    // email/password signups (functions/api/auth/signup.js) — previously
    // this left subscription: null, which made a brand-new Google/Kakao
    // user's status resolve to 'none' and immediately hit the signup wall
    // instead of getting their trial. The one admin account (ADMIN_EMAIL
    // env var, defaults to the owner's own address) gets unlimited access
    // instead of the trial.
    user = {
      email: identity.email,
      name: identity.name || '',
      provider: provider,
      createdAt: new Date().toISOString(),
      subscription: isAdmin ? buildAdminSubscription() : buildSubscription('monthly', {}),
      trialUsed: true,
      payments: []
    };
    await kvPutJSON(kv, key, user);
  } else if (isAdmin) {
    // Re-apply the admin's unlimited subscription on every login so the
    // account can never drift into an expired/trial/cancelled state,
    // regardless of what happened to it in the past.
    const sub = user.subscription;
    const alreadyUnlimited = sub && sub.plan === 'admin' && sub.status === 'active'
      && new Date(sub.periodEnd).getTime() - Date.now() > 1000 * 60 * 60 * 24 * 365 * 10;
    if (!alreadyUnlimited) {
      user.subscription = buildAdminSubscription();
      await kvPutJSON(kv, key, user);
    }
  } else if (!user.subscription) {
    // Heal accounts created while this endpoint had the old bug (before the
    // trial-grant fix above) — they were left with subscription: null,
    // which made their status permanently resolve to 'none' and re-show
    // the signup wall on every search, forever, even after logging back
    // in. Grant the trial they should have gotten originally (or skip
    // straight to active if they'd already used their trial elsewhere).
    user.subscription = buildSubscription('monthly', { trialUsed: !!user.trialUsed });
    user.trialUsed = true;
    await kvPutJSON(kv, key, user);
  }

  const token = await createSession(kv, identity.email);
  return json({
    token,
    isNew,
    user: { email: user.email, name: user.name, provider: user.provider },
    subscription: user.subscription || null,
    payments: user.payments || []
  });
}
