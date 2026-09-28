// POST /api/auth/oauth â verifies a Google/Kakao access token *server-side*
// (never trusts the client's claimed email) and gets-or-creates the matching
// account, so social-login users also get a durable, cross-device account.
import { json, bad, userKey, kvGetJSON, kvPutJSON, createSession, checkRateLimit } from '../../_shared/lib.js';

// Accepts either an OAuth2 access_token (implicit-flow popup) or an id_token
// (GIS one-tap JWT credential) â the client sends whichever it has.
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
  if (!kv) return bad('ìë² ì ì¥ìê° ì¤ì ëì§ ìììµëë¤.', 500);

  let body;
  try { body = await request.json(); } catch (e) { return bad('ìëª»ë ìì²­ìëë¤.'); }

  const provider = body.provider === 'kakao' ? 'kakao' : (body.provider === 'google' ? 'google' : null);
  const accessToken = String(body.accessToken || body.idToken || '');
  const tokenKind = body.idToken ? 'id_token' : 'access_token';
  if (!provider || !accessToken) return bad('ìëª»ë ìì²­ìëë¤.');

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'oauth', ip, 30, 60 * 60);
  if (!okRate) return bad('ìì²­ì´ ëë¬´ ë§ìµëë¤. ì ì í ë¤ì ìëí´ì£¼ì¸ì.', 429);

  let identity = null;
  try {
    identity = provider === 'google'
      ? await verifyGoogle(accessToken, tokenKind, env.GOOGLE_CLIENT_ID)
      : await verifyKakao(accessToken);
  } catch (e) {
    identity = null;
  }
  if (!identity || !identity.email) return bad(provider + ' ì¸ì¦ì ì¤í¨íìµëë¤.', 401);

  const key = userKey(identity.email);
  let user = await kvGetJSON(kv, key);
  const isNew = !user;
  if (!user) {
    user = {
      email: identity.email,
      name: identity.name || '',
      provider: provider,
      createdAt: new Date().toISOString(),
      subscription: null,
      payments: []
    };
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
