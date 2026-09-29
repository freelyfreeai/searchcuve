// GET /api/session — refresh the client's cached user/subscription/payments
// from the server on page load, using the bearer session token.
import { json, bad, getBearerToken, getSession, userKey, kvGetJSON } from '../_shared/lib.js';

export async function onRequestGet({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('서버 저장소가 설정되지 않았습니다.', 500);

  const token = getBearerToken(request);
  const session = await getSession(kv, token);
  if (!session) return bad('세션이 만료되었습니다.', 401);

  const user = await kvGetJSON(kv, userKey(session.email));
  if (!user) return bad('계정을 찾을 수 없습니다.', 404);

  return json({
    user: { email: user.email, provider: user.provider, name: user.name || '' },
    subscription: user.subscription || null,
    payments: user.payments || []
  });
}
