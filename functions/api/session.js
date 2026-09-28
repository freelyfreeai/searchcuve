// GET /api/session â refresh the client's cached user/subscription/payments
// from the server on page load, using the bearer session token.
import { json, bad, getBearerToken, getSession, userKey, kvGetJSON } from '../_shared/lib.js';

export async function onRequestGet({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('ìë² ì ì¥ìê° ì¤ì ëì§ ìììµëë¤.', 500);

  const token = getBearerToken(request);
  const session = await getSession(kv, token);
  if (!session) return bad('ì¸ìì´ ë§ë£ëììµëë¤.', 401);

  const masterEmail = (env.MASTER_EMAIL || '').toLowerCase().trim();
  if (session.master || (masterEmail && session.email === masterEmail)) {
    const far = new Date();
    far.setFullYear(far.getFullYear() + 100);
    const masterSub = {
      status: 'active', plan: 'master',
      trialEnd: far.toISOString(), periodStart: new Date().toISOString(), periodEnd: far.toISOString()
    };
    return json({ user: { email: session.email, master: true }, subscription: masterSub, payments: [] });
  }

  const user = await kvGetJSON(kv, userKey(session.email));
  if (!user) return bad('ê³ì ì ì°¾ì ì ììµëë¤.', 404);

  return json({
    user: { email: user.email, provider: user.provider, name: user.name || '' },
    subscription: user.subscription || null,
    payments: user.payments || []
  });
}
