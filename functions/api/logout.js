// POST /api/logout â best-effort server-side session invalidation.
import { bad, getBearerToken, sessionKey, json } from '../_shared/lib.js';

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return json({ ok: true });
  const token = getBearerToken(request);
  if (token) {
    try { await kv.delete(sessionKey(token)); } catch (e) {}
  }
  return json({ ok: true });
}
