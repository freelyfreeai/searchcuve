// POST /api/subscription — authenticated subscription actions.
//
// 결제는 PG 없이 "무통장입금(현금)"으로만 받는다.
//   고객:   order(입금 신청) / cancelOrder / confirmCancel / reactivate
//   관리자: adminList / adminApprove / adminReject / adminReceipt
// 이용권은 관리자가 입금을 확인하고 승인해야만 켜진다(서버가 판단하므로 클라이언트 조작 불가).
import {
  json, bad, getBearerToken, getSession, userKey, kvGetJSON, kvPutJSON,
  buildSubscription, makePaymentEntry, checkRateLimit, randomHex,
  isAdminEmail, buildAdminSubscription, planInfo, applyPaidPlan
} from '../_shared/lib.js';

function cleanReceipt(r) {
  r = r || {};
  const type = r.type === 'income' || r.type === 'business' ? r.type : 'none';
  if (type === 'none') return { type: 'none', number: '' };
  const num = String(r.number || '').replace(/\D/g, '');
  if (type === 'income' && !/^01\d{8,9}$/.test(num)) return { error: '현금영수증용 휴대폰번호를 정확히 입력해주세요. (예: 01012345678)' };
  if (type === 'business' && !/^\d{10}$/.test(num)) return { error: '지출증빙용 사업자등록번호 10자리를 입력해주세요.' };
  return { type, number: num };
}

async function listOrders(kv) {
  const out = [];
  let cursor;
  for (let page = 0; page < 5; page++) {
    const res = await kv.list({ prefix: 'order:', cursor });
    for (const k of res.keys) {
      const o = await kvGetJSON(kv, k.name);
      if (o) out.push(o);
    }
    if (res.list_complete) break;
    cursor = res.cursor;
  }
  out.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return out;
}

export async function onRequestPost({ request, env }) {
  const kv = env.SC_KV;
  if (!kv) return bad('서버 저장소가 설정되지 않았습니다.', 500);

  const token = getBearerToken(request);
  const session = await getSession(kv, token);
  if (!session) return bad('세션이 만료되었습니다. 다시 로그인해주세요.', 401);

  let body;
  try { body = await request.json(); } catch (e) { return bad('잘못된 요청입니다.'); }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const okRate = await checkRateLimit(kv, 'subaction', session.email + ':' + ip, 60, 60 * 60);
  if (!okRate) return bad('요청이 너무 많습니다. 잠시 후 다시 시도해주세요.', 429);

  const action = body.action;

  // ---------- 관리자 전용 ----------
  if (typeof action === 'string' && action.indexOf('admin') === 0) {
    if (!isAdminEmail(env, session.email)) return bad('권한이 없습니다.', 403);

    if (action === 'adminList') {
      return json({ orders: await listOrders(kv) });
    }

    const oKey = 'order:' + String(body.id || '');
    const order = await kvGetJSON(kv, oKey);
    if (!order) return bad('신청 내역을 찾을 수 없습니다.', 404);

    if (action === 'adminReceipt') {
      order.receiptDone = !!body.done;
      await kvPutJSON(kv, oKey, order);
      return json({ order });
    }

    if (order.status !== 'pending') return bad('이미 처리된 신청입니다.');
    const target = await kvGetJSON(kv, userKey(order.email));
    if (!target) return bad('회원 정보를 찾을 수 없습니다.', 404);

    if (action === 'adminApprove') {
      target.subscription = applyPaidPlan(target, order.planType);
      target.payments = target.payments || [];
      const pay = makePaymentEntry({
        planName: order.planName, amount: order.amount,
        method: '무통장입금', status: '입금확인'
      });
      pay.receipt = order.receipt && order.receipt.type !== 'none' ? '현금영수증 신청' : '';
      target.payments.unshift(pay);
      target.trialUsed = true;
      if (target.order && target.order.id === order.id) target.order = null;
      order.status = 'approved';
      order.approvedAt = new Date().toISOString();
      order.receiptDone = false;
      await kvPutJSON(kv, userKey(order.email), target);
      await kvPutJSON(kv, oKey, order);
      return json({ order });
    }

    if (action === 'adminReject') {
      order.status = 'rejected';
      order.rejectedAt = new Date().toISOString();
      order.rejectReason = String(body.reason || '').slice(0, 100);
      if (target.order && target.order.id === order.id) target.order = null;
      await kvPutJSON(kv, userKey(order.email), target);
      await kvPutJSON(kv, oKey, order);
      return json({ order });
    }
    return bad('알 수 없는 action 입니다.');
  }

  // ---------- 일반 회원 ----------
  const key = userKey(session.email);
  const user = await kvGetJSON(kv, key);
  if (!user) return bad('계정을 찾을 수 없습니다.', 404);

  // 관리자(영구회원) 계정은 언제나 무제한 상태 유지
  if (isAdminEmail(env, user.email)) {
    user.subscription = buildAdminSubscription();
    await kvPutJSON(kv, key, user);
    return json({ subscription: user.subscription, payments: user.payments || [], order: null });
  }

  const sub = user.subscription;
  const state = () => json({ subscription: user.subscription, payments: user.payments || [], order: user.order || null });

  // 입금 신청 (이용권은 관리자 승인 후에 켜진다)
  if (action === 'order') {
    const planType = body.planType === 'annual' ? 'annual' : (body.planType === 'once' ? 'once' : null);
    if (!planType) return bad('이용권을 선택해주세요.');
    const depositor = String(body.depositor || '').trim().slice(0, 20);
    if (depositor.length < 2) return bad('입금자명을 2자 이상 입력해주세요.');
    const rc = cleanReceipt(body.receipt);
    if (rc.error) return bad(rc.error);
    if (user.order && user.order.id) await kv.delete('order:' + user.order.id);
    const info = planInfo(planType);
    const id = 'o' + Date.now().toString(36) + randomHex(3);
    const order = {
      id, email: user.email, name: user.name || '', planType,
      planName: info.name, amount: info.amount, depositor, receipt: rc,
      status: 'pending', createdAt: new Date().toISOString()
    };
    await kvPutJSON(kv, 'order:' + id, order);
    user.order = order;
    await kvPutJSON(kv, key, user);
    return state();
  }

  if (action === 'cancelOrder') {
    if (user.order && user.order.id) {
      await kv.delete('order:' + user.order.id);
      user.order = null;
      await kvPutJSON(kv, key, user);
    }
    return state();
  }

  // 예전 'start' 호출: 결제 없이 유료 이용권을 켤 수 없다. 무료체험은 가입 시 1회만.
  if (action === 'start') {
    if (body.planType !== 'once' && body.planType !== 'annual' && !user.trialUsed) {
      user.subscription = buildSubscription('monthly', {});
      user.trialUsed = true;
      await kvPutJSON(kv, key, user);
    }
    return state();
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
    return state();
  }

  if (action === 'reactivate') {
    if (sub.status === 'cancelled' && new Date(sub.periodEnd).getTime() > Date.now()) {
      sub.status = 'once';
      delete sub.cancelledAt;
      user.subscription = sub;
      await kvPutJSON(kv, key, user);
    }
    return state();
  }

  return bad('알 수 없는 action 입니다.');
}
