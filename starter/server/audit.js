import { randomUUID } from 'node:crypto';
import { HttpError } from './http.js';

export function audit(db, {
  orgId,
  actorId = null,
  action,
  targetType = null,
  targetId = null,
  result,
  reasonCode = null,
  requestId = null,
}) {
  if (!orgId) return;

  const id = `aud_${randomUUID().slice(0, 8)}`;
  db.prepare(`
    INSERT INTO audit_events (
      id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  `).run(id, orgId, actorId, action, targetType, targetId, result, reasonCode, requestId);
}

export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && (err.status === 403 || err.status === 401)) {
      audit(db, {
        orgId: ctx?.orgId ?? meta?.orgId,
        actorId: ctx?.userId ?? meta?.actorId ?? null,
        action: meta?.action ?? 'unknown',
        targetType: meta?.targetType ?? null,
        targetId: meta?.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? err.code ?? 'FORBIDDEN',
        requestId: ctx?.requestId ?? null,
      });
    }
    throw err;
  }
}
