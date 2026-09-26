import { HttpError } from './http.js';

export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};

class PermissionError extends HttpError {
  constructor(status, code, message, reason) {
    super(status, code, message);
    this.reason = reason;
  }
}

// Matches permission patterns like '*', 'device:*', or exact keys
function matchesPattern(permission, pattern) {
  if (pattern === '*' || pattern === permission) return true;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return permission.startsWith(prefix);
  }
  return false;
}

export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  // 1. Fetch dynamic catalogue from permissions table (never hardcode)
  const allPermissions = db.prepare('SELECT key FROM permissions').all().map(r => r.key);

  // 2. Fetch membership
  const membership = db.prepare(
    'SELECT role, status, perm_version FROM memberships WHERE user_id = ? AND org_id = ?'
  ).get(userId, orgId);

  if (!membership) {
    const permissions = {};
    for (const p of allPermissions) {
      permissions[p] = { effect: 'deny', reason: 'not_a_member', source: null };
    }
    return { role: null, status: null, permissions };
  }

  const { role, status } = membership;

  // Suspended membership yields an empty/denied permission set
  if (status === 'suspended') {
    const permissions = {};
    for (const p of allPermissions) {
      permissions[p] = { effect: 'deny', reason: 'suspended', source: null };
    }
    return { role, status, permissions };
  }

  // 3. Fetch role baselines
  const roleRows = db.prepare('SELECT permission FROM role_permissions WHERE role = ?').all(role);
  const baselineSet = new Set(roleRows.map(r => r.permission));

  // 4. Fetch active grants
  // Window check: half-open: (starts_at IS NULL OR starts_at <= now) AND (expires_at IS NULL OR expires_at > now)
  const nowIso = now instanceof Date ? now.toISOString() : new Date(now).toISOString();

  let grantQuery = `
    SELECT g.id, g.effect, g.device_id, gp.permission AS pattern
    FROM grants g
    JOIN grant_permissions gp ON g.id = gp.grant_id
    WHERE g.user_id = ? AND g.org_id = ?
      AND (g.revoked_at IS NULL)
      AND (g.starts_at IS NULL OR g.starts_at <= ?)
      AND (g.expires_at IS NULL OR g.expires_at > ?)
  `;
  const params = [userId, orgId, nowIso, nowIso];

  if (deviceId !== null) {
    grantQuery += ' AND (g.device_id IS NULL OR g.device_id = ?)';
    params.push(deviceId);
  } else {
    grantQuery += ' AND g.device_id IS NULL';
  }

  const activeGrants = db.prepare(grantQuery).all(...params);

  // 5. Evaluate permissions: Deny precedence (D1), then Allow, then Implicit Deny (D4)
  const permissions = {};

  for (const perm of allPermissions) {
    const matchingGrants = activeGrants.filter(g => matchesPattern(perm, g.pattern));
    const denyGrant = matchingGrants.find(g => g.effect === 'deny');

    if (denyGrant) {
      permissions[perm] = {
        effect: 'deny',
        reason: 'explicit_deny',
        source: `grant:${denyGrant.id}`,
      };
      continue;
    }

    const allowGrant = matchingGrants.find(g => g.effect === 'allow');
    if (allowGrant) {
      permissions[perm] = {
        effect: 'allow',
        reason: 'grant',
        source: `grant:${allowGrant.id}`,
      };
      continue;
    }

    if (baselineSet.has(perm)) {
      permissions[perm] = {
        effect: 'allow',
        reason: 'role_baseline',
        source: `role:${role}`,
      };
      continue;
    }

    permissions[perm] = {
      effect: 'deny',
      reason: 'implicit',
      source: null,
    };
  }

  return { role, status, permissions };
}

export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const membership = db.prepare(
    'SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ?'
  ).get(userId, orgId);

  const byDevice = {};
  for (const id of deviceIds) {
    byDevice[id] = resolve(db, { userId, orgId, deviceId: id, now }).permissions;
  }

  return { role: membership?.role ?? null, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  const res = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  return res.permissions[permission]?.effect === 'allow';
}

export function assertCan(db, ctx, permission, deviceId = null) {
  const res = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const entry = res.permissions[permission];
  if (entry?.effect !== 'allow') {
    const reason = entry?.reason ?? 'implicit';
    throw new PermissionError(403, 'FORBIDDEN', `Permission denied: ${permission}`, reason);
  }
}

export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const allPermissions = db.prepare('SELECT key FROM permissions').all().map(r => r.key);

  for (const pattern of patterns) {
    const targets = allPermissions.filter(p => matchesPattern(p, pattern));
    for (const p of targets) {
      if (resolved.permissions[p]?.effect !== 'allow') {
        throw new PermissionError(403, 'FORBIDDEN', `Cannot grant unheld permission: ${p}`, 'privilege_laundering');
      }
    }
  }
}

export function assertCanStartSession(db, ctx, mode, deviceId) {
  const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  // 1. Must hold session:start
  if (resolved.permissions['session:start']?.effect !== 'allow') {
    throw new PermissionError(403, 'FORBIDDEN', 'Cannot start session: missing session:start', 'missing_permission');
  }

  // 2. Must hold mode-specific device permission
  const requiredModePerm = MODE_PERMISSION[mode];
  if (!requiredModePerm || resolved.permissions[requiredModePerm]?.effect !== 'allow') {
    throw new PermissionError(403, 'FORBIDDEN', `Cannot start session: missing ${requiredModePerm}`, 'missing_device_permission');
  }
}
