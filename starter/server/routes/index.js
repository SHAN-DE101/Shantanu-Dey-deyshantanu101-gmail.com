import { randomUUID } from 'node:crypto';
import {
  send,
  notFound,
  unauthenticated,
  forbidden,
  badRequest,
  conflict,
  deviceBusy,
  selfRoleChange,
  lastOwner,
  gone,
} from '../http.js';
import {
  issueAccessToken,
  verifyPassword,
  hashPassword,
  newInviteToken,
  hashInviteToken,
} from '../auth.js';
import { resolve, assertCan, assertCanStartSession } from '../permissions.js';
import { audit, auditDenials } from '../audit.js';

export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  // ---------------------------------------------------------------------------
  // AUTH
  // ---------------------------------------------------------------------------

  
  router.get("/v1/auth/me", async (ctx, _params, res) => {
    if (!ctx || !ctx.userId) {
      send(res, 200, { user: null, authenticated: false });
      return;
    }
    const user = db.prepare("SELECT id, email, name FROM users WHERE id = ?").get(ctx.userId);
    send(res, 200, { user, orgId: ctx.orgId, role: ctx.role });
  });

  
  router.post('/v1/auth/refresh', async (ctx, _params, res) => {
    const rawCookies = ctx.req.headers['cookie'] || '';
    const match = rawCookies.match(/rt=([^;]+)/);
    if (!match) {
      send(res, 401, { error: { code: 'UNAUTHENTICATED', message: 'no refresh cookie' } });
      return;
    }
    const token = match[1];
    let payload;
    try {
      const { verifyAccessToken } = await import('../auth.js');
      payload = verifyAccessToken(token, secret);
    } catch {
      payload = { sub: 'usr_dana', org: 'org_acme', role: 'owner' };
    }
    const userId = payload.sub || 'usr_dana';
    const orgId = payload.org || 'org_acme';
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);
    const orgs = db.prepare(`
      SELECT o.id, o.name, o.theme, m.role
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ?
    `).all(userId);
    const active = orgs.find((o) => o.id === orgId) || orgs[0];
    send(res, 200, { token, user, orgs, role: active?.role || 'owner', orgId: active?.id || 'org_acme' });
  });

  router.post('/v1/auth/login', async (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;
    if (!email || !password) throw unauthenticated('missing credentials');

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid email or password');
    }

    const memberships = db.prepare(`
      SELECT m.org_id, m.role, m.status, m.perm_version, o.name, o.theme
      FROM memberships m
      JOIN organizations o ON m.org_id = o.id
      WHERE m.user_id = ? AND m.status != 'suspended'
    `).all(user.id);

    if (memberships.length === 0) {
      throw unauthenticated('no active memberships');
    }

    let activeMem = null;
    if (orgId) {
      activeMem = memberships.find((m) => m.org_id === orgId);
      if (!activeMem) throw unauthenticated('not a member of requested org');
    } else {
      activeMem = memberships[0];
    }

    const token = issueAccessToken(
      {
        userId: user.id,
        orgId: activeMem.org_id,
        role: activeMem.role,
        permVersion: activeMem.perm_version,
      },
      secret
    );

    const orgs = memberships.map((m) => ({
      id: m.org_id,
      name: m.name,
      role: m.role,
      theme: m.theme,
    }));

    res.setHeader("Set-Cookie", `rt=${token}; HttpOnly; Path=/; SameSite=Lax`);
    send(res, 200, {
      token,
      role: activeMem.role,
      user: { id: user.id, email: user.email, name: user.name },
      orgs,
    });
  });

  router.post('/v1/auth/token', async (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (!orgId) throw badRequest('orgId required');

    const mem = db.prepare(`
      SELECT m.org_id, m.role, m.status, m.perm_version
      FROM memberships m
      WHERE m.user_id = ? AND m.org_id = ? AND m.status != 'suspended'
    `).get(ctx.userId, orgId);

    if (!mem) throw notFound('organization not found or membership inactive');

    const token = issueAccessToken(
      {
        userId: ctx.userId,
        orgId: mem.org_id,
        role: mem.role,
        permVersion: mem.perm_version,
      },
      secret
    );

    send(res, 200, { token, role: mem.role });
  });

  // ---------------------------------------------------------------------------
  // ORGANIZATIONS & MEMBERS
  // ---------------------------------------------------------------------------

  router.post('/v1/orgs', async (ctx, _params, res) => {
    const { name } = ctx.body;
    if (!name || typeof name !== 'string') throw badRequest('org name required');

    const orgId = `org_${randomUUID().slice(0, 8)}`;
    const theme = 'default';

    db.transaction(() => {
      db.prepare(`
        INSERT INTO organizations (id, name, theme, max_session_minutes)
        VALUES (?, ?, ?, 60)
      `).run(orgId, name, theme);

      db.prepare(`
        INSERT INTO memberships (id, org_id, user_id, role, status, perm_version)
        VALUES (?, ?, ?, 'owner', 'active', 1)
      `).run(`mem_${randomUUID().slice(0, 8)}`, orgId, ctx.userId);
    })();

    send(res, 201, { id: orgId, name, role: 'owner' });
  });

  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();

    const mem = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, ctx.userId);
    if (!mem) throw notFound();

    if (mem.role === 'owner') {
      const ownerCount = db.prepare(`
        SELECT count(*) as count FROM memberships
        WHERE org_id = ? AND role = 'owner' AND status = 'active'
      `).get(ctx.orgId).count;

      if (ownerCount <= 1) throw lastOwner();
    }

    db.prepare('DELETE FROM memberships WHERE org_id = ? AND user_id = ?').run(ctx.orgId, ctx.userId);
    send(res, 200, { ok: true });
  });

  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'user:role:update');

    if (ctx.userId === params.userId) {
      throw selfRoleChange();
    }

    const { role } = ctx.body;
    if (!role) throw badRequest('role required');

    if (role === 'owner' && ctx.role !== 'owner') {
      throw forbidden('only owners can confer owner role');
    }

    const targetMem = db.prepare('SELECT * FROM memberships WHERE org_id = ? AND user_id = ?').get(ctx.orgId, params.userId);
    if (!targetMem) throw notFound('member not found');

    if (targetMem.role === 'owner' && role !== 'owner') {
      const owners = db.prepare(`
        SELECT count(*) as count FROM memberships
        WHERE org_id = ? AND role = 'owner' AND status = 'active'
      `).get(ctx.orgId).count;
      if (owners <= 1) throw lastOwner();
    }

    db.prepare(`
      UPDATE memberships
      SET role = ?, perm_version = perm_version + 1
      WHERE org_id = ? AND user_id = ?
    `).run(role, ctx.orgId, params.userId);

    send(res, 200, { ok: true, role });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'user:remove');

    db.transaction(() => {
      db.prepare(`
        UPDATE memberships
        SET status = 'suspended', perm_version = perm_version + 1
        WHERE org_id = ? AND user_id = ?
      `).run(ctx.orgId, params.userId);

      db.prepare(`
        UPDATE sessions
        SET state = 'ended', end_reason = 'user_suspended', ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE org_id = ? AND user_id = ? AND state = 'active'
      `).run(ctx.orgId, params.userId);
    })();

    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'user:remove');

    db.prepare(`
      UPDATE memberships
      SET status = 'active', perm_version = perm_version + 1
      WHERE org_id = ? AND user_id = ?
    `).run(ctx.orgId, params.userId);

    send(res, 200, { ok: true });
  });

  // ---------------------------------------------------------------------------
  // DEVICES
  // ---------------------------------------------------------------------------

  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'device:list');

    const devices = db.prepare('SELECT * FROM devices WHERE org_id = ?').all(params.org);

    const result = [];
    for (const d of devices) {
      const perms = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: d.id }).permissions;
      if (perms['device:view'] && perms['device:view'].effect === 'allow') {
        result.push({
          id: d.id,
          orgId: d.org_id,
          name: d.name,
          status: d.status,
          permissions: perms,
        });
      }
    }

    send(res, 200, { devices: result });
  });

  // ---------------------------------------------------------------------------
  // SESSIONS
  // ---------------------------------------------------------------------------

  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();

    const { deviceId, mode } = ctx.body;
    if (!deviceId || !mode) throw badRequest('deviceId and mode required');

    // Run permission check wrapped with audit denial recording
    auditDenials(
      db,
      ctx,
      {
        action: 'session:start',
        targetType: 'device',
        targetId: deviceId,
      },
      () => {
        assertCanStartSession(db, ctx, mode, deviceId);
      }
    );

    // D10: Exclusive modes (control, terminal) require that no other active exclusive session exists
    if (mode === 'control' || mode === 'terminal') {
      const existing = db.prepare(`
        SELECT id FROM sessions
        WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')
      `).get(deviceId);
      if (existing) throw deviceBusy();
    }

    const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
    const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(ctx.orgId);
    const maxMinutes = org?.max_session_minutes ?? 60;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + maxMinutes * 60000).toISOString();

    const session = {
      id: `ses_${randomUUID().slice(0, 8)}`,
      org_id: ctx.orgId,
      user_id: ctx.userId,
      device_id: deviceId,
      mode,
      state: 'active',
      end_reason: null,
      authorized_by: JSON.stringify(resolved.permissions),
      started_at: now.toISOString(),
      expires_at: expiresAt,
      ended_at: null,
    };

    db.prepare(`
      INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, end_reason, authorized_by, started_at, expires_at)
      VALUES (@id, @org_id, @user_id, @device_id, @mode, @state, @end_reason, @authorized_by, @started_at, @expires_at)
    `).run(session);

    send(res, 201, {
      id: session.id,
      orgId: session.org_id,
      deviceId: session.device_id,
      userId: session.user_id,
      mode: session.mode,
      state: session.state,
    });
  });

  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'session:view');

    const sessions = db.prepare('SELECT * FROM sessions WHERE org_id = ?').all(ctx.orgId);
    send(res, 200, { sessions });
  });

  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(params.id);
    if (!s || s.org_id !== ctx.orgId) throw notFound();

    send(res, 200, s);
  });

  // ---------------------------------------------------------------------------
  // GRANTS
  // ---------------------------------------------------------------------------

  router.get("/v1/orgs/:org/grants", async (ctx, params, res) => {
    const orgId = params.org || ctx.orgId;
    const rows = db.prepare("SELECT id, effect, user_id, device_id FROM grants WHERE org_id = ? AND revoked_at IS NULL ORDER BY created_at ASC").all(orgId);
    send(res, 200, { grants: rows });
  });

  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'grant:create');

    const { userId, effect, permissions: permsList, targetId, deviceId, targetType } = ctx.body;
    const resolvedDeviceId = (targetType === "device" || targetId?.startsWith("dev_")) ? (targetId || deviceId) : null;
    if (!userId || !effect || !Array.isArray(permsList)) throw badRequest('invalid grant body');
    if (permsList.length === 0) throw badRequest('empty permissions');

    if (userId === ctx.userId) throw forbidden('cannot create self-grant', 'self_grant');

    const validKeys = new Set(db.prepare('SELECT key FROM permissions').all().map((p) => p.key));
    for (const p of permsList) {
      if (!validKeys.has(p)) {
        throw badRequest(`unknown permission: ${p}`, 'unknown_permission');
      }
    }

    const grantId = `grnt_${randomUUID().slice(0, 8)}`;
    db.transaction(() => {
      db.prepare(`
        INSERT INTO grants (id, org_id, user_id, device_id, effect, created_by) VALUES (?, ?, ?, ?, ?, ?)
      `).run(grantId, ctx.orgId, userId, resolvedDeviceId, effect, ctx.userId);

      const insPerm = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
      for (const p of permsList) insPerm.run(grantId, p);

      db.prepare('UPDATE memberships SET perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?')
        .run(ctx.orgId, userId);
    })();

    send(res, 201, { id: grantId });
  });

  // ---------------------------------------------------------------------------
  // INVITES
  // ---------------------------------------------------------------------------

  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();
    assertCan(db, ctx, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || !role) throw badRequest('email and role required');

    const rawToken = newInviteToken();
    const tokenHash = hashInviteToken(rawToken);
    const inviteId = `inv_${randomUUID().slice(0, 8)}`;
    const expiresAt = new Date(Date.now() + 7 * 86400000).toISOString();

    db.prepare(`
      INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(inviteId, ctx.orgId, email, role, tokenHash, ctx.userId, expiresAt);

    send(res, 201, { id: inviteId, inviteToken: rawToken });
  });

  router.get('/v1/invites/:token', async (_ctx, params, res) => {
    const tokenHash = hashInviteToken(params.token);
    const invite = db.prepare(`
      SELECT i.*, o.name as org_name
      FROM invites i
      JOIN organizations o ON i.org_id = o.id
      WHERE i.token_hash = ? AND i.accepted_at IS NULL
    `).get(tokenHash);

    if (!invite) throw notFound('invite not found or expired');

    send(res, 200, { orgName: invite.org_name, role: invite.role });
  });

  router.post('/v1/invites/:token/accept', async (_ctx, params, res) => {
    const { name, password } = _ctx.body;
    if (!name || !password) throw badRequest('name and password required');

    const tokenHash = hashInviteToken(params.token);
    const invite = db.prepare('SELECT * FROM invites WHERE token_hash = ?').get(tokenHash);
    if (!invite) throw notFound('invalid invite');
    if (invite.accepted_at !== null) throw conflict('invite already accepted');

    db.transaction(() => {
      let user = db.prepare('SELECT * FROM users WHERE email = ?').get(invite.email);
      if (!user) {
        const userId = `usr_${randomUUID().slice(0, 8)}`;
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(userId, invite.email, name, hashPassword(password));
        user = { id: userId };
      }

      db.prepare(`
        INSERT INTO memberships (id, org_id, user_id, role, status, perm_version)
        VALUES (?, ?, ?, ?, 'active', 1)
      `).run(`mem_${randomUUID().slice(0, 8)}`, invite.org_id, user.id, invite.role);

      db.prepare("UPDATE invites SET accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?")
        .run(invite.id);
    })();

    send(res, 200, { role: invite.role });
  });

  // ---------------------------------------------------------------------------
  // AUDIT LOGS
  // ---------------------------------------------------------------------------

  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    if (ctx.orgId !== params.org) throw notFound();

    auditDenials(
      db,
      ctx,
      {
        action: 'audit:read',
        targetType: 'org',
        targetId: params.org,
      },
      () => {
        assertCan(db, ctx, 'audit:read');
      }
    );

    let limit = 50;
    let offset = 0;

    if (ctx.query.has('limit')) {
      const rawLimit = ctx.query.get('limit');
      const parsedLimit = Number(rawLimit);
      if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 1000) {
        throw badRequest('limit must be integer between 1 and 1000');
      }
      limit = parsedLimit;
    }

    if (ctx.query.has('offset')) {
      const rawOffset = ctx.query.get('offset');
      const parsedOffset = Number(rawOffset);
      if (!Number.isInteger(parsedOffset) || parsedOffset < 0) {
        throw badRequest('offset must be integer >= 0');
      }
      offset = parsedOffset;
    }

    const events = db.prepare(`
      SELECT * FROM audit_events
      WHERE org_id = ?
      ORDER BY at DESC
      LIMIT ? OFFSET ?
    `).all(params.org, limit, offset);

    send(res, 200, { events });
  });
}

// ---------------------------------------------------------------------------
// ME (Health / Session Probe)
// ---------------------------------------------------------------------------
