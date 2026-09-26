import { unauthenticated, notFound } from './http.js';
import { verifyAccessToken, assertFresh } from './auth.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const authHeader = req.headers['authorization'] ?? req.headers['Authorization'];
    if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
      throw unauthenticated('missing or malformed authorization header');
    }

    const rawToken = authHeader.slice(7).trim();
    if (!rawToken) {
      throw unauthenticated('missing token');
    }

    const claims = verifyAccessToken(rawToken, secret);

    // Cross-org invisibility: PERMISSIONS.md §6
    // If the route has an org param and it does not match the token's active org,
    // return 404 NOT_FOUND so cross-org presence is completely invisible.
    if (params && params.org && params.org !== claims.org) {
      throw notFound();
    }

    const membership = db.prepare(`
      SELECT * FROM memberships
      WHERE user_id = ? AND org_id = ?
    `).get(claims.sub, claims.org);

    if (!membership || membership.status !== 'active') {
      throw unauthenticated('membership not found or not active');
    }

    assertFresh(claims, membership);

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
