import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { HttpError } from './http.js';

export function unauthenticated(message = 'UNAUTHENTICATED') {
  return new HttpError(401, 'UNAUTHENTICATED', message);
}

export function tokenStale(message = 'TOKEN_STALE') {
  return new HttpError(401, 'TOKEN_STALE', message);
}

export const ALG = 'HS256';
export const ISS = process.env.JWT_ISS ?? 'remoteops';
export const AUD = process.env.JWT_AUD ?? 'remoteops-api';
export const ACCESS_TTL_SECONDS = 900;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

export function verifyAccessToken(token, secret) {
  if (typeof token !== 'string') {
    throw unauthenticated('malformed token');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw unauthenticated('malformed token');
  }

  const [h, p, s] = parts;
  if (!h || !p || s === undefined) {
    throw unauthenticated('malformed token');
  }

  // 1. Decode & parse header
  let header;
  try {
    const rawHeader = unb64(h).toString('utf8');
    header = JSON.parse(rawHeader);
  } catch {
    throw unauthenticated('malformed token header');
  }

  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    throw unauthenticated('malformed token header');
  }

  // Defend against alg: none & algorithm substitutions
  if (header.alg !== ALG || header.typ !== 'JWT') {
    throw unauthenticated('unsupported token algorithm');
  }

  // 2. Validate signature in constant time
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw unauthenticated('bad signature');
  }

  let actualSig;
  try {
    actualSig = unb64(s);
  } catch {
    throw unauthenticated('bad signature');
  }

  const expectedSig = createHmac('sha256', secret).update(`${h}.${p}`).digest();

  if (actualSig.length !== expectedSig.length || !timingSafeEqual(actualSig, expectedSig)) {
    throw unauthenticated('bad signature');
  }

  // 3. Decode & parse payload
  let claims;
  try {
    const rawPayload = unb64(p).toString('utf8');
    claims = JSON.parse(rawPayload);
  } catch {
    throw unauthenticated('malformed token payload');
  }

  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw unauthenticated('malformed token payload');
  }

  // 4. Validate claims
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp <= now) {
    throw unauthenticated('token expired');
  }

  if (claims.iss !== ISS || claims.aud !== AUD) {
    throw unauthenticated('bad token issuer or audience');
  }

  if (typeof claims.jti !== 'string' || claims.jti.trim() === '') {
    throw unauthenticated('token has no jti');
  }

  return claims;
}

export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
