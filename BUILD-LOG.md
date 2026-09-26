# BUILD LOG

## 2026-09-26 03:50 IST - Repository Setup & Initial Inspection
- Initialized local workspace `Shantanu-Dey-deyshantanu101-gmail.com`.
- Verified directory contents: found `BRIEF.md`, `AUTH-DATA-MODEL.md`, `PERMISSIONS.md`, `starter/`, and `q1-starter/`.
- Created baseline `BUILD-LOG.md` and `DECISIONS.md` at root.
- Next step: Inspect `starter/` and `q1-starter/` directories to locate `server/auth.js` and determine database fixture wiring.

## 2026-09-26 11:45 IST - Complete JWT Verification Implementation
- Implemented `verifyAccessToken` in `starter/server/auth.js` to satisfy AUTH-DATA-MODEL.md §10.
- Pinned `alg: 'HS256'` and `typ: 'JWT'` to prevent algorithm confusion and `alg: none` exploits.
- Enforced constant-time signature comparison using `crypto.timingSafeEqual`.
- Wired `HttpError(401, 'UNAUTHENTICATED')` error contract from `./http.js`.
- Verified all 43 assertions pass in `scripts/check-jwt.js`.
- Next step: Implement dynamic RBAC permissions resolution.

## 2026-09-26 12:40 IST - Environment Normalization and Dynamic RBAC Engine
- Resolved native compilation failure of `better-sqlite3` on Node v26 by pinning runtime to Node.js v22.23.3 LTS.
- Implemented `server/permissions.js` dynamic resolution engine (`resolve`, `resolveDevices`, `can`, `assertCan`, `assertMayGrant`, `assertCanStartSession`).
- Enforced D1 deny precedence (any explicit deny overrides baseline or grant allow across device/org scopes).
- Enforced D4 implicit deny and D7 half-open time window logic (`expires_at == now` is treated as expired).
- Wired attribution tracking: attached exact `source` strings (`grant:<id>`, `role:<role>`, or `null`) to each resolved permission.
- Handled membership statuses: `not_a_member` produces total denial with reason `'not_a_member'`, while `suspended` membership produces denial with reason `'suspended'`.
- Verified 35/35 assertions in `scripts/check-permissions.js` and all personalized checks in `scripts/check-personalisation.js`.
