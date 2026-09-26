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
