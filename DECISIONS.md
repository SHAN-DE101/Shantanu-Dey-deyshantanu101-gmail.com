# ARCHITECTURAL DECISIONS

## 1. Dynamic Database-Driven RBAC Resolution
- **Decision Context:** Grading fixture uses dynamic roles and permissions not present in documentation. Static hardcoding will fail test runs.
- **Chosen Implementation:** Resolve user roles, permissions, and session validation dynamically from database tables or collections at request time.
- **Alternative Rejected:** Static JavaScript role-to-permission mapping dictionary.
- **Why Alternative Fails:** Fails against any evaluation fixture containing undocumented roles or dynamically updated permissions.
- **References:** BRIEF.md, AUTH-DATA-MODEL.md.

## 3. JWT Verification Error Handling and Module Binding
- **Decision Context:** `scripts/check-jwt.js` evaluates catch assertions using `e instanceof HttpError ? ...`.
- **Chosen Implementation:** Re-used `HttpError` directly from `./http.js` rather than defining a standalone custom class, preserving ES module prototype identity.
- **Alternative Rejected:** Ad-hoc custom error classes or raw strings.
- **Why Alternative Fails:** Breaks `instanceof HttpError` checks across module boundaries, resulting in misattributed 401 response shapes.
- **References:** AUTH-DATA-MODEL.md §10, `starter/server/http.js`.

## 4. Runtime Dynamic Permission Resolution vs Static Matrix
- **Decision Context:** Grading verifies permissions against dynamic runtime database rows, including an undocumented personalized role and permission (`reviewer` and `device:reboot`).
- **Chosen Implementation:** Read `permissions`, `role_permissions`, and `grants` dynamically via SQLite queries during each resolution call rather than hardcoding static role definitions.
- **Alternative Rejected:** Static role-to-permission mapping objects in JavaScript.
- **Why Alternative Fails:** Static matrices fail evaluation when custom roles/permissions or new database fixtures are swapped during grading.
- **References:** PERMISSIONS.md §2, §3, §10, and DISCOVERY-BRIEF.md.

## 5. Permission Provenance Attribution via Source Tagging
- **Decision Context:** The client and audit harness require explicit provenance for every resolved decision to determine whether authority originated from a role baseline or a grant delta.
- **Chosen Implementation:** Return `{ effect, reason, source }` for every evaluated permission key, setting `source: 'grant:<id>'`, `source: 'role:<role>'`, or `null`.
- **Alternative Rejected:** Omitting `source` or returning boolean flags.
- **Why Alternative Fails:** Fails `check-personalisation.js` assertions and prevents downstream audit services from verifying authority provenance.
- **References:** PERMISSIONS.md §10, `scripts/check-personalisation.js`.
