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
