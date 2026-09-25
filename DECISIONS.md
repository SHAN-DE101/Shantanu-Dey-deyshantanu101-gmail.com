# ARCHITECTURAL DECISIONS

## 1. Dynamic Database-Driven RBAC Resolution
- **Decision Context:** Grading fixture uses dynamic roles and permissions not present in documentation. Static hardcoding will fail test runs.
- **Chosen Implementation:** Resolve user roles, permissions, and session validation dynamically from database tables or collections at request time.
- **Alternative Rejected:** Static JavaScript role-to-permission mapping dictionary.
- **Why Alternative Fails:** Fails against any evaluation fixture containing undocumented roles or dynamically updated permissions.
- **References:** BRIEF.md, AUTH-DATA-MODEL.md.
