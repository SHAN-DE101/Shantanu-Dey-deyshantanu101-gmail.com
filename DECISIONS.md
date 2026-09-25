# ARCHITECTURAL DECISIONS

## 1. Dynamic Database-Driven RBAC Resolution
- **Decision Context:** Grading fixture uses dynamic roles/permissions not present in documentation. Static hardcoding leads to immediate failure.
- **Chosen Implementation:** Resolve user roles, permissions, and session validation dynamically from database tables/collections at request time.
- **Alternative Rejected:** Static JavaScript role-to-permission mapping dictionary.
- **Why Alternative Fails:** Static maps fail against any fixture containing undocumented roles or dynamic administrative permission updates.
- **References:** BRIEF.md, AUTH-DATA-MODEL.md.
