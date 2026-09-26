# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### <the decision, as a claim — not "permissions", but "the org-level view counts device-scoped grants">

**What I chose:**
**Why:** _(evidence: test, log line, commit)_
**What I rejected:** _(the plausible alternative, and the specific reason it fails)_
**What would change my mind:**

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

### Stub — the shape of a weak "Why"

**What I chose:** the obvious thing.
**Why:** it is what the brief says to do.
**What I rejected:** nothing, the alternative seemed worse.
**What would change my mind:** I do not know.

_Reads as a memory of the document, not a model of the system. Scores nothing._

---

### Stub — the shape of a strong "Why"

**What I chose:** X.
**Why:** I implemented Y first, because Y is the intuitive precedence rule. `node scripts/check-
permissions.js` reported `<the actual reason string it reported>` on the case where the two grants
disagree. That is only reachable if the two are evaluated in a different order than Y assumes.
Moved to X in `<commit>` and the case passed. Logged in `BUILD-LOG.md` under Phase 2.
**What I rejected:** Y, and also "resolve the narrower one last" — both fail the same case for the
same reason.
**What would change my mind:** a case where a narrower grant is expected to survive a broader
refusal. I could not construct one, which is itself evidence for X.

_Shows what you believed, what disproved it, and what you did next._

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.

### D1: In-Memory Access Tokens with HttpOnly Refresh Cookie

**What I chose:** Access tokens are stored exclusively in module-scoped JavaScript memory (`let inMemoryToken = null`). Session continuity across reloads is achieved via an `HttpOnly`, `SameSite=Lax` refresh cookie (`rt`) exchanged at `POST /v1/auth/refresh`.
**Why:** `tests/ui.spec.js:201` (`no token is persisted in web storage`) explicitly asserts `localStorage`, `sessionStorage`, and readable `document.cookie` have length 0 and do not contain tokens.
**What I rejected:** Storing the JWT in `localStorage` or accessible cookies. While simpler for SPA page reloads, it exposes the token to extraction via XSS and fails the security contract test.
**What would change my mind:** If the application were hosted across multiple third-party domains requiring cross-site CORS without credentials support.

---

### D2: Server-Side Permission Resolution Over Client Matrices

**What I chose:** The server computes an element-level permissions dictionary on all entity endpoints (`GET /v1/orgs/:org/devices`). The React SPA only renders an action if `permissions[key]?.effect === 'allow'`.
**Why:** Verified by `tests/ui.spec.js:139` ("an element vanishes when the server withdraws the permission"). When Playwright intercepts the API route and replaces the permission effect with `deny`, the button immediately disappears.
**What I rejected:** Hardcoding a role-to-permission mapping inside `web/main.jsx`. A client matrix decouples UI state from backend policy enforcement and fails dynamic grant evaluation.
**What would change my mind:** A strict offline-first requirement where decisions must be computed on disconnected clients using signed policy bundles.

---

### D3: Presence Semantics (Absence Over Disabled State)

**What I chose:** Elements for which the user lacks permission are completely omitted from the DOM rather than rendered with `disabled` attributes.
**Why:** Stated in `tests/ui.spec.js:1`: "The rule under test: an element is PRESENT or ABSENT. There is no disabled state." Also prevents enumeration oracles on endpoints (e.g. `tests/ui.spec.js:127`).
**What I rejected:** Rendering disabled buttons with tooltips explaining missing permissions. While common in internal enterprise tools, it leaks feature existence and organizational hierarchy to unauthorized observers.
**What would change my mind:** Explicit enterprise UX requirements where users need discoverability to request privilege escalations for unavailable features.
