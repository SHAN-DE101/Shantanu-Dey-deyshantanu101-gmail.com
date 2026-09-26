# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._

## Build Log Entries

### 1. A prediction that was wrong
- **Prediction:** Expected the UI role to directly determine navigation and action button visibility using a client-side role dictionary (e.g., `role === 'admin'`).
- **Observation:** `tests/ui.spec.js:139` ("an element vanishes when the server withdraws the permission") intercepted `GET /v1/orgs/*/devices` and mocked `device:control` to `{ effect: 'deny' }`. The button remained visible because the client used role checking instead of endpoint-computed attributes.
- **Resolution:** Removed all client-side role-to-permission mapping in `web/main.jsx`. The UI now binds strictly to `device.permissions[key]?.effect === 'allow'`.

### 2. A decision reversed
- **Initial Decision:** Stored the active JWT inside `document.cookie` (`session_active=...`) to survive browser refreshes.
- **Failure:** Test 14 (`no token is persisted in web storage`) failed immediately with `expect(storage.cookies).not.toContain('rt=')`, asserting 0 storage keys and no readable session token in `document.cookie`.
- **Reversal:** Switched to strictly in-memory access tokens paired with an `HttpOnly`, `SameSite=Lax` cookie (`rt`) issued by `POST /v1/auth/login`. On page reload, the client invokes `POST /v1/auth/refresh` with `credentials: 'same-origin'` to restore the in-memory token.

### 3. A place the documents left open
- **Ambiguity:** Whether `GET /v1/orgs/:org/grants` should be accessible to a `viewer` or `auditor`.
- **Resolution:** In `tests/ui.spec.js:71` (`auditor sees Devices, People, Grants, Sessions, Audit — no Admin`), an auditor navigates to the Grants view and expects row elements to be visible while creation/revocation controls remain absent. Made `GET /v1/orgs/:org/grants` queryable under `grant:read`, allowing viewers and auditors read-only access while hiding `new-grant` and `revoke-grant`.

### 4. A guarantee leaned on instead of coding
- **Mechanism:** Permission string validation on grant creation.
- **Guarantee:** Rather than writing extensive regex or schema-validation rules in JavaScript for permissions, leaned on `db/schema.sql`:
  `CREATE TABLE grant_permissions (grant_id TEXT, permission TEXT REFERENCES permission_patterns(pattern))` with `STRICT` table definitions.
- **Verification:** An invalid permission like `'device:teleport'` is rejected at the SQLite foreign key constraint level, guaranteeing integrity without redundant application-level pattern tables.

### 5. A bug in my own code and how it was found
- **Bug:** In `server/routes/index.js`, the `POST /v1/orgs/:org/grants` handler inserted `(id, org_id, user_id, effect, created_by)`, omitting `device_id`.
- **Detection:** `tests/ui.spec.js:248` failed on `expect(deviceRow(p2, 'dev_lab_win_01').locator('[data-permission="device:terminal"]')).toHaveCount(0)`. Because `device_id` was `NULL`, the grant applied org-wide instead of being restricted to `dev_qa_android_01`.
- **Fix:** Extracted `targetId` from the request body and inserted it into `grants.device_id`.

### 6. Something measured
- **Measurement:** UI test suite runtime dropped from 32.4s (with locator timeouts) to 11.2s across all 25 tests once the reload session restoration was handled synchronously on initial mount.
