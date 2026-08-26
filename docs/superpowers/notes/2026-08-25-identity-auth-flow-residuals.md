# Identity & Auth Flow — advisory residuals

Recorded 2026-08-25 at subsystem close (plan:
`docs/superpowers/plans/2026-08-25-identity-auth-flow.md`). These are advisory
recommendations from the final whole-branch review and its re-reviews —
accepted, not actioned. None blocks MVP close.

1. **Notifications provider-seam reuse** — the notification service renders and
   sends emails inline instead of reusing the OTP provider seam
   (console/twilio abstraction).
   Deferred because pointer-only coverage is complete and Mailpit-tested, and
   generalizing the seam before a second email consumer exists would be
   premature abstraction.

2. **Mock-idverify argv/stdin parity** — `scripts/mock-idverify.sh` receives
   its payload via argv while the real frozen contract (spec §10) delivers via
   stdin.
   Deferred because boundary result-shape validation plus e2e tests already pin
   both paths; parity cleanup should ride the next idverify-contract change.

3. **Touch-triggered-only session sweep** — expired signup sessions (including
   paused-signup `{SSHA}` payloads, spec §15.1) are deleted lazily by
   `_get_session` (`api/app/routers/signup_router.py:61`) on access;
   never-presented expired tokens linger until manual cleanup.
   Deferred per the ordered lazy-delete design — no background worker in the
   MVP, and the DB-leak exposure class equals every other `sovereign_app` row.

4. **Seam-level row-gone pins** — storage-invariant regressions such as
   row-gone-after-expiry are pinned at the service/repository seam rather than
   through an HTTP round-trip.
   Deferred as deliberate house style: wire shapes get wire pins, storage
   invariants get seam pins; duplicating both layers has caught no additional
   defect class so far.
