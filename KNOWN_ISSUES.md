# Known Issues

## Test environment

The RBAC test suite originally relied on `server.js`'s `initialize()` flow
to seed default roles, permissions, and users. Tests `require()` the app
module rather than running it as `main`, so seeding never happened and
most permission tests failed.

**Fix applied:**
- Added `tests/setup.js` as a Jest `globalSetup` that points `DATA_DIR` to
  a fixed test fixture directory and seeds defaults via the model layer.
- Added `tests/env-shim.js` as a Jest `setupFiles` shim so each worker
  process resolves the same `DATA_DIR` regardless of pid.

**Remaining work (separate from the seeding fix):**
- Several integration tests assume rate-limit windows that aren't reset
  between runs.
- A few admin-route tests depend on audit log state that needs explicit
  cleanup in `beforeEach`.
- Async handle cleanup needs `--detectOpenHandles` work (Jest currently
  reports it doesn't exit cleanly after the suite).

These are tracked for follow-up.
