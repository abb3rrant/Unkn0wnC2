# Defensive security and WebUI review — 2026-11-04

Owner: security-tool-dev. Base: `7cc6a9c559a134ca03476db9765c19a98a04e548` (main, PR #19 merged).

## Scope and limits

This pass reviews browser navigation/accessibility and authentication trust boundaries, and executes existing offline regression/static checks. It is not a complete audit or proof that all code is correct. No beacon command execution, BOF execution, transport optimization, live deployment, destructive data cleanup, or release was performed.

## Fixed in this patch

### CSRF exemption disagreed with authentication source

`Archon/api.go` authenticates with the session cookie before considering a bearer header. The CSRF middleware previously exempted any request with an Authorization header, including requests authenticated by that cookie. The exemption now applies only when the session cookie is absent. Bearer-only API clients retain their existing behavior.

`TestCSRFMatchesAuthenticationSource` uses a valid locally signed session, a temporary database, the real authentication and CSRF middleware, and an inert handler. Its matrix covers POST/PUT/PATCH/DELETE, missing/mismatched/matching CSRF values, unrelated/invalid/valid Authorization headers, and valid/invalid bearer-only requests. It failed before the fix and passed afterwards. This proves middleware behavior, not cross-origin browser exploitability; header-setting restrictions, SameSite cookies, and deployment policy affect real-world exposure.

### Inconsistent accessibility semantics across shared navigation

Ten authenticated pages now share labelled primary navigation, one aria-current section, a focusable main landmark, and a keyboard-accessible skip link. Existing navigation order is unchanged. Shared CSS gives keyboard focus an inset outline that survives decorative clip-path boundaries.

`TestWebUIAccessibleNavigation` failed on the baseline and passes with the patch. It covers all ten pages, including detail-page parent sections, exact navigation order, a unique main landmark, and bypass-link placement.

## Execution evidence

- Forced `GOTOOLCHAIN=go1.26.10` for **all four modules**; the installed default compiler is not a reliable substitute for this pin.
- Archon, Client, Server, tools/builder: `go mod verify`, `go mod tidy -diff`, `go vet ./...`, `staticcheck ./...`, and `go test -race -count=1 ./...` passed. tools/builder reports `[no test files]`; do not describe it as a behavioral test suite.
- After the CSRF edit, reran Archon focused regression, vet, staticcheck, and the entire race suite successfully.
- `govulncheck ./...`: no reachable vulnerabilities found in each module. It also reported module-level advisories not reached by these programs: Archon 23, Client 19, Server 20. These are overlapping per-module counts, not a unique vulnerability total or a clean dependency inventory.
- `git diff --check` passed.
- Isolated Chromium render checks: ten pages at 1280px and 390px (20 combinations). Each has one labelled primary navigation and one current section; the skip link is initially off-screen, visible on focus, precedes header controls in focus order, and moves focus to main when activated.
- Browser checks loaded the real markup/shared and inline CSS but removed scripts, external links/images, and event handlers. They verify layout/focus semantics, **not authenticated application flows**, dynamic tables, modal behavior, API submission, or complete visual/accessibility conformance.
- Authoritative baseline CI: run 134 on main completed successfully. This is not CI evidence for this uncommitted patch.

## Open findings from source inspection — not fixed or runtime reproduced here

The recent abandoned-task sweep merits a separate data-integrity review before relying on the previous claim that all work is closed:

1. `Archon/task_sweep.go:25,40` uses a fixed 30-minute silence threshold, while `beacon_liveness.go:36-53` uses build-aware timing. The two policies can disagree for long configured intervals. Silence alone also does not prove a process died.
2. `task_sweep.go:36-75` selects candidates before opening each write transaction, then updates by task ID without rechecking status or last contact. A concurrent state change can be overwritten. This is a source-level race concern; passing Go race tests does not exclude database logic races.
3. `task_sweep.go:80-82` uses INSERT OR IGNORE for the explanatory result. Existing partial result rows may prevent the promised failure reason from being recorded as expected.

These findings concern record integrity and accuracy of previous completion claims. No changes to the operational tasking subsystem were made in this pass.

## Remaining review gaps

Independent diff review passed with no security concerns, logic errors, or suggestions (`deleg_fb9f81e4`); the reviewer also ran `go test ./...` successfully. This was limited to the CSRF/accessibility patch, not whole-repository correctness. New-branch CI is pending. Live authenticated frontend workflows, mobile overflow of dynamic content, color-contrast compliance, complete modal keyboard behavior, release artifacts at this patch, Windows-specific checks, and a complete repository audit remain unverified. Do not infer their success from the checks above.
