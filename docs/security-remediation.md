# Defensive security remediation

This branch addresses security findings from the HTTP/control-plane audit. It does not change beacon command execution, BOF loading, C2 payload formats, transport delivery, or task-ledger cleanup policies. HTTP credential placement changes as described below.

## WebSocket authorization lifetime (SEC-02)

An authenticated WebSocket is no longer authorized solely by the state observed during its initial upgrade:

- Require a persistent, unrevoked, unexpired session row belonging to the operator at upgrade and on each recheck; JWTs without a JTI/expiry are rejected for WebSockets.
- Read that session state directly, bypassing the HTTP revocation cache so external database changes are observed on the next check.
- Recheck the account's active state before each outgoing event.
- Recheck idle connections every five seconds; close on database validation failure as well as revocation/disable.
- Close at the JWT expiry deadline using a dedicated timer. Heartbeat pongs cannot extend authorization.
- Discard queued events when the session is no longer authorized, sending WebSocket policy-violation close code 1008.

Revocation checks are not a transaction with network delivery: an event already being written when an account is disabled cannot be recalled. Idle detection is bounded by the recheck interval and database/network operation time, not instantaneous logout propagation.

`TestWebSocketSessionAuthorizationLifetime` uses a temporary database and an inert local event to cover active sessions plus disable/revoke/expire cases with queued output and while idle. It failed against baseline behavior and passes with this change, including the focused race run.

## Authenticated HTTPS without a pin (CFG-01)

No-pin HTTPS now uses the normal Go/system certificate trust store and verifies the target hostname. Explicit SPKI pins continue to support authenticated self-signed deployments and must match the presented key.

**Compatibility/security change:** a self-signed HTTPS certificate with no configured pin will now be rejected. Use an explicit trusted pin or a certificate trusted by the runtime's CA store. This change does not introduce a new trust-any flag or alter plain HTTP. Encrypted transport alone does not authenticate a peer.

`TestHTTPTLSPeerAuthentication` exercises local TLS handshakes against an inert server: unknown self-signed certificate rejected, trusted certificate accepted, wrong hostname rejected, matching pin accepted, wrong pin rejected.

## Release diagnostics (BUILD-01)

The CI container-SBOM scanner no longer runs in quiet mode. No release/security gate is removed or bypassed. A scratch stub test demonstrates that the exact workflow invocation no longer suppresses scanner diagnostics; it is not an actual scanner or release test. The underlying release failure remains unresolved until exact-head CI supplies its real error and that cause is corrected.

## HTTP credential non-disclosure (SEC-01)

New bootstrap requests put the token in `X-Bootstrap-Token`, not the query URL. Controller-bound GET requests relocate API keys to `X-DNS-Server-API-Key` and bootstrap tokens to `X-Bootstrap-Token` before constructing the outgoing HTTP request. Both clients reject redirects rather than forwarding credential headers to another destination. Standard network-error logging and non-success response errors omit secret-bearing URLs, causes, and response bodies; the Server wrapper retains its underlying cause for explicit `errors.Is`/`errors.As` inspection, not for logging.

The controller accepts the new headers and retains legacy query authentication and existing JSON-body authentication for older peers. Conflicting header/query server identities are rejected. **Upgrade the controller before updated peers:** older controllers do not understand the new GET credential headers. Legacy peers that still put credentials in URLs retain that exposure; compatibility support is not a claim that old traffic is safe. Configure infrastructure logging not to record authentication headers.

Focused tests demonstrated the URL/error/redirect failures before the fix and now cover outgoing header placement, non-disclosing errors, stopped redirects, new-header authentication, rejected identity conflicts, and retained legacy query/body authentication using only fakes or inert local handlers.

## Verification and remaining scope

A serial pinned-Go1.26.10 run passed module verification, tidy, vet, staticcheck, and race checks in Archon, Client, Server and tools/builder; the builder has no tests. An initial Archon full run hit duplicate-schema/UNIQUE fixture errors; a serial rerun passed. Concurrent runner fixture collisions are suspected but not established. Focused WebSocket/TLS/credential tests passed. Independent credential review and the corrected WebSocket/TLS re-review passed with no substantive findings. Exact-head CI remains pending at document preparation time.

The three source-only task-sweep/data-integrity findings remain unchanged and are outside this defensive patch's scope. No cloud access, live C2 end-to-end run, production deployment, merge, or release has been performed.
