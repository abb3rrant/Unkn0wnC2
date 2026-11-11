# Defensive account and log fixes

This change addresses six web-control-plane findings. It does not change beacon
execution, transports, payloads, network topology, or deployment configuration.

## Authentication and password changes

- HTTP and WebSocket authorization require a persisted session belonging to the
  JWT's operator and JTI, with both session and token unexpired, an unrevoked
  session, and an active account. Signed tokens without a corresponding session
  record are no longer accepted.
- Session authorization reads the persistent state directly, rather than relying
  on a cached revocation result. Current roles still come from the database.
- Login session insertion atomically checks that the verified password-hash
  snapshot is still current and the account remains active. An in-flight login
  cannot create a session from old credentials after a completed password reset.
- Updating a password and revoking that account's existing sessions happen in
  one database transaction. If revocation fails, the password update rolls back.
- A successful self-service password change invalidates the requester's session
  too: sign in again using the new password. No replacement session is silently
  issued. An administrator resetting a different account's password does not
  lose their own session; unrelated accounts remain signed in.
- Cookie/header authentication precedence and CSRF checks are unchanged.

## Account management

- Role changes, disabling accounts, and deleting accounts cannot remove the
  final active administrator. The check is part of the SQLite mutation, not a
  separate stale count checked by the handler.
- Disabled administrators do not satisfy the active-administrator requirement.
  Existing self-delete/self-disable prohibitions still apply.
- Non-admin profile edits omit `role` from the request body. The server continues
  rejecting unauthorized role changes; a disabled form selector is not relied
  upon as an authorization boundary.

## Logs

- Severity metadata is normalized to INFO, WARN, ERROR, or DEBUG at log ingress;
  WARNING maps to WARN and unknown values map to INFO without losing the message.
- Both initial rendering and live append create text nodes for metadata and
  messages. Search highlighting also uses text nodes. Existing stored log
  records do not need rewriting to be displayed safely.
- Log lookup uses the configured log directory and may check a legacy local
  directory for the **same requested source**. A missing server log no longer
  falls back to controller logs. Missing sources return 404; read errors return
  500. The reported filename is the file actually read.

## Verification

The regressions use temporary databases and log files. Coverage includes valid
login, invalid/missing/deleted/revoked/wrong-owner/expired sessions, password
self-change and admin reset through cookie-authenticated HTTP routes, cache-
primed old sessions, rollback on revocation failure, admin-invariant concurrency,
non-admin self-edit authorization, source-preserving log lookup, and literal log
metadata in both rendering paths.

The DOM/form regressions execute the exact checked-in JavaScript with Node.js;
these tests skip when Node is unavailable. Isolated Chromium checks independently
exercise the same log-rendering and self-edit functions. This is focused security
verification, not a claim of full-product or live-deployment acceptance.
