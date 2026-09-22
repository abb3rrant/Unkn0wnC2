# Unkn0wnC2 — Testing Guide

How to build and run the Unkn0wnC2 test suites, from unit tests through the
full Docker end-to-end (E2E) stack. This is the reference manifest for the
issue-agent graph's `verify` stage.

## Overview

Four tiers of testing:

| Tier | Scope | Where it runs | Gate |
|------|-------|---------------|------|
| Unit | Go tests per component (`Archon/`, `Client/`, `Server/`) | Go 1.25.14 toolchain | `go test` |
| HTTP transport E2E (Docker) | HTTPS listener, custom profiles, HTTP-only beacon, task/result, runtime push | `docker-wk` | `run-http-transport-tests.sh` |
| Integration (Docker) | Live C2 stack: beacon check-in, task exec, Shadow Mesh | `docker-wk` | `run-tests.sh` |
| Extended E2E (Docker) | DNS comms malleability, edge cases, all phase configs | `docker-wk` | `run-extended-tests.sh` |

The Docker tiers are the definitive validation. They build Archon, two listener/DNS
servers, DNS and HTTP-only beacons, and verify real control-plane behavior over
both transports.

---

## Prerequisites

- Docker + Docker Compose v2 on the test host. Authorized host for this org:
  `docker-wk.thebitcrypt.net` (Docker 20.10, Compose v2).
- Source tree with the `docker/` directory (the Compose file and Dockerfile
  build from the repo root as context).
- ~2 GB free disk. Compose images use a digest-pinned Go 1.25.14 base and pull Go module
  deps on first build (subsequent builds are cached).
- `jq`, `curl`, `sqlite3` — present inside the containers, no host install needed.

---

## Tier 1 — Go unit tests

Each of `Archon/`, `Client/`, `Server/` is its own Go module.

```bash
cd Archon && go test ./...        # control plane, DB, builder
cd Client && go test ./...        # beacon transports, framing, deduplication
cd Server && go test ./...        # listener, DNS/HTTP, chunking, mesh behavior
cd tools/builder && go test ./... # standalone builder utility
```

All modules build and test from a clean checkout with Go 1.25.14+. `Client/` ships
an inert `config_default.go` solely for compilation and tests. Archon writes
`config.go` and builds with the `generated` tag for every deployable beacon, so
the development configuration can never be included in an operator build.

---

## Tier 2 + 3 — Docker E2E on `docker-wk`

> **Critical:** `setup` builds the DNS servers and beacons through the live
> Archon builder API **inside** the stack. Running the test services via
> `docker compose run` re-triggers `setup` (a transitive dependency) unless you
> pass `--no-deps` — and a re-run `setup` fails with `Text file busy` because
> the running DNS containers hold the rebuilt binaries open. **Always bring the
> stack up once, then run tests with `--no-deps`.**

### 1) Bring up the core stack (this runs `setup` exactly once)

```bash
export ENCRYPTION_KEY=$(openssl rand -hex 32)
export JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_PASSWORD=$(openssl rand -hex 24)
COMPOSE="docker compose -f docker/docker-compose.yml"

$COMPOSE up -d archon dns1 dns2 client http-client setup
```

`setup` logs in to Archon, builds via the builder API, and writes binaries to
the shared `builds` volume:

```
builds/beacon                baseline beacon (alpha.test, dns1)
builds/beacon-http           HTTP-only beacon (custom HTTPS profile, dns1 listener)
builds/beacon-mesh           Shadow Mesh beacon (bravo.test, dns2)
builds/beacon-a-record       Go A-record polling client
builds/beacon-unencrypted    Go base36-only client (no AES)
builds/beacon-staged         Go staged-registration client
builds/dns-server-1          DNS server 1 (alpha.test, 172.20.0.11)
builds/dns-server-2          DNS server 2 (bravo.test, 172.20.0.12)
```

Wait for `setup` to finish (it exits when done):

```bash
# until `docker compose ps` no longer shows a `setup` service:
while docker compose -f docker/docker-compose.yml ps --format '{{.Service}} {{.State}}' | grep -q '^setup'; do
  sleep 5
done
```

Verify the stack is healthy:

```bash
$COMPOSE ps
# archon should show "healthy"
$COMPOSE exec -T archon ls /opt/unkn0wnc2/builds/   # all 6 beacon + 2 dns-server binaries
```

### 2) Run the HTTP transport E2E suite

```bash
$COMPOSE --profile http-test run --rm --no-deps http-test
```

Exercises the live HTTPS listener, camouflage responses, custom response headers,
omitted headers, profile CRUD validation, an Archon-built HTTP-only beacon using
an authoritative ordered request-header profile, a benign command/result round
trip, and runtime transport-update queueing.

A successful HTTP-only check-in also proves the listener accepted the enforced
`X-Profile` request fingerprint and that the beacon verified the generated SPKI
pin. Expected: **ALL TESTS PASSED (14/14)**.

### 3) Run the Integration suite

```bash
$COMPOSE --profile test run --rm --no-deps test
```

Exercises: Archon web UI health, Go beacon check-in, task creation + result
(`whoami` → `root`), and Shadow Mesh multi-beacon sync via DNS2.

Expected: **ALL TESTS PASSED (6/6)**.

### 4) Run the Extended E2E suite

```bash
$COMPOSE --profile extended-test run --rm --no-deps extended-test
```

Exercises: A-record polling, unencrypted (base36) comms, staged registration,
large-result exfiltration (chunked), rapid consecutive tasks, minimal-output
edge cases, special characters, and multi-beacon/domain failover.

Expected: **ALL TESTS PASSED (14/14)** (some beacons may be reported `SKIP` only if a
specific variant binary did not build; a failed required test fails the run).

### 5) Teardown

```bash
$COMPOSE down --remove-orphans --volumes
```

Always tear down after a run. The `--volumes` flag clears the shared `builds`
and `archon-data` volumes so the next run starts from a clean state (avoiding
stale beacon registrations or `Text file busy` collisions).

---

## Exit codes

- HTTP transport suite: exit `0` on ALL PASS, non-zero if any test failed.
- Integration suite: same.
- Extended suite: same.
- `setup`/`up` failures return non-zero and must block any test interpretation.

Treat skipped/timed-out/unavailable stages as **incomplete**, not passing.

## Secrets & data handling

- Compose refuses to start unless `ADMIN_PASSWORD`, `ENCRYPTION_KEY`, and
  `JWT_SECRET` are supplied. Generate disposable values for each run as shown
  above; never reuse production credentials.
- Never place real `.env`, private keys, or production credentials in the
  Compose environment or test scripts.

## Troubleshooting

- **`Text file busy` during `setup`:** you ran a test service without
  `--no-deps` (or re-ran `setup` while dns containers were up), so `setup`
  tried to overwrite a DNS-server binary that the running `dns1`/`dns2`
  containers had open. This is a **known pitfall** — always run the suites with
  `--no-deps`, and if it happens, tear down fully (`down --volumes`) and bring
  the stack up fresh once. A half-run `setup` also rotates dns1's credentials,
  causing `401 invalid credentials` in dns1 logs and a failed beacon check-in.
- **Beacon check-in fails (0 beacons):** usually the `Text file busy` half-run
  above left dns1 with stale/rotated credentials. Full teardown + fresh up.
- **`setup` "Login failed":** Archon wasn't healthy yet; the stack healthcheck
  handles this, but ensure `archon` shows `(healthy)` before running tests.
- **Port 8443 in use on host:** `archon` binds `8443:8443`; stop the conflicting
  service or change the port mapping in `docker-compose.yml`.
- **Zero-output task misreported as timeout:** fixed in `run-tests.sh` /
  `run-extended-tests.sh` — `wait_result` now gates on the task's terminal
  `status` (via exit code) rather than non-empty `.result`, so `true` / bare
  `echo` tasks that complete with empty output pass correctly.

---

## Graph integration notes

For the issue-agent graph, this document is the reviewed `Unkn0wnC2` test
manifest. The `verify` stage must:
1. Run Tier 1 unit tests where they build standalone (`go test ./...` in
   `Archon/` and `Server/`; `Client/` coverage comes via the Docker E2E path).
2. Bring up the Docker stack once, then run HTTP transport, Integration, and
   Extended suites with `--no-deps`.
3. Teardown (`down --volumes`) unconditionally; cleanup failure blocks success.
4. Treat the candidate branch/commit SHA as the build source (not base).
