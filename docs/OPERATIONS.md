# Unkn0wnC2 Operations Wiki

Operational reference for the Unkn0wnC2 C2, its listeners and beacons, the Wraith
NativeAOT beacon (separate repository), and the lab mesh used to test them.

> Scope: how to build, deploy, configure, operate and troubleshoot. Engagement
> specifics do not belong here.

---

## 1. Architecture

```
                 +--------------------+
   operator ---> |  Archon (REST+UI) |  :8443   control plane, SQLite master DB
                 +---------+----------+
                           |  reports / task sync / format push (async)
        +------------------+-------------------+
        |                  |                   |
   +----v----+        +----v----+         +----v----+
   |  DNS 1  |        |  DNS 2  |         |  DNS 3  |   each: DNS :53 + optional HTTP listener
   +----+----+        +----+----+         +----+----+
        \__________________|___________________/
                     shadow mesh (domains)
                           |
                    beacons (DNS / HTTP / dual)
```

Two planes matter operationally:

- **Control plane (Archon)**: operator API, task queue, beacon records, catalog,
  profiles, cover sites. Never on a beacon's query path.
- **Data plane (listeners)**: answer DNS/HTTP immediately from local state. A
  listener decodes, authorises and returns a task without calling Archon.
  Archon reports and format pushes are asynchronous.

Breaking the data plane (an Archon call inside a DNS answer) breaks recursion
timeouts, so all per-query state must be local: encryption key, payload formats,
phase configs, beacon records.

---

## 2. Repositories and layout

| Path | What |
|---|---|
| `Archon/` | control plane (Go, own `go.mod`) |
| `Server/` | DNS/HTTP listener (Go, own `go.mod`) |
| `Client/` | Go beacon |
| `docker/` | compose, Dockerfiles, entrypoints |
| `docs/OPERATIONS.md` | this document |

Wraith lives in its own repository (`The-BitCrypt/Wraith`) and is **never**
vendored here.

---

## 3. Building

### 3.1 Beacons and listeners (Go)

```bash
# listener + control plane images
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml up -d
```

The builder in the UI/API (`POST /api/builder/client`) compiles a beacon with the
requested config baked in. Key fields:

| Field | Meaning |
|---|---|
| `dns_domains` | mesh domains the beacon rotates over |
| `resolver` | `ip:port`; empty = system resolver |
| `transport` | `dns`, `http`, `dual` |
| `http_listeners` | embedded profile documents for HTTP/dual |
| `payload_format` | global template (declared to the C2) |
| per-phase `payload_format` | template actually used on the wire per phase |
| `staged_registration` | CHK split into S1/S2/S3 |
| `encrypted` | AES-GCM vs plain base36 |
| `result_transport` | `auto` / `http` / `dns` |
| `checkin_dns_weight` / `checkin_http_weight` | dual split (default 2:1) |

**Known gap:** the builder currently writes the global `payload_format` but not
per-phase formats, so a formatted Go build does not decorate its queries. Wraith
handles this with a poll-phase fallback.

### 3.2 Wraith (NativeAOT, Windows)

```powershell
.\build.ps1 -Config .\config.lab.json -BuildMode nativeaot -EvasionProfile aggressive `
            -OutputPath C:\wraith\out
```

- Requires the .NET 9 SDK and VS Build Tools (MSVC + Windows SDK).
- `-BuildMode managed` produces a JIT single-file build **for diagnosis only**
  (named stack traces); never ship it.
- `-Trace` defines `WRAITH_TRACE`: `DnsTransport` sends are written to
  `%TEMP%\wraith-trace.log` (SYSTEM: `C:\Windows\SystemTemp\`). Without the
  switch the call sites are compiled out.
- `compiled/` (BOF `.o` files) is gitignored; run `grimoire/compile_all.sh`
  (mingw) before building a registry.

---

## 4. DNS servers and the shadow mesh

Each DNS server answers on `:53` for one or more authoritative domains and may
also host HTTP listener profiles.

- **Domains**: add to the DNS server config; beacons rotate across all of them.
- **Mesh resolver** (`dnsmasq` in the lab): forwards each mesh domain to its
  authoritative server; beacons point at it (`resolver`).
- **Per-beacon contact history** is recorded per `(dns_server_id, dns_domain)`,
  which is what proves rotation and transport class.
- **A-record modes**: `a_record_ack_ip` / `a_record_task_ip` let an A query carry
  a signal (task pending -> beacon fetches over HTTP).

### 4.1 Payload formats (decorated subdomains)

A template such as

```
cdn-XXXXXXXX-XXXXXXXX.asset-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.edge-XXXX...
```

places base36 data in `X` slots and keeps decorators verbatim. Rules:

- label <= 63 chars, FQDN <= 253.
- the client stops as soon as the data ends, so the emitted subdomain is a
  **prefix** of the template (no padding).
- the listener strips decorators by walking template and subdomain together and
  stopping when either ends.

**How a listener learns a template**

| Source | Applies to |
|---|---|
| `CHK_META` (beacon-declared) | that beacon, on the server that handled it |
| format push from Archon on check-in | every listener |
| build configs | Go beacons built by Archon |

Externally built beacons (Wraith) use the *declared* path plus the push. A
decorated beacon that starts before the push lands will be unreadable on servers
that have not seen the template, so Wraith keeps plain labels for 10 check-ins
after `CHK_META` before switching.

---

## 5. Beacons

- **Identity is process identity**: a restarted beacon is a new beacon; a dead
  beacon cannot be resumed.
- **Transports**
  - `dns`: TXT payloads; chunked tasks (`TASKC` + `TASKGET`).
  - `http`: one request per operation; task is a single `TASK|id|cmd`.
  - `dual`: registration probes **both**; both OK -> dual, one OK -> latch
    (no silent auto-promotion), neither -> error.
- **Check-in selection (dual)**: one endpoint per check-in, weighted by class
  (default DNS 2 : HTTP 1), uniform inside the class.
- **Fallback**: an HTTP check-in that fails degrades to DNS for that check-in;
  after N failures the beacon backs off for `retry_backoff_secs`.
- **Results** honour `result_transport`; chunk size follows the transport that
  will actually carry the frame (an HTTP-sized frame must never be handed to DNS).
- **Staged registration**: `CHK|id|S1|name`, `S2|hostname|os`, `S3|user|arch`,
  then `CHK_META`. Non-staged registration sends one full CHK and then
  `CHK_META`.

---

## 6. HTTP listeners and profiles

A profile is a JSON document: `bind_port`, `beacon_host`, `scheme`,
`beacon_scheme`, `user_agents`, `request_headers`, `auth`, `uris`, `methods`,
body codecs, `timeout_secs`, `max_body_bytes`, optional site.

- `scheme` is what the listener serves; `beacon_scheme` is what the beacon dials
  (Cloudflare Flexible SSL: serve `http`, dial `https`, no pin).
- **Header fingerprint** is enforced: `Accept`, `Accept-Language`,
  `User-Agent` must match the profile. A mismatch returns 400 and the beacon
  latches to DNS. Mirror the profile exactly in the beacon build.
- **HMAC** (`X-Sig`): `hex(HMAC-SHA256(key = HMAC-SHA256(aesKey, "unkn0wnc2-http-v1"),
  msg = METHOD\nrequest-target\ntimestamp\nbody))`, value `timestamp.signature`.
  Clock skew tolerance is 60 s: a drifted beacon host silently 401s.
- **Cover site**: static files attached to a profile, served only for paths the
  profile's URI table did not claim. C2 traffic can never be shadowed.
- **Transport push** (operator): `POST /api/http/transport` with
  `{beacon_id|all, mode, listeners[], weights}`. Fire-and-forget: no reply.
  Applied atomically; invalid payloads are rejected before queueing.

---

## 7. Wraith

Separate NativeAOT beacon; integrates over the wire protocol only.

- **Name**: `WRAITH#` (neutral). The **number** is assigned by Archon.
- **Catalog**: each distinct declared template becomes `WRAITH#1`, `WRAITH#2`, ...
  A rebuild with the same template reuses its number. The beacon never knows it.
- **Bootstrap**: plain labels + `CHK_META` declaring the template, then decorated
  labels after 10 check-ins.
- **BOFs**: embedded registry (`bof:list`, `bof:<name> [args]`) and
  operator-uploaded (`bof:{"name","args","data"}`) through
  `POST /api/beacons/{id}/bof`.
  - uploaded objects are validated for base64, <= 512 KiB, COFF x86-64 and a
    `go` symbol before the loader runs;
  - BOFs run only on `http`/`dual` transports; `dns` is refused;
  - args are a NUL-terminated buffer with its length (Go convention).
- **Transport updates**: the same `update_transport:` tasks as Go beacons.
- **Spawn mode** degrades to inline when a host refuses threads or process
  attributes; the BOF still runs.

---

## 8. Tasks, results, exfil

- Create: `POST /api/beacons/{id}/task` `{beacon_id, command}` -> `task_id`.
- Delivery: first check-in across any listener presents the task; DNS chunk
  state lives on the server that delivered it (clients must pin `TASKGET`).
- Completion: `MarkTaskCompleteFromBeacon` is the only writer of `completed`.
- Fire-and-forget commands (`update_domains:`, `update_transport:`) do not
  expect results.
- Exfil: `exfil <path>` runs as a background job; chunks are carried by the
  data-exfil phase and reassembled by the master.

---

## 9. Runbook

**Add a listener profile**
1. `POST /api/http/profiles` (document).
2. Assign it to a DNS server: `POST /api/listeners/{id}/http-profiles {name}`.
3. Restart/reload the listener (or wait for the sync) and confirm it binds.
4. Push the listener to live beacons with a transport update.

**Add a domain**
1. Register it on the DNS server.
2. Update the mesh resolver.
3. `update_domains:` to beacons (persisted before transport changes).

**Recover a beacon that stopped checking in**
1. Contact history: which class and endpoint last answered?
2. `status` task if it still polls; otherwise check the listener logs for auth or
   decode failures.
3. Remember: restarting the beacon creates a *new* beacon.

---

## 10. Troubleshooting (observed in the lab)

| Symptom | Cause | Fix |
|---|---|---|
| HTTP 401 `timestamp outside the 60s tolerance window` | host clock skew | sync the beacon host clock |
| HTTP 400 `Accept does not match the profile` | beacon headers drift from profile | mirror `request_headers` exactly |
| `invalid base36 string` on decorated queries | listener has no template yet (rotation) | wait for the format push; keep plain bootstrap |
| transport update rejected `unknown transport mode "hmac-sha256"` | naive JSON field scan hit `auth.mode` | parse JSON scope-aware |
| updates never land on a >1-chunk task | `TASKGET` rotated to a server without chunk state | pin per domain and try each |
| `OutOfMemoryException` on a `[Spawn]` BOF | host refuses threads/attributes | run inline |
| `entry point 'go' not found` | object is shellcode, not a BOF | exclude / reject at upload |
| new Wraith layout numbered `#62`/`#94` | SQLite AUTOINCREMENT burns ids on conflict | allocate `MAX(id)+1` in a transaction |
| beacon dies immediately on startup | generated stub dereferenced a null block | guard the call |

---

## 11. Known gaps / operator-requested UI ideas

Filled in by the QA pass; see the UI findings section of the QA report.
