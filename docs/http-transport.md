# HTTP / HTTPS Transport

Unkn0wnC2 beacons can reach their C2 servers over HTTP or HTTPS, in addition to DNS.
A beacon runs in one of three modes, set at build time and changeable at runtime.

| Mode | What travels over DNS | What travels over HTTP |
| --- | --- | --- |
| `dns` (default) | everything | nothing |
| `http` | nothing | everything |
| `dual` | only the A-record task-readiness signal | registration, tasking, chunk fetches, results |

`dns` is the default, so every build made before this transport existed behaves
exactly as it did.

## Why dual mode looks like that

DNS is cheap, quiet and hard to block, but it is a poor bulk carrier: a result
needs many packets, and many packets in a short window is exactly what DNS
exfiltration detection looks for.

Dual mode splits the two roles:

1. The beacon polls with an **A-record query**. The listener answers with the
   configured **task-ready IP** (`poll_task_ip`) if work is waiting, or the
   **ACK IP** (`poll_ack_ip`) if not.
2. On a task-ready signal the beacon makes **one HTTP request** to pull the task,
   then returns results over HTTP.

The A-record signal is a *peek*: the listener reports that work is ready without
consuming it. The HTTP request is the real delivery. That is enforced on the
server side — an A-record `POLL` takes the peek path, and the HTTP request is
processed with TXT semantics, which is the deliver-not-peek path. The result is
that a task cannot be handed out twice and a lost response still triggers
re-delivery.

## Configuring a listener

Listeners are defined by JSON profiles. A profile describes how the listener looks
on the wire, so URIs, header order, status codes and the certificate pin can all be
rotated without rebuil research beacons.

`Server/config.go` (`http_profile_dir`) sets the profile directory, defaulting to
`/opt/unkn0wnc2/profiles`. A missing or empty directory disables HTTP transport
entirely — DNS-only, as before.

A complete example lives in `Server/profiles/cdn-assets.json.example`.

### Profile reference

| Field | Meaning |
| --- | --- |
| `name` | Profile name. Defaults to the file stem. |
| `enabled` | `false` parks the profile without deleting it. |
| `bind_addr`, `bind_port` | Where the listener binds. Defaults `0.0.0.0`, `8443`. |
| `scheme` | `http` or `https`. Defaults to `http`. |
| `host_header` | Host header the beacon sends. Empty uses the connection host. |
| `beacon_host` | Where beacons connect, `host:port`. The listener ignores this key; it exists so the address beacons dial is stated rather than inferred, since it is usually not the bind address. Build requests read it to fill `host`. |
| `tls.cert_file`, `tls.key_file` | Required for `https`. |
| `tls.spki_sha256` | The pin: base64 SHA-256 of the certificate's SubjectPublicKeyInfo. |
| `tls.min_version` | `1.2` (default) or `1.3`. |
| `uris` | `register` / `task` / `result` / `ack` → one or more paths. |
| `methods` | HTTP method per operation. Defaults `POST`, `GET`, `POST`, `GET`. |
| `user_agents` | Pool the beacon picks from, one per transport instance. |
| `headers` | Request headers, **emitted in this order**. |
| `request_body` / `response_body` | Body codec (see below). |
| `auth` | `hmac-sha256` (default), `shared-header`, or `none`. |
| `status` | Status codes for `ok`, `empty`, `not_found`, `error`. |
| `jitter` | Random per-response delay in ms, to break timing correlation. |
| `max_body_bytes` | Response and request size cap. Default 1 MiB. |

Body codecs: `raw`, `base64`, `base36`, `aes-gcm-base64`, `aes-gcm-base36`.
The AES codecs use the same C2 key as the DNS path. `padding_field` with
`pad_min`/`pad_max` adds random padding so body length is not a fixed signature.

Defaults are filled in for anything a profile omits, so a sparse profile is still
a valid listener. `scheme` defaults to `http` rather than `https` because a profile
that omits certificate material cannot be a working HTTPS listener; HTTPS must name
its certificate explicitly.

### URIs and the operation they carry

Message routing happens inside the C2 pipeline, so a path does not fix what a
request means. The operation name decides which configured path a message travels
to:

| Operation | Protocol messages |
| --- | --- |
| `register` | `CHK`, `CHK_META` |
| `task` | `POLL`, `TASKGET` |
| `result` | `RESULT_META`, `DATA`, `RESULT_COMPLETE`, `RESULT` |
| `ack` | `STATUS` |

Several paths per operation let an operator rotate URIs; the beacon picks one at
random per request.

`POST`-style operations carry the message in the request body. `GET`-style
operations carry it in the query parameter named by `request_body.field`, so a
profile with `"field": "d"` produces `GET /api/v1/sync?d=<payload>`.

### Authentication

`hmac-sha256` signs `METHOD\nPATH\nTIMESTAMP\nBODY` with an HMAC key derived from
the C2 encryption key. The signature travels as `<unix-timestamp>.<signature>` in
the configured header.

This proves possession of the C2 key — the same credential the DNS path relies on,
since a beacon that can AES-GCM its subdomain payload can sign a request. No second,
per-beacon secret is introduced, so rotating the C2 key rotates both transports at
once. `max_skew_secs` bounds replay.

The signature covers the path **without** the query string, which is what the
listener verifies against.

### The pin

`tls.spki_sha256` is what makes a self-signed listener trustworthy. The beacon
skips normal certificate verification and instead aborts the TLS handshake when the
presented certificate's SPKI does not match the pin.

Generate a listener certificate and its pin with the server helper:

```go
certPath, keyPath, spki, err := GenerateListenerCert("cdn-assets", "/opt/unkn0wnc2/certs", "cdn.example.com")
```

The listener refuses to start when the certificate it is about to serve does not
match its own pin. Serving a certificate no beacon would accept would otherwise look
healthy while every beacon failed, so this is a startup error rather than a warning.

Rotating a certificate means rotating the pin in the profile **and** in any beacon
build that pinned the old one.

## Listeners and profile assignment

A DNS server is a **listener**: it answers DNS always, and additionally serves the HTTP
profiles assigned to it. You assign profiles in Archon, and the listener applies them —
there is no file to copy to a host and no restart.

- **Listeners page** — every registered listener, with its assignments and what it
  reports it is actually serving.
- **Listener page** — assign and remove profiles for one listener, and see the reported
  state of each, including why one is not running.
- **HTTP Profiles page** — author, validate and store the profiles themselves.

```bash
# what is assigned to a listener
curl -s https://<archon>/api/listeners/<listener-id>

# assign / remove
curl -s -X POST -H "Content-Type: application/json" -d '{"name":"cdn-assets"}' \
  https://<archon>/api/listeners/<listener-id>/http-profiles
curl -s -X DELETE https://<archon>/api/listeners/<listener-id>/http-profiles/cdn-assets

# move live beacons between transports
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"all":true,"mode":"dual","fallback_after_failures":3,"retry_backoff_secs":60,"listeners":[...]}' \
  https://<archon>/api/http/transport
```

### How it reaches the listener

The listener fetches its assignments from an authenticated endpoint every 60 seconds and
reconciles. Reconciliation means:

| Change | Effect |
| --- | --- |
| New assignment | Listener starts |
| URI, header, status code, jitter, body codec | Applied immediately, no rebind |
| Bind address, port, scheme, certificate, pin | That listener rebinds |
| Removed assignment | Listener stops |
| `enabled: false` | Known, but not serving |

The last known assignment stays in force if Archon is unreachable, so a control-plane
outage does not tear down working listeners.

An assignment that cannot start — a port already in use, a certificate missing, a pin
that does not match the certificate — is **reported, not fatal**. The listener keeps
answering DNS, and the listener page shows the reason. This is the opposite of a profile
in the server's own profile directory, which is local configuration and does stop
startup if it is broken.

A profile assigned by Archon wins over a local file of the same name, including on the
file reload ticker, so editing files cannot shadow what the control plane assigned.

## Hot reload

Local profile files are re-read every 30 seconds, and assigned profiles arrive on the
60-second control-plane sync. Both take effect without restarting the process.

Binding address, port and TLS material need the affected listener to rebind, which the
reconciler does on its own.

A local file that fails to parse or validate is rejected and the previous version stays
live, so a bad edit cannot take a listener down.

Binding address, port and TLS material are read at startup; changing those needs a
restart.

## What the listener looks like to a scanner

Anything that is not a valid, authenticated request for a configured URI gets the
profile's `not_found` status with an empty body. A scanner cannot distinguish a wrong
path from a wrong signature from a request that was never C2 traffic, and no probe
reaches the C2 pipeline, so probing cannot create beacon state or tasks.

Requests are rate limited per client address. `X-Forwarded-For` is deliberately
ignored so a client cannot choose its own rate-limit bucket.

## Building a beacon for HTTP

The Archon build request carries the transport:

```json
{
  "transport": "dual",
  "http_fallback_after_failures": 3,
  "http_retry_backoff_secs": 60,
  "http_listeners": [
    {
      "name": "cdn-assets",
      "scheme": "https",
      "host": "cdn.example.com:8443",
      "host_header": "cdn.example.com",
      "spki_sha256": "<pin>",
      "uris": {
        "register": ["/api/v1/ping"],
        "task": ["/api/v1/sync"],
        "result": ["/api/v1/report"],
        "ack": ["/api/v1/ack"]
      }
    }
  ]
}
```

The listener list is embedded in the beacon as JSON — the same document the DNS
server loads — so one profile serves both sides.

## Fallback behaviour

In `dual` mode, `http_fallback_after_failures` consecutive HTTP failures (default 3)
switch the beacon back to the full DNS path. It retries HTTP after
`http_retry_backoff_secs` (default 60) and returns to HTTP on the first success.

In `http` mode there is no fallback: a failure is reported and retried rather than
silently moved onto DNS. An operator who chose HTTP-only does not find half the
protocol on DNS.

## Runtime changes

Transport can be replaced on a live beacon with the same fire-and-forget channel
that carries Shadow Mesh domain updates:

```
update_transport:{"mode":"dual","fallback_after_failures":5,"retry_backoff_secs":30,"listeners":[...]}
```

The beacon applies it and sends no result — a reply would travel on whichever
transport the update just replaced. A payload naming an unknown mode, or one that
produces no usable listener for a mode that needs HTTP, is rejected and the current
configuration stays live.

## Verifying a deployment

1. Start the DNS server with `http_profile_dir` set. Log lines report each listener
   and its bound address.
2. Confirm the listener answers: a request to an unmatched path returns the
   configured `not_found` status with an empty body.
3. Assign the profile to that listener in Archon. Within a minute the listener page
   should show it running, with the address it bound.
4. Build a `dual` beacon, run it, and confirm registration appears in the Archon
   beacon list.
5. Queue a task and confirm the beacon's A-record poll reports task-ready without
   consuming it, then that the HTTP request delivers it.
6. Detach the profile: the listener should stop serving. Re-assign it and it should
   come back without touching the host.
7. Stop the HTTP listener's assignment and confirm the beacon falls back to DNS within
   `http_fallback_after_failures`, then assign it again and confirm HTTP resumes.

## Testing

```bash
cd Server && go test ./...    # profiles, codec, listener, startup wiring
cd Client && go test ./...    # transport, wire shape, pinning, fallback
cd Archon && go test ./...    # build plumbing, including a real beacon compile
```

The Client module takes its configuration from a `config.go` that Archon generates,
and that file is gitignored, so the Client module does not compile from a fresh clone
until a build has produced one.
