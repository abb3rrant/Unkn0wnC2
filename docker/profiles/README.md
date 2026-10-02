# HTTP listener profiles

Profiles placed here are mounted into the DNS server containers at
`/opt/unkn0wnc2/profiles`, which is the default `http_profile_dir`.

The image ships `cdn-assets.json` **disabled**, so the containers are DNS-only
until you opt in. To start a listener:

1. Copy `cdn-assets.json` to a new name, or edit it in place.
2. Set `"enabled": true`.
3. Set `bind_port` to the container port the service publishes (8443), matching
   the host mapping: `dns1` is `8445:8443` and `dns2` is `8446:8443`, because
   archon already owns host port 8443 for its own UI.
4. Either use the certificate and pin the image already generated
   (`/opt/unkn0wnc2/certs/http-cdn-assets.{crt,key}`), or generate your own and
   update `tls.spki_sha256` to match it.
5. Restart the DNS server container. The log reports each listener and its bound
   address.

Profiles are re-read every 30 seconds, so URI and status-code changes apply to a
running listener without a restart. Bind address, port and TLS material need a
restart.

Full reference: `docs/http-transport.md`.
