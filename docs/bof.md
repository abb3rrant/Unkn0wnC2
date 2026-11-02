# BOF execution

Beacons can run Beacon Object Files: a compiled COFF object is delivered with a
task and loaded **in-process** by the beacon, with no child process and no file
written to disk.

BOFs are a Windows/amd64 capability. A Linux build answers the task with
`BOF execution needs a windows/amd64 beacon` rather than failing silently.

## Transport rule

A BOF runs only when the beacon's active transport is `http` or `dual`.

The object has to reach the beacon inside the task, and a DNS-carried task is
chunked into ~400-byte subdomain labels — slow, noisy and pointless for anything
larger than a few hundred bytes. Two independent checks enforce it:

- **Archon** refuses to queue a BOF for a beacon it knows is DNS-only (recorded
  when the dashboard last applied listeners, or the build's transport).
- **The beacon** refuses the task unless its live transport is http/dual. The
  beacon is the authority: an operator can move a live beacon with
  `update_transport`, and only the beacon knows where it is now.

## Using it

Beacon page → **Run BOF**:

1. Choose a `.bof` / `.o` file (max 512 KiB decoded).
2. Optionally give arguments — they are passed as a NUL-terminated string with
   the length, matching the Cobalt Strike convention.
3. **Run BOF**, then read the result in the task list like any other task.

The response is the object's own output, captured from `BeaconOutput` and
`BeaconPrintf`. A BOF that prints nothing reports "completed with no output"; a
BOF that fails reports its output followed by the error.

## Task format

The operator surface is the dashboard, but the task itself is a normal task:

```
bof:{"name":"whoami.o","args":"-v","data":"<base64 COFF>"}
```

`data` is the object; `args` is optional. The beacon dispatches on the `bof:`
prefix before it considers shell execution, so a BOF can never be mistaken for a
command line.

## What the loader supports

| Area | Support |
| --- | --- |
| Sections | Laid out in one allocation, 16-byte aligned; discardable sections (`.drectve`, debug) skipped |
| Relocations | `ADDR64`, `ADDR32`, `ADDR32NB`, `REL32`…`REL32_5`, `SECTION`, `SECREL` |
| Entry point | symbol `go`, then `_go`, `bof_main`, `main` |
| Memory | `VirtualAlloc` (RW) → copy → per-section `VirtualProtect` (RX for code, R for read-only data, RW otherwise) |
| Imports | Beacon API subset below, then `kernel32`, `ntdll`, `user32`, `advapi32`, `ws2_32`, `ole32`, `shell32` exports by name (also accepts `module!function`) |

Beacon API implemented: `BeaconOutput`, `BeaconPrintf`, `BeaconDataParse`,
`BeaconDataInt`, `BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`,
`BeaconDataPtr`, `BeaconIsAdmin` (always 0).

Declared but non-functional (they resolve so the object still loads, and return 0):
the `BeaconFormat*` family, `BeaconUseToken`, `BeaconRevertToken`,
`BeaconGetSpawnTo`, `toWideChar`. An object that depends on them will run but not
produce the output or side effect it expects.

Result output is capped at 256 KiB per BOF so a runaway object cannot flood the
result path.

## Limits and risks

- **In-process means in-process.** A BOF that faults takes the beacon with it.
  There is no sandbox and no separate thread with its own guard page.
- The loader is **amd64 only**. An arm64 object is rejected with a specific
  message rather than loaded incorrectly.
- Nothing is written to disk: the object lives in memory for the duration of the
  call and the allocation is not freed (the beacon is short-lived by design, and
  freeing memory an object may still reference is worse than leaking it).
- Process-creation telemetry does not apply, which is the point — but in-memory
  COFF loading is itself a well-known detection surface. Use deliberately.

## Testing boundary

`Client/testdata/sample.bof` is a real object built by mingw and used by both the
Archon and Client tests, so the object the API accepts is the object the loader
parses. Unit tests cover the envelope, limits, machine check, transport guard and
the response of a build without the loader.

`go vet` on the `windows/amd64` build reports "possible misuse of unsafe.Pointer"
for the loader's native boundary: the `VirtualAlloc` base and every callback
argument the object hands back as a `uintptr` (`BeaconOutput` data, `BeaconDataParse`
buffers). Those conversions are unavoidable when a Go process hosts native code —
there is no `unsafe` form that expresses them without a `uintptr`. Address
arithmetic inside the loader was refactored so the *only* conversions are those
boundaries, and each was audited by hand. CI vets the linux build, where this file
is excluded by its build tag.

**Executing a BOF has not been verified on a Windows host yet** — the loader builds
and its parsing is exercised, but no object has been run in-process. Treat first
use as a lab exercise: start with an object that only calls `BeaconOutput`.
