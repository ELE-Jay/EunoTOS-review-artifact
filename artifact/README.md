# EunoBench Review Artifact — 2026-11-06

The current extension in `current/` reproduces the eight-configuration score arithmetic (48 measured scalars, FreeRTOS = 1, 235 preference profiles) and Table 1 coverage status. Run `python3.11 -S -B tools/replay_current.py --output ../current-results`. These are archived measurement summaries and coverage commitments, not a new raw-data replay. New coverage captures and full resource evidence remain private.

The following historical subset and its replay are preserved. Its 40-input exclusion refers to the former mechanism leaderboard, not the current 48-input common-task score.

# EunoTOS Minimal Review Artifact

## Scope

This is a bounded, offline evidence-replay subset, not the complete benchmark or
a new measurement campaign. It rebuilds a three-OS message-processing energy
table (FreeRTOS, Zephyr, NuttX; three recorded resets each), and the manuscript's
same-record decision-increment table (18 G1 configuration-assembly candidates,
12 resource requests, six histories). It uses saved inputs, not paper-table
values. No measured result is supplied as a hardcoded expected output.

The adapter calls the production `paired_trace`, `qualify_cell`,
`build_identity`, `guest_outcome`, `constraint_outcome`, `admitted`,
`summarize_accounting`, `clock_endpoint`, and reviewed resource-admission entry.
It does not execute acquisition, model APIs, guest boots, or compiler commands.

Not covered: the full 40-input overall score, ESP32 firmware-byte revalidation,
raw RAM lifecycle reconstruction, or generation/Kconfig preflight reconstruction.
Saved generation/preflight classifications and the reviewed RAM catalog are
authenticated inputs to this subset, not newly established measurements. The
source/image/board bindings remain declared and checked for consistency; this
subset does not independently certify adapter equivalence or a hardware identity.
Do not use it to qualify a new measured cohort or assign it a score.

## Requirements and Quick Start

Use CPython **3.11**. The transitive production-module dependency pyelftools is
vendored, with its recorded version and license; all other imports used by this
replay are standard-library imports. No pip install, credentials, network,
hardware, original workspace, private SDK, or account is required. Isolation
checks disable installed site packages as well as hiding the original workspace.

From the extracted artifact root:

```sh
python3.11 -S -B tools/eunotos_adoption_replay.py --output ../review-results
```

The output path must be new and outside the artifact. Exit code zero and
`receipt.json: pass=true` indicate successful replay, not independent human
replication. The command verifies every `SHA256SUMS` member before reading inputs;
missing, changed, or extra inputs fail closed. It must not repair inputs for you.

Outputs:

| File | Meaning |
| --- | --- |
| `message-energy.csv` | Reset-median rate, board-input power, and energy per original completion |
| `decision-increment.json` | Original-output versus request checks; native versus full decisions; accepted edits versus retained-state compliance |
| `admission-controls.json` | Real reviewed-admission entry: valid binding; changed flags, workload, observer, missing context; unmeasured cohort |
| `receipt.json` | Explicit scope, exclusions, no new hardware/model runs |

To check the hash guard, make a disposable copy, change one capture byte or remove
one manifest-listed file, and run the same command against a new output path. It
must return nonzero before producing result tables. Do not change `SHA256SUMS` to
make a damaged copy pass. A hash manifest authenticates the distributed snapshot,
not the authors' institutional identity or an external signature.

## Data Dictionary and Measurement Boundaries

`artifacts/reports/esp32-message-energy-b1-v1/` contains UART bytes, JSONL capture
records, raw HID packets, power CSVs, metadata, and saved source/image bindings.
The raw UART bytes must decode to the recorded lines with their chunk hashes.
HID packet voltage/current values must match CSV values. Fixed campaign polarity
is applied once, not an absolute value per sample. Two original steady windows
pair completed counts and integrated board-input energy. Reset summaries are
aggregated by the existing production function. `counts_per_s` is original
Thread-Metric message work per second, `energy_uj_per_count` is microjoules per
original completion, and `power_w` is watts. This is whole-board input energy,
not MCU-only power or a calibration certificate.

G1 tasks, resolved configurations, build identities and raw guest stdout/stderr
support original-output and requested-policy decisions. Build/image/config and
guest-receipt hashes are checked. G1 output completion alone is not behavioral
qualification. Generation/preflight is not rerun by this subset.

Resource-history records preserve every request, rejection, parent, retained
configuration and original clock. Recorded preflight results feed the same stage
reducer; runnable configurations and original guest outputs are rechecked. The
catalog is the declared **matched observer-inclusive peak allocated capacity**,
not uninstrumented deployment RAM. Its values are inputs here; rebuilding raw
memory observations needs the complete private evidence bundle. Catalog reuse
does not add independent RAM samples. Final-state compliance uses the latest
request, not a changed historical verdict. Outer history elapsed time is retained;
it is not replaced by a sum of round durations.

## Valid, Invalid, and New-Cohort Examples

`review.json` binds one existing reviewed build and context. Only the derived
copy's path-redacted support-file hashes are rebound; this is not a claim that
these extra checks ran during historical acceptance. The production matcher uses
the frozen catalog as an explicit input; it does not reacquire RAM. An unchanged
build/context is qualified. Changed build flags, workload, observer, or missing
required context return `review_required`, with no inherited energy or new RAM
sample. These are selected cases from the existing finite boundary controls.

`cohort-declaration.json` is an editable offline declaration example. A reviewer
may replace board/serial/build/contract names, but cannot enable acquisition or
claim a measured result through this example. The real entry rejects its unknown
context. Real acquisition requires reviewed native mapping, image/board binding,
new raw captures and applicable resource evidence. Old identity guards remain.

## Anonymity, Rights, and Provenance

This derived snapshot removes author-specific absolute source paths from text
copies. Original private evidence is unchanged. New distributed hashes are in
`SHA256SUMS`; the original-to-derived transformation map is retained privately.
Runtime-image bytes used in the generated-configuration checks are not edited.
Historical receipts remain historical; this replay creates separate outputs.

The owner has authorized publication of this specific anonymous review snapshot;
no general open-source license is granted for the full project. Third-party
source and notices retain their existing licenses. Archived Tenon runtime images
are included for generated-configuration identity checks; no ESP32 SDK or
firmware image is bundled. `THIRD_PARTY.md` identifies the upstream TLSF dual
licensing/linking exception and the supplied public kernel, application, library
source and patches. It separates source-material checks from an unperformed
executable-relink test. An anonymous hosting endpoint is not implied by preparing
this package; access is available only after the endpoint has actually been
published and verified.

## Independent Use

Give `PARTICIPANT_CHECK.md` to a real researcher who did not develop the core
tool. Record their commands, environment, errors and explanations, without
coaching them through unrecorded repairs. A new container or an agent-run replay
is not an independent human user study. Until such a person executes it, this
part remains **NOT RUN**.
