# EunoBench: Anonymous Review Artifact

**Updated 2026-11-07.** This is the current, bounded review snapshot. It replaces
the former landing page; the historical replay remains available below.

## Current paper results

- **Eight ESP32 B1 configurations, one common-task leaderboard.** Four categories
  and Overall use **FreeRTOS = 1**. The offline entry recomputes the category
  ratios, overall ranks and the 235 preference profiles from **48 archived
  measurement summaries**, including the correct acquisition-block reference.
- **Table 1:** 70 benchmark-target cells, **0 still unmeasured**.
  The distributed table and coverage index agree cell by cell. Each measured
  cell identifies its cases, configurations and evidence commitments; remaining
  gaps stay explicitly unmeasured. Coverage tests do not replace the common-task
  scoring inputs or change the leaderboard.
- Pi KVM results are additional execution-coverage evidence; they are not mixed
  into the eight-configuration same-board leaderboard. Contiki-NG's hosted
  deployment and each measurement boundary remain explicit in the table.
- Contiki thread suites marked **h** use actual Contiki process dispatch with
  host-provided priority threads, IPC and IRQ services. Their execution coverage
  does not establish native Contiki preemption or replace the cooperative Contiki
  configuration in the common-task leaderboard.

### Run the current offline check

Use CPython **3.11**; no installation, model key, network or device is needed.

```sh
cd artifact
python3.11 -S -B tools/replay_current.py --output ../current-results
```

This writes `leaderboard.csv`, `coverage.csv` and `receipt.json`. Successful replay
checks the supplied summaries and index; it does **not** reacquire raw hardware
data, establish new adapter equivalence or independently reconstruct the full
RAM lifecycle. Full private captures, firmware and new coverage validators are
not in this bounded copy. The coverage index supplies source commitments and
case/configuration bindings, not public access to every committed source file.

Browse [the current inputs and Table 1](artifact/current/) or
[the precomputed current output](results/current/).
Download [EunoBench_Review_20261106.zip](EunoBench_Review_20261106.zip), extract it,
and run the same command from its root (the ZIP contains the artifact contents).

ZIP SHA-256: `d9ac6339b33da61702af92ddfdead2fa43ebd161f9e8de74b6ab28800812f380`.

## Preserved historical raw-evidence replay

```sh
cd artifact
python3.11 -S -B tools/eunotos_adoption_replay.py --output ../legacy-results
```

This separate entry replays the original three-system message-energy subset,
18 G1 configuration candidates, 12 resource requests and six retained-state
histories. These are historical cohorts, not additional independent samples in
the current leaderboard. The generated-configuration records concern an
independent, paper-inspired Tenon reconstruction, not an author-provided
orchestration engine. Saved RAM profiles and generation/preflight classifications
remain inputs to this limited replay.

The prior `EunoTOS_Minimal_Review_Artifact.zip` is retained unchanged for version
comparison. Its README describes that older snapshot, not current coverage.
Independent human use remains **NOT RUN**. See
[artifact/README.md](artifact/README.md) for the full scope and boundaries.

## Source and rights

See [artifact/THIRD_PARTY.md](artifact/THIRD_PARTY.md) for upstream source,
TLSF licensing/linking exceptions and notices. Only this selected redacted
review copy is authorized for distribution; it does not grant a blanket
open-source license to the project. No manuscript draft, credential, original
private provenance map or full private reproduction archive is included.
