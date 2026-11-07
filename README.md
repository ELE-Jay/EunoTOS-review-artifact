# EunoBench: Anonymous Review Artifact

**Updated 2026-11-07.** This is the current, bounded review snapshot. It replaces
the former landing page; the historical replay remains available below.

## Current paper results

- **Eight ESP32 B1 configurations, one common-task leaderboard.** Four categories
  and Overall use **FreeRTOS = 1**. The offline entry recomputes the category
  ratios, overall ranks and the 235 preference profiles from **48 archived
  measurement summaries**, including the correct acquisition-block reference.
- **Table 1:** 70 benchmark-target cells, **8 without qualifying full-subset coverage**.
  The distributed table and coverage index agree cell by cell. Each measured
  cell identifies its cases, configurations and evidence commitments; remaining
  gaps stay explicit. A cross includes measured diagnostics that do not qualify
  for the original OS/subset; it does not necessarily mean no execution exists.
  Coverage tests do not replace the common-task
  scoring inputs or change the leaderboard.
- Pi KVM results are additional execution-coverage evidence; they are not mixed
  into the eight-configuration same-board leaderboard. Contiki-NG's hosted
  deployment and each measurement boundary remain explicit in the table.
- **Coverage corrections (2026-11-07):** eight cells are excluded from original-OS
  full-subset coverage. The four former Contiki **h** kernel-suite marks used
  FreeRTOS services. Contiki zperf used IDF/lwIP, and Pi zperf forwarded socket
  operations to Linux. Contiki PH3 replaced priority/preemptive releases with
  cooperative event dispatch. Pi Thread-Metric core used an adapter-owned queue
  without established native-queue/nonblocking equivalence, so its partial
  native subcases do not qualify the full three-case cell. All real runs,
  including these diagnostics, remain preserved privately.
- Semaphore cells marked **a** execute unchanged kernel-mode bodies through a
  compatibility API over the target OS's own threads and waits. Adapter-provided
  reset/count-limit/pipe behavior is included; this is not a claim that the
  target supplies an unchanged native Zephyr API. **p** additionally identifies
  the separately patched Tenon wakeup/timeout configuration; its earlier
  unpatched failures remain failures. The common-task deployments, 48 score
  inputs and all 235 preference profiles are unchanged. Their hosted/network
  boundaries do not establish native Contiki or Tenon TCP/IP capability.

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

ZIP SHA-256: `6ebff5ae4f5f11a74047dd60244b9a1c3baa9ed7cb3712a9de9c738ac2ced6c6`.

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
