# EunoBench: Anonymous Review Artifact

**Updated 2026-11-07.** This is the current, bounded review snapshot. It replaces
the former landing page; the historical replay remains available below.

## Current paper results

- **Eight ESP32 B1 configurations, one common-task leaderboard.** Four categories
  and Overall use **FreeRTOS = 1**. The offline entry recomputes the category
  ratios, overall ranks and the 235 preference profiles from **48 archived
  measurement summaries**, including the correct acquisition-block reference.
- **Figure 1 attribution:** the comparison unit is the complete deployed
  configuration. **Contiki-NG + FreeRTOS** includes actual Contiki job dispatch,
  FreeRTOS host scheduling and IDF/lwIP networking. Task response starts at
  submission, excluding earlier release and ingress waiting. UDP rate is a
  complete transaction; energy and observer RAM cover the declared combined
  deployment. The indices do not isolate Contiki's kernel, native TCP/IP,
  energy or RAM. The private production raw replay reconstructs all 48 inputs
  and 235 preference profiles unchanged. Current public replay additionally
  rejects missing or altered deployment attribution.
- **Table 1:** 70 benchmark-target cells, **5 without qualifying full-subset coverage**.
  The distributed table and coverage index agree cell by cell. Each measured
  cell identifies its cases, configurations and evidence commitments; remaining
  gaps stay explicit. A cross includes measured diagnostics that do not qualify
  for the original OS/subset; it does not necessarily mean no execution exists.
  The current five non-full cells comprise **four N/A subsets** whose required
  native services are absent from the frozen cooperative model, and **one
  partially executed semaphore subset (10/24 original cases)**. Neither is a
  complete-subset check; the universe remains 70 cells, with 65 complete.
  Coverage tests do not replace the common-task
  scoring inputs or change the leaderboard.
- Pi KVM results are additional execution-coverage evidence; they are not mixed
  into the eight-configuration same-board leaderboard. Contiki-NG's hosted
  deployment and each measurement boundary remain explicit in the table.
- **Coverage corrections (2026-11-07):** the withdrawn diagnostic variants stay
  excluded. The four former Contiki **h** kernel-suite marks used
  FreeRTOS services. Contiki zperf used IDF/lwIP, and Pi zperf forwarded socket
  operations to Linux. Contiki PH3 replaced priority/preemptive releases with
  cooperative event dispatch. Pi Thread-Metric core used an adapter-owned queue
  without established native-queue/nonblocking equivalence, so its partial
  native subcases alone did not qualify the full three-case cell. All real runs,
  including these diagnostics, remain preserved privately.
- **Native Thread-Metric completion:** Pi KVM now qualifies the three-case
  subset with a new Tenon **ukmpi mailbox** message image: sixteen owned
  four-word payload buffers, native nonblocking try operations, and executed
  copy, FIFO, caller-overwrite, empty and full controls. Three fresh message
  guests were measured; six valid preemption/semaphore guests were reused.
  The old custom-ring message results are not relabeled or reused as the new
  message result. This fills one cell; it does not change any B1 score.
- **Native guest networking completion:** Pi KVM zperf now executes the
  unchanged TCP and UDP cores with guest lwIP and a virtio NIC. The host is an
  independent peer behind QEMU SLIRP, not a socket RPC service. Three fresh
  guests per protocol, native kernel/dependency bindings and UDP wire totals
  were checked. The **p** mark retains the isolated wakeup/timeout fixes.
  Original 100-Hz UDP pacing achieves a lower rate than its request; coverage
  does not establish a common-rate performance comparison. Previous RPC and
  incompatible-receiver captures remain excluded.
- **Native Contiki networking completion:** the **n** mark qualifies the
  unchanged TCP/UDP cores on Contiki-NG's official **native/Linux** target,
  using its own uIP endpoints, native process/event loop and TUN link. Linux
  supplies the native platform's clock/select/link and an independent peer.
  Three fresh processes per protocol, data-socket ownership, receiver totals
  and the complete UDP finish/statistics exchange were checked. This is
  neither an ESP32 measurement nor a repair of Contiki's hosted B1 network
  score. Four original thread/preemption subsets are structurally inapplicable
  to the frozen cooperative model; no host-thread substitution fills them.
- **Native semaphore partial coverage:** seven unchanged counter cases reuse
  their three archived Contiki native/Linux processes. Three additional
  single-caller timeout cases pass in three new processes. PT_SEM supplies
  counters and available takes; Contiki process protothreads and etimer supply
  the finite wait. The synchronous compatibility facade pumps exactly the
  original native event-loop iteration outside callbacks; it does not supply
  priority threads or a multi-waiter scheduler. Limits, reset, validation and
  return-code mapping remain explicit adapter behavior. Timeouts round up by
  one native tick; the original busy-wait call also uses native clock granularity.
  Empty infinite waits and thread creation fail closed. Early-return, missing
  timer, missing-case and false-full-subset controls are rejected. This is
  **10/24 across two images**, not a full-suite run or a new leaderboard input.
  The other 14 cases remain unexecuted and are named in the index. Six process
  executions contain 30 case invocations; those are not 30 independent experiments.
- Complete semaphore cells marked **a** execute unchanged kernel-mode bodies through a
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

ZIP SHA-256: `4547b8a98b0e16f810e3a3fd85b2e1a4d37caf3059ea25f1062f3b17c43e1386`.

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
