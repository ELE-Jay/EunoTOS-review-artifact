# EunoTOS: Anonymous Review Snapshot

This bounded snapshot supplies real archived inputs and production checking
functions, not a script that prints paper-table values. The generated-
configuration records concern an independent, paper-inspired Tenon
reconstruction, not an author-supplied orchestration engine.

## Run Offline

Use CPython 3.11. The required pyelftools dependency and its license are bundled;
no network, model key, private workspace or device is needed.

```sh
cd artifact
python3.11 -S -B tools/eunotos_adoption_replay.py --output ../review-results
```

Alternatively extract `EunoTOS_Minimal_Review_Artifact.zip` and follow its README.
ZIP SHA-256: `86ad2f505fe4e2e2e96985325c4ae0cf621ab872cc80657a518c5e0013b4357b`.

## What Is Reconstructed

- Three-OS message-processing rate, board-input power and energy per completion,
  using original UART bytes and raw meter packets (three recorded resets each).
- The same-record decision comparison: 18 G1 configuration-assembly candidates,
  12 resource requests and six retained-state histories.
- The production reviewed-admission entry's valid/invalid context examples and
  a new-cohort offline declaration that cannot inherit a measured result.

Scope and inputs are documented in [artifact/README.md](artifact/README.md).
The RAM catalog and generation/preflight classifications are authenticated
inputs here, not freshly reconstructed RAM or model experiments. The full
40-input overall score, ESP32 firmware-byte revalidation, raw RAM lifecycle,
fresh acquisition and independent human use are not claimed by this subset.
The real-researcher check remains NOT RUN; its execution template is included.

## Source and Rights

See [artifact/THIRD_PARTY.md](artifact/THIRD_PARTY.md) for the public runtime
source, original TLSF license/linking exception, library patches and notices.
Those materials preserve third-party rights; the benchmark tools are supplied
for review without granting a blanket open-source license to the full project.
No paper draft, credential, full private reproduction archive or original
private provenance map is included.
