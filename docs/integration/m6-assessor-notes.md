# M6 performance assessor receipt

Observed 2026-09-06. This receipt covers the assessor implementation and the already completed frozen macOS soak. The predeclared limits were not changed and no soak was rerun. This is a bounded budget assessment, not Release A qualification or evidence for the current M7 hardware changes.

## Implementation and verification

`tools/assess_performance.py` now requires nonempty matched environment/fixture fields and schema 1, validates finite nonnegative raw measurements and integer counts, computes nearest-rank p95 from samples, and rejects inconsistent supplied summaries. It still requires the predeclared three runs per side and at least 20 samples per metric. Repeating an input path cannot count as multiple runs; distinct file provenance still needs review.

Soak validation requires completed duration/cycles, contiguous per-cycle samples, finite measurements, increasing time/capture/snapshot counters and nondecreasing cumulative primary-trace storage. Counter resets and shrinking storage require separate accounting instead of a misleading negative-growth PASS. Resource diagnostics include every post-warmup rolling three-sample median, full-sample range and ordinary least-squares slope per minute; storage includes every post-warmup interval. These descriptive trends do not introduce a new acceptance threshold after measurement. The original endpoint, storage, pause and event budgets remain unchanged. Every soak result explicitly retains required trend/idle, cleanup, lifecycle-storage and external identity reviews.

CLI exit codes are 0 for budget PASS, 1 for budget FAIL and 2 for INVALID evidence. An invalid report replaces a previous output PASS with INVALID. Output binds measurement input paths and SHA256 values plus the limits SHA256.

Checks run from the GhidraBoy root:

```sh
python3 -m unittest discover -s tools -p test_assess_performance.py -v
python3 tools/assess_performance.py \
  --limits dist/integration-baseline-20260906/m6-soak/declared-limits.json \
  --soak dist/integration-baseline-20260906/m6-soak/session-soak.json \
  --output /private/tmp/ghidraboy-m6-soak-assessment-20260906.json
git diff --check
```

All 12 assessor tests passed, including budget boundaries, nearest-rank recomputation, missing/mismatched identity, invalid/nonfinite values, incomplete/reset counters, mid-run spikes hidden by endpoints, duplicate run paths and CLI exit/output behavior. The retained soak assessment exited 0; the whitespace check passed. No Java, native or runtime changes were made by this work.

## Evidence identity

All five M6 evidence hashes below were independently recomputed and match `handoff-state.json`. The two M7 log hashes in that snapshot also match, without extending their previously stated acceptance scope.

| Input under `dist/integration-baseline-20260906/` | SHA256 |
| --- | --- |
| `m6-harness-build.log` | `6776a6edfcad8c07b82416a3ada1d6d06585b61e7d7d5caf7292eb5d6f429bed` |
| `m6-soak.log` | `88e4734a223ece4a32a2cde4d90af56ece247b184582be0e5048c507424165ab` |
| `m6-soak/declared-limits.json` | `4b0f2aced9b7d8f5bdc3e5a3a257779f29349d3c3a1f4d9532f3458593f554c9` |
| `m6-soak/session-performance.json` | `41add2e1191356eac4ed4b2653c2829071093d7af7fd22dd24aa11ee38887f7b` |
| `m6-soak/session-soak.json` | `7924bead4f3c1355d17067935b351e5bd183e2ee6a3817e9d194e05e4fbdc34d` |

The working `tools/performance_limits.json` still matches the declared-limits hash. Assessor source SHA256: `a55c69caea1411cad04de8c02b7741e4e7814bdccef93844f485d4339c3a134c`. Test source SHA256: `6ece607b85a793d962ec9b12780806e73755eb1ebb31171aae0d2e184cfddda1`.

The generated full assessment is `/private/tmp/ghidraboy-m6-soak-assessment-20260906.json`, SHA256 `3b65c562c2d5556262be7c8d1c25820ce69ec283ca85cbbf2767a92f04d94fdf`. This temporary file is reproducible with the command above; retain it with release evidence before temporary-directory cleanup.

## Bounded result and complete-trend review

The completed 109-cycle, 1,802.203868-second primary-target soak passes all predeclared bounded budgets. Resource windows exclude cycles 1–5 and compare medians of cycles 6–8 with 107–109.

| Check | Observed growth/value | Declared allowance |
| --- | ---: | ---: |
| Agent RSS | +96 KiB | 32,768 KiB |
| Ghidra RSS | +135,600 KiB | 524,288 KiB |
| Agent threads | 0 | 4 |
| Ghidra threads | +4 | 12 |
| Agent handles | 0 | 8 |
| Ghidra handles | 0 | 32 |
| Primary trace bytes/capture | 7,555.73 | 65,536 |
| Maximum pause | 65.041667 ms | strictly below 2,000 ms |
| Maximum reported dropped events | 0 | 0 |

All 104 post-warmup samples contribute to 102 rolling windows per resource and 103 storage intervals. Agent RSS ranges from 36,320 to 36,432 KiB, with slope +2.93 KiB/minute; threads and handles remain 4 and 5. Ghidra RSS ranges from 641,808 to 1,014,800 KiB, with maximum rolling median 1,014,352 KiB and slope +3,708.75 KiB/minute. Ghidra threads range 28–36 (maximum rolling median 34), and handles range 193–194 (maximum rolling median 193). Primary-trace interval growth ranges from 0 to 55,296 bytes/capture. These samples show variable Ghidra RSS and positive overall growth while trace history accumulates; they do not distinguish expected history/allocator growth from leaks or establish an idle plateau.

The retained performance report's supplied summaries agree with independently recomputed p95 values: step reply 38.353459 ms, step capture-ready 38.42275 ms, pause reply 2.103334 ms and pause capture-ready 37.238041 ms. This single report does not supply the required three baseline plus three candidate runs and is not a comparison PASS.

## Scope and remaining blockers

The schema-1 soak report has no embedded host, harness, package, session or process identity. Its association with the frozen pre-M7 macOS candidate relies on the retained handoff/log/report hashes; the candidate archive hash in the handoff was not independently rechecked by this assessor task. External identity binding remains required for promotion.

Review of `RealTraceTest.failureLifecycle` confirms that it saves the primary `trace`, runs separate disconnect/crash/replacement targets, and restores the primary trace in `finally`. The retained primary capture/snapshot/storage counters increase without resets. Thus the primary-trace bytes/capture calculation is coherent, but excludes the lifecycle targets' traces. Ghidra RSS includes shared effects from those targets; the sampled agent RSS covers the original primary process only. Separate target replacements do not demonstrate repeated replacement of the primary measured process.

The log retains `REAL_TRACE_TEST_PASSED`; the original exit-0 observation and absence of the three recorded PIDs remain evidence from the handoff, not a new descendant/process audit. No post-close resource series, full descendant inventory, queue occupancy series or idle-memory plateau is present. Mapping/session-epoch retry warnings, the socket-close diagnostic and the terminal bad-file-descriptor diagnostic remain visible in the original log. This receipt does not infer successful retry of every static binding from the terminal PASS marker.

M6 remains incomplete: collect comparable independent performance runs, resolve static-binding retry/mapping evidence, review idle/cleanup and lifecycle resources, then run final source/artifact-matched package/platform checks and physical GUI acceptance. No predeclared limit was relaxed to obtain the scoped PASS.
