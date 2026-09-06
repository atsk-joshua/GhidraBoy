// SPDX-License-Identifier: MIT
#ifndef GHIDRABOY_MGBA_EXECUTION_PROBE_H
#define GHIDRABOY_MGBA_EXECUTION_PROBE_H

struct mCore;

enum GBProbeBoundary {
    GB_PROBE_EXECUTED, /* One instruction, or one interrupt dispatch. */
    GB_PROBE_IDLE,     /* Only native halted event processing; no opcode. */
    GB_PROBE_FAULT     /* Unsupported entry/pipeline; reset before reuse. */
};

/* Owner thread only. Requires pinned SM83TickNoIdle patch. */
enum GBProbeBoundary gb_probe_boundary(struct mCore *core);

#endif
