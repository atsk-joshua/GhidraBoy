// SPDX-License-Identifier: MIT
// Feasibility primitive, not the production adapter ABI.
#include "execution.h"
#include <mgba/core/core.h>
#include <mgba/internal/gb/gb.h>
#include <mgba/internal/sm83/sm83.h>

static bool at_boundary(const struct SM83Core *cpu) {
    // HALT_BUG is the next opcode fetch without PC increment, not a pending
    // micro-operation of HALT. Do not silently consume that next instruction.
    return cpu->executionState == SM83_CORE_FETCH ||
           cpu->executionState == SM83_CORE_HALT_BUG;
}

static void idle(struct GB *gb) {
    // Native GBProcessEvents aligns halted state to FETCH and advances devices.
    // earlyExit prevents its IME+IE fast-forward loop waiting for an interrupt
    // that may never occur. GBProcessEvents consumes/resets earlyExit itself.
    gb->earlyExit = true;
    gb->cpu->irqh.processEvents(gb->cpu);
}

enum GBProbeBoundary gb_probe_boundary(struct mCore *core) {
    struct GB *gb = core->board;
    struct SM83Core *cpu = core->cpu;
    if (!at_boundary(cpu)) return GB_PROBE_FAULT;
    if (cpu->halted) {
        idle(gb);
        return at_boundary(cpu) ? GB_PROBE_IDLE : GB_PROBE_FAULT;
    }
    // Longest ordinary SM83 instruction is six M-cycles. A defensive cap fails
    // closed on unsupported pipeline behavior; it does not invent a boundary.
    for (unsigned ticks = 0; ticks < 8; ++ticks) {
        SM83TickNoIdle(cpu);
        if (cpu->halted) idle(gb);
        if (at_boundary(cpu)) return GB_PROBE_EXECUTED;
    }
    return GB_PROBE_FAULT;
}
