// SPDX-License-Identifier: MIT
#include "execution.h"
#include <mgba/core/core.h>
#include <mgba/core/timing.h>
#include <mgba/gb/core.h>
#include <mgba/internal/gb/gb.h>
#include <mgba/internal/gb/io.h>
#include <mgba/internal/gb/serialize.h>
#include <mgba/internal/sm83/sm83.h>
#include <mgba-util/vfs.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(c, message) do { if (!(c)) { \
    fprintf(stderr, "FAIL: %s (line %d)\n", message, __LINE__); exit(1); \
} } while (0)

static struct mCore *core;
static struct GB *gb;
static struct SM83Core *cpu;
static unsigned sleep_count, shutdown_count;
static pthread_t owner;
static atomic_bool pause_requested, execution_started;
static double pause_requested_at;

static double now(void) {
    struct timespec value;
    CHECK(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic clock");
    return value.tv_sec + value.tv_nsec / 1e9;
}

static void sleep_event(void *context) {
    (void) context;
    CHECK(pthread_equal(owner, pthread_self()), "STOP callback owner");
    ++sleep_count;
}

static void shutdown_event(void *context) {
    (void) context;
    CHECK(pthread_equal(owner, pthread_self()), "shutdown callback owner");
    ++shutdown_count;
}

static void setup(const uint8_t *program, size_t size) {
    core->reset(core);
    core->busWrite8(core, 0xffff, 0);
    core->busWrite8(core, 0xff0f, 0);
    cpu->irqh.setInterrupts(cpu, false);
    for (size_t i = 0; i < size; ++i) core->busWrite8(core, 0xc000 + i, program[i]);
    cpu->pc = 0xc000;
    cpu->sp = 0xd000;
    cpu->af = 0x1200;
    cpu->bc = 0xc100;
    cpu->de = 0xc200;
    cpu->hl = 0xc300;
    cpu->memory.setActiveRegion(cpu, cpu->pc);
    core->busWrite8(core, cpu->sp, 0x08);
    core->busWrite8(core, cpu->sp + 1, 0xc0);
    CHECK(cpu->executionState == SM83_CORE_FETCH && !cpu->halted, "reset boundary");
}

static void serialize(struct GBSerializedState *state) {
    memset(state, 0, sizeof(*state));
    GBSerialize(gb, state);
}

static void step(void) {
    CHECK(gb_probe_boundary(core) == GB_PROBE_EXECUTED, "one execution boundary");
}

static unsigned differential(void) {
    struct GBSerializedState *start = calloc(1, sizeof(*start));
    struct GBSerializedState *reference = calloc(1, sizeof(*reference));
    struct GBSerializedState *actual = calloc(1, sizeof(*actual));
    CHECK(start && reference && actual, "state buffers");
    unsigned count = 0;
    const uint8_t illegal[] = {0xd3, 0xdb, 0xdd, 0xe3, 0xe4, 0xeb, 0xec, 0xed, 0xf4, 0xfc, 0xfd};
    for (unsigned prefixed = 0; prefixed < 2; ++prefixed) {
        for (unsigned opcode = 0; opcode < 256; ++opcode) {
            if (!prefixed && (opcode == 0x76 || opcode == 0x10 ||
                memchr(illegal, (int) opcode, sizeof(illegal)))) continue;
            for (unsigned flags = 0; flags < 2; ++flags) {
                uint8_t program[] = {prefixed ? 0xcb : opcode, prefixed ? opcode : 0x04, 0xc4, 0};
                setup(program, sizeof(program));
                cpu->f.packed = flags ? 0xf0 : 0;
                serialize(start);
                core->step(core);
                serialize(reference);
                CHECK(GBDeserialize(gb, start), "restore differential start");
                step();
                serialize(actual);
                if (memcmp(reference, actual, sizeof(*actual))) {
                    fprintf(stderr, "Mismatch prefix=%u opcode=%02x flags=%u PC=%04x\n",
                            prefixed, opcode, flags, cpu->pc);
                    CHECK(false, "full serialized state matches original core->step");
                }
                ++count;
            }
        }
    }
    free(start); free(reference); free(actual);
    fprintf(stderr, "PASS: %u ordinary opcode/flag differential cases\n", count);
    return count;
}

static void halted_idle(unsigned count) {
    uint16_t pc = cpu->pc, bc = cpu->bc;
    uint64_t before = mTimingGlobalTime(&gb->timing);
    for (unsigned i = 0; i < count; ++i) {
        CHECK(gb_probe_boundary(core) == GB_PROBE_IDLE, "halted event slice");
        CHECK(cpu->halted && cpu->pc == pc && cpu->bc == bc &&
              cpu->executionState == SM83_CORE_FETCH, "idle does not execute an opcode");
    }
    if (mTimingGlobalTime(&gb->timing) <= before)
        fprintf(stderr, "Idle count=%u time=%llu -> %llu cycles=%d next=%d\n", count,
                (unsigned long long) before, (unsigned long long) mTimingGlobalTime(&gb->timing),
                cpu->cycles, cpu->nextEvent);
    CHECK(mTimingGlobalTime(&gb->timing) > before, "halted devices advance");
}

static void halt_cases(void) {
    const uint8_t program[] = {0x76, 0x04, 0x00}; // HALT; INC B; NOP
    setup(program, sizeof(program));
    step();
    CHECK(cpu->pc == 0xc001 && cpu->halted && cpu->b == 0xc1, "HALT instruction ends before next opcode");
    halted_idle(1000);
    struct GBSerializedState before, after;
    serialize(&before);
    CHECK(core->saveState(core, &after), "halted public save");
    serialize(&after);
    CHECK(!memcmp(&before, &after, sizeof(before)), "halted public save is nondestructive at normalized boundary");
    CHECK(GBDeserialize(gb, &before), "halted normalized state restores");
    // Restore can schedule an event at the current cycle; servicing that event
    // may legitimately make no elapsed-time progress in its first idle slice.
    halted_idle(1000);

    // Enabled serial interrupt with no transfer: native events cannot wake HALT.
    for (unsigned ime = 0; ime < 2; ++ime) {
        setup(program, sizeof(program));
        core->busWrite8(core, 0xffff, 8);
        gb->memory.ime = ime;
        GBUpdateIRQs(gb);
        step();
        CHECK(cpu->halted && cpu->pc == 0xc001, "HALT with enabled but absent interrupt");
        halted_idle(1000);
        core->busWrite8(core, 0xff0f, 8);
        CHECK(!cpu->halted && cpu->irqPending == (bool) ime, "pending interrupt wakes HALT using native handler");
        step();
        if (ime) {
            CHECK(cpu->pc == 0x58 && cpu->sp == 0xcffe && cpu->b == 0xc1,
                  "one IRQ dispatch ends before vector opcode");
            CHECK(core->busRead8(core, 0xcffe) == 1 && core->busRead8(core, 0xcfff) == 0xc0,
                  "interrupt saved post-HALT PC");
        } else {
            CHECK(cpu->pc == 0xc002 && cpu->b == 0xc2, "IME-off wake executes next instruction");
        }
    }

    setup(program, sizeof(program));
    core->busWrite8(core, 0xffff, 1);
    core->busWrite8(core, 0xff0f, 1);
    step();
    CHECK(!cpu->halted && cpu->executionState == SM83_CORE_HALT_BUG &&
          cpu->pc == 0xc001 && cpu->b == 0xc1, "HALT bug is a distinct instruction boundary");
    step();
    CHECK(cpu->pc == 0xc001 && cpu->b == 0xc2, "HALT bug suppresses next opcode PC increment");
    step();
    CHECK(cpu->pc == 0xc002 && cpu->b == 0xc3, "HALT bug following instruction resumes native fetch");

    setup(program, sizeof(program));
    core->busWrite8(core, 0xffff, 1);
    core->busWrite8(core, 0xff0f, 1);
    gb->memory.ime = true;
    GBUpdateIRQs(gb);
    step();
    CHECK(cpu->pc == 0x40 && cpu->sp == 0xcffe && !cpu->halted,
          "already pending IME-on interrupt dispatches before HALT fetch");
    CHECK(core->busRead8(core, 0xcffe) == 0 && core->busRead8(core, 0xcfff) == 0xc0,
          "pending IRQ saved pre-HALT PC");
    fprintf(stderr, "PASS: HALT absent/pending IRQ, IME off/on, HALT bug and halted serialization\n");
}

static void stop_cases(void) {
    const uint8_t program[] = {0x10, 0x00, 0x04, 0x10, 0x00, 0x00};
    setup(program, sizeof(program));
    unsigned events = sleep_count + shutdown_count;
    core->busWrite8(core, 0xff4d, 1);
    step();
    CHECK(cpu->pc == 0xc002 && gb->doubleSpeed && cpu->tMultiplier == 1 &&
          core->busRead8(core, 0xff4d) == 0xfe && sleep_count + shutdown_count == events,
          "STOP speed switch completes exactly its two-byte instruction");
    step();
    CHECK(cpu->pc == 0xc003 && cpu->b == 0xc2, "ordinary instruction at double speed");
    core->busWrite8(core, 0xff4d, 1);
    step();
    CHECK(cpu->pc == 0xc005 && !gb->doubleSpeed && cpu->tMultiplier == 2,
          "STOP switches back to normal speed");
    setup(program, sizeof(program));
    events = sleep_count + shutdown_count;
    step();
    CHECK(cpu->pc == 0xc002 && !gb->doubleSpeed && sleep_count + shutdown_count == events + 1,
          "plain STOP returns with one native control callback before next opcode");
    fprintf(stderr, "PASS: CGB STOP switches both speeds; plain STOP callback preserved\n");
}

static void *request_pause(void *unused) {
    (void) unused;
    const struct timespec delay = {.tv_nsec = 1000000};
    while (!atomic_load_explicit(&execution_started, memory_order_acquire)) nanosleep(&delay, NULL);
    nanosleep(&delay, NULL);
    pause_requested_at = now();
    atomic_store_explicit(&pause_requested, true, memory_order_release);
    return NULL;
}

static double pause_halted(void) {
    const uint8_t program[] = {0x76, 0x04};
    setup(program, sizeof(program));
    gb->memory.ime = true;
    core->busWrite8(core, 0xffff, 8);
    step();
    CHECK(cpu->halted, "pause case enters HALT");
    pthread_t requester;
    CHECK(!pthread_create(&requester, NULL, request_pause, NULL), "start pause requester");
    double deadline = now() + 1;
    atomic_store_explicit(&execution_started, true, memory_order_release);
    unsigned slices = 0;
    while (!atomic_load_explicit(&pause_requested, memory_order_acquire) && now() < deadline) {
        CHECK(gb_probe_boundary(core) == GB_PROBE_IDLE, "pause owner services halted events");
        ++slices;
    }
    double acknowledged = now();
    CHECK(atomic_load_explicit(&pause_requested, memory_order_acquire), "urgent pause acknowledged before deadline");
    CHECK(!pthread_join(requester, NULL), "join pause requester");
    CHECK(cpu->halted && cpu->pc == 0xc001 && cpu->b == 0xc1 && slices,
          "pause leaves halted instruction boundary unchanged");
    double latency = (acknowledged - pause_requested_at) * 1000;
    fprintf(stderr, "PASS: atomic pause while IME+IE HALTed after %u idle slices, %.3f ms\n", slices, latency);
    return latency;
}

int main(int argc, char **argv) {
    CHECK(argc == 2, "fixture ROM argument");
    owner = pthread_self();
    core = GBCoreCreate();
    CHECK(core && core->init(core), "initialize core");
    mCoreInitConfig(core, NULL);
    mCoreConfigSetValue(&core->config, "cgb.model", "CGB");
    core->opts.useBios = false;
    core->opts.skipBios = true;
    struct VFile *rom = VFileOpen(argv[1], O_RDONLY);
    CHECK(rom && core->loadROM(core, rom), "load authored fixture");
    gb = core->board;
    cpu = core->cpu;
    struct mCoreCallbacks callbacks = {.sleep = sleep_event, .shutdown = shutdown_event};
    core->addCoreCallbacks(core, &callbacks);
    unsigned cases = differential();
    halt_cases();
    stop_cases();
    double latency = pause_halted();
    mCoreConfigDeinit(&core->config);
    core->deinit(core);
    printf("{\"schema\":1,\"status\":\"PASS\",\"ordinaryDifferentialCases\":%u,"
           "\"haltCases\":\"PASS\",\"stopCases\":\"PASS\",\"haltPauseMilliseconds\":%.6f}\n", cases, latency);
    return 0;
}
