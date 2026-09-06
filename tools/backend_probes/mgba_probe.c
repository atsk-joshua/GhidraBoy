// SPDX-License-Identifier: MIT
// Bounded M1 feasibility probe. Uses only mGBA's public core/debugger interfaces.
#include <mgba/core/core.h>
#include <mgba/gb/core.h>
#include <mgba/debugger/debugger.h>
#include <mgba-util/vfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

static unsigned breakpoint_count, watch_count;
static int breakpoint_banks[2];
static struct mDebuggerEntryInfo last_watch;
static pthread_t owner;
static unsigned manual_count, instruction_callbacks;
static atomic_bool pause_requested, execution_started;
static double pause_requested_at;
static bool (*close_rom_file)(struct VFile *);
static unsigned rom_close_count;

static bool tracked_rom_close(struct VFile *file) {
    ++rom_close_count;
    return close_rom_file(file);
}

#define CHECK(condition, message) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", message); exit(1); } \
    fprintf(stderr, "PASS: %s\n", message); \
} while (0)

static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
    return now.tv_sec + now.tv_nsec / 1e9;
}

static void instruction_boundary(struct mDebuggerModule *module) {
    (void) module;
    if (!pthread_equal(owner, pthread_self())) abort();
    ++instruction_callbacks;
}

static void *request_pause(void *unused) {
    (void) unused;
    struct timespec delay = { .tv_nsec = 1000000 };
    while (!atomic_load_explicit(&execution_started, memory_order_acquire))
        nanosleep(&delay, NULL);
    nanosleep(&delay, NULL);
    pause_requested_at = monotonic_seconds();
    /* This is the entire cross-thread interface: no core or debugger access. */
    atomic_store_explicit(&pause_requested, true, memory_order_release);
    return NULL;
}

static int32_t reg(struct mCore *core, const char *name) {
    int32_t value;
    CHECK(core->readRegister(core, name, &value), "register read");
    return value;
}

static void entered(struct mDebuggerModule *module, enum mDebuggerEntryReason reason,
                    struct mDebuggerEntryInfo *info) {
    (void) module;
    CHECK(pthread_equal(owner, pthread_self()), "stop callback runs on owner thread");
    if (reason == DEBUGGER_ENTER_BREAKPOINT) {
        CHECK(info && breakpoint_count < 2, "bounded breakpoint records");
        breakpoint_banks[breakpoint_count++] = info->segment;
    } else if (reason == DEBUGGER_ENTER_WATCHPOINT) {
        CHECK(info && watch_count < 16, "bounded watch records");
        last_watch = *info;
        ++watch_count;
    } else if (reason == DEBUGGER_ENTER_MANUAL) {
        ++manual_count;
    }
}

static unsigned run_until_pause(struct mDebugger *debugger) {
    unsigned steps = 0;
    while (debugger->state != DEBUGGER_PAUSED && steps < 100000) {
        mDebuggerRun(debugger);
        ++steps;
    }
    CHECK(debugger->state == DEBUGGER_PAUSED, "bounded stop reached");
    return steps;
}

static void resume(struct mDebuggerModule *module) {
    module->isPaused = false;
    mDebuggerUpdatePaused(module->p);
}

int main(int argc, char **argv) {
    owner = pthread_self();
    CHECK(argc == 2 || (argc == 3 && (!strcmp(argv[2], "--halt-step") ||
          !strcmp(argv[2], "--halt-run-loop"))), "provide self-authored banks fixture ROM and optional HALT case");
    FILE *file = fopen(argv[1], "rb");
    CHECK(file, "open fixture");
    CHECK(fseek(file, 0, SEEK_END) == 0, "seek fixture");
    long length = ftell(file);
    CHECK(length >= 0xc000 && length <= 0x800000, "bounded fixture size");
    rewind(file);
    unsigned char *rom = malloc((size_t) length);
    CHECK(rom && fread(rom, 1, (size_t) length, file) == (size_t) length, "read fixture");
    fclose(file);

    struct mCore *core = GBCoreCreate();
    CHECK(core && core->init(core), "initialize GB core");
    mCoreInitConfig(core, NULL);
    mCoreConfigSetValue(&core->config, "cgb.model", "CGB");
    core->opts.useBios = false;
    core->opts.skipBios = true;
    struct VFile *vf = VFileFromConstMemory(rom, (size_t) length);
    CHECK(vf, "create ROM file view");
    close_rom_file = vf->close;
    vf->close = tracked_rom_close;
    CHECK(core->loadROM(core, vf), "load immutable fixture buffer");
    core->reset(core);
    CHECK(reg(core, "pc") == 0x100, "post-boot PC");
    CHECK(core->rawRead8(core, 0x402a, 1) == 0x11, "physical ROM bank 1");
    CHECK(core->rawRead8(core, 0x402a, 2) == 0x22, "physical ROM bank 2");
    core->step(core);
    CHECK(reg(core, "pc") == 0x101, "one instruction step");

    struct mDebugger debugger;
    struct mDebuggerModule module = { .type = DEBUGGER_CUSTOM, .entered = entered };
    mDebuggerInit(&debugger);
    mDebuggerAttach(&debugger, core);
    mDebuggerAttachModule(&debugger, &module);
    struct mBreakpoint point = { .address = 0x4029, .segment = 1,
                                .type = BREAKPOINT_HARDWARE };
    ssize_t first = debugger.platform->setBreakpoint(debugger.platform, &module, &point);
    point.segment = 2;
    ssize_t second = debugger.platform->setBreakpoint(debugger.platform, &module, &point);
    CHECK(first > 0 && second > first, "physical breakpoint registration");
    unsigned steps = run_until_pause(&debugger);
    CHECK(breakpoint_count == 1 && breakpoint_banks[0] == 1, "bank 1 breakpoint");
    CHECK(reg(core, "pc") == 0x4029, "first bank CPU PC");
    struct mDebuggerInstructionInfo instruction = {0};
    debugger.platform->nextInstructionInfo(debugger.platform, &instruction);
    CHECK(instruction.address == 0x4029 && instruction.segment == 1, "instruction bank identity");
    resume(&module);
    steps += run_until_pause(&debugger);
    CHECK(breakpoint_count == 2 && breakpoint_banks[1] == 2, "bank 2 breakpoint");
    CHECK(reg(core, "pc") == 0x4029, "same CPU PC in second bank");

    size_t state_size = core->stateSize(core);
    void *before = calloc(1, state_size), *after = calloc(1, state_size);
    CHECK(before && after && core->saveState(core, before), "save paused state");
    CHECK(core->saveState(core, after) && !memcmp(before, after, state_size),
          "repeated serialization without inspection is stable");
    for (unsigned address = 0; address < 0x10000; ++address)
        (void) core->rawRead8(core, address, -1);
    CHECK(core->saveState(core, after), "serialize after raw inspection");
    bool raw_inspection_safe = !memcmp(before, after, state_size);
    fprintf(stderr, "OBSERVATION: full rawRead8 inspection preserves state=%s\n",
            raw_inspection_safe ? "true" : "false");
    CHECK(core->loadState(core, before), "restore before alternate inspection probe");
    CHECK(core->saveState(core, before), "baseline for memory-block inspection");
    const struct mCoreMemoryBlock *blocks;
    size_t block_count = core->listMemoryBlocks(core, &blocks);
    size_t copied_bytes = 0;
    bool loaded_rom_equal = false;
    volatile unsigned checksum = 0;
    for (size_t i = 0; i < block_count; ++i) {
        size_t size = 0;
        const unsigned char *memory = core->getMemoryBlock(core, blocks[i].id, &size);
        fprintf(stderr, "BLOCK: id=%zu name=%s declared=%u accessible=%zu available=%s\n",
                blocks[i].id, blocks[i].internalName, blocks[i].size, size, memory ? "true" : "false");
        if (!memory) continue;
        if (!strcmp(blocks[i].internalName, "cart0"))
            loaded_rom_equal = size == (size_t) length && !memcmp(memory, rom, size);
        for (size_t j = 0; j < size; ++j) checksum += memory[j];
        copied_bytes += size;
    }
    (void) checksum;
    CHECK(copied_bytes >= (size_t) length, "physical memory blocks available");
    CHECK(loaded_rom_equal, "loaded physical ROM bytes exactly match owned input");
    CHECK(core->saveState(core, after) && !memcmp(before, after, state_size),
          "physical block inspection preserves serialized state");
    for (int bank = 0; bank < 2; ++bank)
        for (unsigned address = 0x8000; address < 0xa000; ++address)
            checksum += core->rawRead8(core, address, bank);
    CHECK(core->saveState(core, after) && !memcmp(before, after, state_size),
          "both physical VRAM bank reads preserve serialized state");
    core->rawWrite8(core, 0x8000, 0, 0x17);
    core->rawWrite8(core, 0x8000, 1, 0x28);
    CHECK(core->rawRead8(core, 0x8000, 0) == 0x17 && core->rawRead8(core, 0x8000, 1) == 0x28,
          "physical VRAM read segments distinguish both CGB banks");
    CHECK(core->loadState(core, before), "restore VRAM bank test mutations");
    CHECK(core->writeRegister(core, "a", 0x99), "register edit");
    CHECK(reg(core, "a") == 0x99, "register edit observed");
    core->step(core);
    CHECK(reg(core, "a") == 0x22 && reg(core, "pc") == 0x402b, "bank 2 instruction effect");
    CHECK(core->loadState(core, before) && reg(core, "pc") == 0x4029, "restore paused state");
    CHECK(core->saveState(core, before), "baseline for rejected mutations");
    int32_t unknown_register = 0;
    CHECK(!core->readRegister(core, "not_a_register", &unknown_register), "unknown register read rejected");
    CHECK(!core->writeRegister(core, "not_a_register", 1), "unknown register write rejected");
    memcpy(after, before, state_size);
    memset(after, 0, sizeof(uint32_t));
    CHECK(!core->loadState(core, after), "invalid state magic rejected");
    CHECK(core->saveState(core, after) && !memcmp(before, after, state_size),
          "rejected mutations preserve serialized state");
    CHECK(debugger.platform->clearBreakpoint(debugger.platform, first), "remove first breakpoint");
    CHECK(debugger.platform->clearBreakpoint(debugger.platform, second), "remove second breakpoint");

    struct mWatchpoint watch = { .segment = 3, .minAddress = 0xd034,
                                .maxAddress = 0xd035, .type = WATCHPOINT_WRITE };
    ssize_t watch_id = debugger.platform->setWatchpoint(debugger.platform, &module, &watch);
    CHECK(watch_id > second, "physical write watch registration");
    resume(&module);
    steps += run_until_pause(&debugger);
    CHECK(watch_count == 1 && last_watch.address == 0xd034 && last_watch.segment == 3,
          "physical WRAM watch coordinates");
    CHECK(last_watch.type.wp.newValue == 0x35, "write attempt value");
    CHECK(core->rawRead8(core, 0xd034, 3) == 0x35, "completed-instruction memory value");
    resume(&module);
    steps += run_until_pause(&debugger);
    CHECK(watch_count == 2 && last_watch.type.wp.oldValue == 0x35 &&
          last_watch.type.wp.newValue == 0x35, "same-value write remains an access");
    CHECK(debugger.platform->clearBreakpoint(debugger.platform, watch_id), "remove watch");
    mDebuggerEnter(&debugger, DEBUGGER_ENTER_MANUAL, NULL);
    CHECK(debugger.state == DEBUGGER_PAUSED, "explicit pause");
    if (argc == 3) {
        CHECK(core->rawRead8(core, 0x456d, 2) == 0x76, "fixture HALT opcode");
        CHECK(core->writeRegister(core, "pc", 0x456d), "select HALT case");
        fprintf(stderr, "HALT_CASE: entering %s (outer watchdog required)\n", argv[2]);
        if (!strcmp(argv[2], "--halt-step")) core->step(core);
        else core->runLoop(core);
        fprintf(stderr, "HALT_CASE: returned pc=%x\n", reg(core, "pc"));
        /* Common cleanup is unnecessary here: process exit is this isolated
         * watchdog case's ownership boundary, including a stalled native call. */
        return 0;
    }
    CHECK(core->rawRead8(core, 0x0312, 0) == 0x18 &&
          core->rawRead8(core, 0x0313, 0) == 0xfe, "fixture bounded JR loop");
    CHECK(core->writeRegister(core, "pc", 0x0312), "select nonhalting execution fixture");

    /* With needsCallback, mDebuggerRun executes one instruction even without
     * breakpoints. RunTimeout's argument is NOT an execution deadline. */
    module.custom = instruction_boundary;
    module.needsCallback = true;
    resume(&module);
    CHECK(debugger.state == DEBUGGER_CALLBACK, "instruction-bounded callback mode");
    pthread_t requester;
    CHECK(pthread_create(&requester, NULL, request_pause, NULL) == 0, "start pause requester");
    double run_deadline = monotonic_seconds() + 2.0;
    atomic_store_explicit(&execution_started, true, memory_order_release);
    unsigned urgent_steps = 0;
    while (!atomic_load_explicit(&pause_requested, memory_order_acquire)) {
        mDebuggerRun(&debugger);
        ++urgent_steps;
        /* Avoid per-instruction clock/log overhead while retaining a bound. */
        if (!(urgent_steps % 4096) && monotonic_seconds() >= run_deadline) break;
    }
    CHECK(atomic_load_explicit(&pause_requested, memory_order_acquire), "pause request arrived within deadline");
    mDebuggerEnter(&debugger, DEBUGGER_ENTER_MANUAL, NULL);
    double pause_latency_ms = (monotonic_seconds() - pause_requested_at) * 1000;
    CHECK(pthread_join(requester, NULL) == 0, "join pause requester");
    CHECK(urgent_steps > 0 && instruction_callbacks == urgent_steps, "one callback per owned instruction");
    CHECK(debugger.state == DEBUGGER_PAUSED && pause_latency_ms < 2000,
          "urgent cross-thread pause acknowledged within two seconds");
    CHECK(core->saveState(core, before), "save manually paused state");
    mDebuggerRunTimeout(&debugger, 0);
    CHECK(core->saveState(core, after) && !memcmp(before, after, state_size),
          "paused debugger polling does not execute");

    resume(&module);
    double deadline_started = monotonic_seconds();
    unsigned deadline_steps = 0;
    do {
        mDebuggerRun(&debugger);
        ++deadline_steps;
    } while (deadline_steps % 4096 || monotonic_seconds() - deadline_started < 0.02);
    mDebuggerEnter(&debugger, DEBUGGER_ENTER_MANUAL, NULL);
    double deadline_elapsed_ms = (monotonic_seconds() - deadline_started) * 1000;
    CHECK(deadline_steps > 0 && deadline_elapsed_ms < 2000 && debugger.state == DEBUGGER_PAUSED,
          "owner deadline stops continuing execution with recoverable pause");
    unsigned callbacks_before_step = instruction_callbacks;
    resume(&module);
    mDebuggerRun(&debugger);
    mDebuggerEnter(&debugger, DEBUGGER_ENTER_MANUAL, NULL);
    CHECK(instruction_callbacks == callbacks_before_step + 1, "execution recovers after deadline");

    CHECK(core->saveState(core, before), "checkpoint before replay");
    for (unsigned i = 0; i < 32; ++i) core->step(core);
    CHECK(core->saveState(core, after), "checkpoint after replay");
    CHECK(core->loadState(core, before), "restore replay origin");
    for (unsigned i = 0; i < 32; ++i) core->step(core);
    CHECK(core->saveState(core, before) && !memcmp(before, after, state_size),
          "32-instruction replay reproduces complete serialized state");
    core->setKeys(core, 3);
    CHECK(core->getKeys(core) == 3, "input state");
    core->setKeys(core, 0);
    int frequency = core->frequency(core), timing_frequency = core->timingFrequency(core);
    CHECK(frequency > 0 && timing_frequency > 0, "declared engine timebases");

    CHECK(core->saveState(core, before), "baseline before debugger shutdown");
    mDebuggerShutdown(&debugger);
    mDebuggerRun(&debugger);
    CHECK(mDebuggerIsShutdown(&debugger) && core->saveState(core, after) && !memcmp(before, after, state_size),
          "shutdown debugger cannot execute");

    mDebuggerDetachModule(&debugger, &module);
    core->detachDebugger(core);
    mDebuggerDeinit(&debugger);
    mCoreConfigDeinit(&core->config);
    core->deinit(core);
    CHECK(rom_close_count == 1, "core destruction closes transferred ROM view exactly once");
    free(before); free(after); free(rom);
    printf("{\"schema\":1,\"probe\":\"mgba-public-api\",\"status\":\"PASS\","
           "\"boundedRunCalls\":%u,\"breakpointBanks\":[1,2],\"cpuPc\":16425,"
           "\"writeEvents\":%u,\"stateBytes\":%zu,\"frequency\":%d,\"timingFrequency\":%d,"
           "\"fullRawReadPreservesState\":%s,\"physicalBlockReadPreservesState\":true,"
           "\"pauseLatencyMs\":%.6f,\"urgentPauseInstructions\":%u,"
           "\"deadlineElapsedMs\":%.6f,\"deadlineInstructions\":%u,"
           "\"ownerThreadCallbacks\":true,\"invalidMutationPreservesState\":true,"
           "\"loadedRomBytesEqualInput\":true,"
           "\"bothVramBankReadPreservesState\":true,\"romViewClosedExactlyOnce\":true,"
           "\"shutdownDoesNotExecute\":true,"
           "\"instructionReplayStateEqual\":true,\"manualStops\":%u,"
           "\"bootPolicy\":\"engine-post-boot\",\"scope\":\"standalone feasibility; not backend conformance\"}\n",
           steps, watch_count, state_size, frequency, timing_frequency,
           raw_inspection_safe ? "true" : "false", pause_latency_ms, urgent_steps,
           deadline_elapsed_ms, deadline_steps, manual_count);
    return 0;
}
