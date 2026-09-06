// SPDX-License-Identifier: MIT
// Bounded M1 feasibility probe. Uses only mGBA's public core/debugger interfaces.
#include <mgba/core/core.h>
#include <mgba/gb/core.h>
#include <mgba/debugger/debugger.h>
#include <mgba-util/vfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned breakpoint_count, watch_count;
static int breakpoint_banks[2];
static struct mDebuggerEntryInfo last_watch;

#define CHECK(condition, message) do { \
    if (!(condition)) { fprintf(stderr, "FAIL: %s\n", message); exit(1); } \
    fprintf(stderr, "PASS: %s\n", message); \
} while (0)

static int32_t reg(struct mCore *core, const char *name) {
    int32_t value;
    CHECK(core->readRegister(core, name, &value), "register read");
    return value;
}

static void entered(struct mDebuggerModule *module, enum mDebuggerEntryReason reason,
                    struct mDebuggerEntryInfo *info) {
    (void) module;
    if (reason == DEBUGGER_ENTER_BREAKPOINT) {
        CHECK(info && breakpoint_count < 2, "bounded breakpoint records");
        breakpoint_banks[breakpoint_count++] = info->segment;
    } else if (reason == DEBUGGER_ENTER_WATCHPOINT) {
        CHECK(info && watch_count < 16, "bounded watch records");
        last_watch = *info;
        ++watch_count;
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
    CHECK(argc == 2, "provide self-authored banks fixture ROM");
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
    CHECK(vf && core->loadROM(core, vf), "load immutable fixture buffer");
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
    volatile unsigned checksum = 0;
    for (size_t i = 0; i < block_count; ++i) {
        size_t size = 0;
        const unsigned char *memory = core->getMemoryBlock(core, blocks[i].id, &size);
        if (!memory) continue;
        for (size_t j = 0; j < size; ++j) checksum += memory[j];
        copied_bytes += size;
    }
    (void) checksum;
    CHECK(copied_bytes >= (size_t) length, "physical memory blocks available");
    CHECK(core->saveState(core, after) && !memcmp(before, after, state_size),
          "physical block inspection preserves serialized state");
    CHECK(core->writeRegister(core, "a", 0x99), "register edit");
    CHECK(reg(core, "a") == 0x99, "register edit observed");
    core->step(core);
    CHECK(reg(core, "a") == 0x22 && reg(core, "pc") == 0x402b, "bank 2 instruction effect");
    CHECK(core->loadState(core, before) && reg(core, "pc") == 0x4029, "restore paused state");
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
    core->setKeys(core, 3);
    CHECK(core->getKeys(core) == 3, "input state");
    core->setKeys(core, 0);
    int frequency = core->frequency(core), timing_frequency = core->timingFrequency(core);
    CHECK(frequency > 0 && timing_frequency > 0, "declared engine timebases");

    mDebuggerDetachModule(&debugger, &module);
    core->detachDebugger(core);
    mDebuggerDeinit(&debugger);
    mCoreConfigDeinit(&core->config);
    core->deinit(core);
    free(before); free(after); free(rom);
    printf("{\"schema\":1,\"probe\":\"mgba-public-api\",\"status\":\"PASS\","
           "\"boundedRunCalls\":%u,\"breakpointBanks\":[1,2],\"cpuPc\":16425,"
           "\"writeEvents\":%u,\"stateBytes\":%zu,\"frequency\":%d,\"timingFrequency\":%d,"
           "\"fullRawReadPreservesState\":%s,\"physicalBlockReadPreservesState\":true,"
           "\"bootPolicy\":\"engine-post-boot\",\"scope\":\"standalone feasibility; not backend conformance\"}\n",
           steps, watch_count, state_size, frequency, timing_frequency,
           raw_inspection_safe ? "true" : "false");
    return 0;
}
