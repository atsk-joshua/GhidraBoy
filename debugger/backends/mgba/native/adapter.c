// SPDX-License-Identifier: MIT
// All mGBA internals stay here. Python receives copied fixed-width data only.
#include "execution.h"
#include <mgba/core/core.h>
#include <mgba/core/config.h>
#include <mgba/gb/core.h>
#include <mgba/internal/gb/gb.h>
#include <mgba/internal/sm83/sm83.h>
#include <mgba-util/vfs.h>
#include <stdatomic.h>
#include <time.h>

#define MEMORY_SIZE (65536 + 32768 + 16384 + 131072)
#define STATE_WORDS 34
enum { SLICE, STEP, PAUSE, BREAKPOINT, HALT_WAIT, STOP_WAIT, ERROR };
struct Point { uint32_t id, region, bank, offset, length, enabled; };
struct Adapter {
    struct mCore *core;
    uint8_t *rom;
    uint32_t rom_size, reason, hit, keys;
    uint64_t boundaries, mapping_generation;
    uint64_t mapping[6];
    atomic_bool pause;
    bool stopped, fault, skip_breakpoint;
    mColor pixels[160 * 144];
    struct Point points[256];
};

static uint64_t now_ns(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t) value.tv_sec * 1000000000 + value.tv_nsec;
}
static bool boundary(struct Adapter *a) {
    struct SM83Core *cpu = a->core->cpu;
    return !a->fault && (cpu->executionState == SM83_CORE_FETCH || cpu->executionState == SM83_CORE_HALT_BUG);
}
static void stopped(void *context) { ((struct Adapter *) context)->stopped = true; }
static void crashed(void *context) { ((struct Adapter *) context)->fault = true; }
void gm_destroy(struct Adapter *a) {
    if (!a) return;
    if (a->core) { mCoreConfigDeinit(&a->core->config); a->core->deinit(a->core); }
    free(a->rom);
    free(a);
}
struct Adapter *gm_create(const uint8_t *rom, uint32_t size) {
    if (!rom || size < 32768 || size > 0x800000 || size % 16384 ||
        !(rom[0x143] & 0x80) || rom[0x147] < 0x19 || rom[0x147] > 0x1b) return NULL;
    struct Adapter *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    atomic_init(&a->pause, false);
    a->rom = malloc(size);
    if (!a->rom) { free(a); return NULL; }
    memcpy(a->rom, rom, size);
    a->rom_size = size;
    a->core = GBCoreCreate();
    if (!a->core) { free(a->rom); free(a); return NULL; }
    if (!a->core->init(a->core)) { free(a->core); free(a->rom); free(a); return NULL; }
    mCoreInitConfig(a->core, NULL);
    mCoreConfigSetValue(&a->core->config, "cgb.model", "CGB");
    a->core->opts.useBios = false;
    a->core->opts.skipBios = true;
    struct VFile *vf = VFileFromConstMemory(a->rom, size);
    if (!vf) { gm_destroy(a); return NULL; }
    // Pinned GBLoadROM owns vf once installed in GB. Failed load may not install it.
    if (!a->core->loadROM(a->core, vf)) {
        if (((struct GB *) a->core->board)->romVf != vf) vf->close(vf);
        gm_destroy(a); return NULL;
    }
    a->core->setVideoBuffer(a->core, a->pixels, 160);
    struct mCoreCallbacks callbacks = { .context = a, .sleep = stopped, .shutdown = stopped, .coreCrashed = crashed };
    a->core->addCoreCallbacks(a->core, &callbacks);
    a->core->reset(a->core);
    struct GB *gb = a->core->board;
    size_t loaded_size = 0;
    const void *loaded = a->core->getMemoryBlock(a->core, GB_REGION_CART_BANK0, &loaded_size);
    if (gb->model != GB_MODEL_CGB || gb->memory.mbcType != GB_MBC5 ||
        gb->sramSize > 131072 || !loaded || loaded_size != size || memcmp(loaded, rom, size)) {
        gm_destroy(a); return NULL;
    }
    a->reason = PAUSE;
    return a;
}
void gm_request_pause(struct Adapter *a) { atomic_store_explicit(&a->pause, true, memory_order_release); }
void gm_prepare(struct Adapter *a) {
    atomic_store_explicit(&a->pause, false, memory_order_release);
    a->skip_breakpoint = a->reason == BREAKPOINT;
    a->reason = SLICE;
    a->hit = 0;
}
uint64_t gm_ticks(struct Adapter *a) { return mTimingGlobalTime(&((struct GB *) a->core->board)->timing); }
static void observe_mapping(struct Adapter *a) {
    struct GB *gb = a->core->board;
    struct GBMemory *m = &gb->memory;
    uint64_t mapping[] = { m->currentBank0, m->currentBank, m->wramCurrentBank, gb->video.vramCurrentBank, m->sramCurrentBank, m->sramAccess };
    if (memcmp(a->mapping, mapping, sizeof(mapping))) {
        memcpy(a->mapping, mapping, sizeof(mapping));
        ++a->mapping_generation;
    }
}
static uint32_t point_hit(struct Adapter *a) {
    struct GB *gb = a->core->board;
    struct SM83Core *cpu = a->core->cpu;
    uint32_t pc = cpu->pc;
    // An interrupt dispatch and a sleeping CPU are not opcode execution.
    if (cpu->halted || cpu->irqPending) return 0;
    uint32_t bank = pc < 0x4000 ? gb->memory.currentBank0 : gb->memory.currentBank;
    for (unsigned i = 0; i < 256; ++i) {
        struct Point *p = &a->points[i];
        uint32_t offset = p->region ? pc % 0x4000 : pc;
        if (p->id && p->enabled && (!p->region || (pc < 0x8000 && p->bank == bank)) &&
            offset >= p->offset && offset - p->offset < p->length) return p->id;
    }
    return 0;
}
int gm_run(struct Adapter *a, uint32_t step) {
    if (!boundary(a)) { a->fault = true; a->reason = ERROR; return -1; }
    uint64_t deadline = now_ns() + 2000000; // Two milliseconds between native boundaries.
    for (unsigned n = 0; n < (step ? 1u : 10000u); ++n) {
        if (atomic_load_explicit(&a->pause, memory_order_acquire)) { a->reason = PAUSE; return 1; }
        if (a->stopped) { a->reason = STOP_WAIT; return 1; }
        if (!step && !a->skip_breakpoint && (a->hit = point_hit(a))) { a->reason = BREAKPOINT; return 1; }
        a->skip_breakpoint = false;
        enum GBProbeBoundary result = gb_probe_boundary(a->core);
        if (result == GB_PROBE_FAULT || a->fault) { a->fault = true; a->reason = ERROR; return -1; }
        observe_mapping(a);
        if (result == GB_PROBE_EXECUTED) ++a->boundaries;
        if (a->stopped) { a->reason = STOP_WAIT; return 1; }
        if (step) { a->reason = result == GB_PROBE_IDLE ? HALT_WAIT : STEP; return 1; }
        if (now_ns() >= deadline) break;
    }
    a->reason = SLICE;
    return 0;
}
int gm_breakpoint(struct Adapter *a, uint32_t id, uint32_t region, uint32_t bank, uint32_t offset, uint32_t length, uint32_t enabled) {
    if (!id || region > 1 || !length || (region == 0 && bank) ||
        (region == 1 && bank >= a->rom_size / 16384)) return -1;
    uint32_t bound = region ? 16384 : 65536;
    if (offset >= bound || length > bound - offset) return -1;
    struct Point *free_point = NULL;
    for (unsigned i = 0; i < 256; ++i) {
        if (a->points[i].id == id) { free_point = &a->points[i]; break; }
        if (!a->points[i].id && !free_point) free_point = &a->points[i];
    }
    if (!free_point) return -1;
    *free_point = (struct Point) { id, region, bank, offset, length, !!enabled };
    return 0;
}
void gm_remove(struct Adapter *a, uint32_t id) {
    for (unsigned i = 0; i < 256; ++i) if (a->points[i].id == id) a->points[i].id = 0;
}
static bool block(struct Adapter *a, uint32_t id, uint8_t *out, size_t expected) {
    size_t size = 0;
    const void *data = a->core->getMemoryBlock(a->core, id, &size);
    if (size != expected || (size && !data)) return false;
    if (size) memcpy(out, data, size);
    return true;
}
int gm_capture(struct Adapter *a, uint64_t *s, uint32_t words, uint8_t *out, uint32_t size) {
    if (!boundary(a) || words != STATE_WORDS || size != MEMORY_SIZE) return -1;
    struct GB *gb = a->core->board;
    struct SM83Core *cpu = a->core->cpu;
    struct GBMemory *m = &gb->memory;
    observe_mapping(a);
    if (m->currentBank0 < 0 || m->currentBank < 0 || (unsigned) m->currentBank0 >= a->rom_size / 16384 ||
        (unsigned) m->currentBank >= a->rom_size / 16384 || m->wramCurrentBank < 1 || m->wramCurrentBank > 7 ||
        gb->video.vramCurrentBank < 0 || gb->video.vramCurrentBank > 1 || m->sramCurrentBank < 0 || gb->sramSize > 131072) return -1;
    memset(out, 0, size);
    if (!block(a, GB_REGION_WORKING_RAM_BANK0, out + 65536, 32768) ||
        !block(a, GB_REGION_EXTERNAL_RAM, out + 114688, gb->sramSize) ||
        !block(a, GB_BASE_OAM, out + 0xfe00, 160) || !block(a, GB_BASE_HRAM, out + 0xff80, 127)) return -1;
    // Pinned segmented VRAM observation is side-effect free; the public block
    // advertises more bytes than its pointer owns and must not be bulk-copied.
    for (unsigned bank = 0; bank < 2; ++bank)
        for (unsigned offset = 0; offset < 8192; ++offset)
            out[98304 + bank * 8192 + offset] = a->core->rawRead8(a->core, 0x8000 + offset, bank);
    memcpy(out, a->rom + m->currentBank0 * 16384, 16384);
    memcpy(out + 0x4000, a->rom + m->currentBank * 16384, 16384);
    memcpy(out + 0x8000, out + 98304 + gb->video.vramCurrentBank * 8192, 8192);
    if (m->sramAccess && gb->sramSize) {
        size_t offset = m->sramCurrentBank * 8192;
        if (offset >= gb->sramSize) return -1;
        size_t count = gb->sramSize - offset;
        if (count > 8192) count = 8192;
        memcpy(out + 0xa000, out + 114688 + offset, count);
    }
    memcpy(out + 0xc000, out + 65536, 4096);
    memcpy(out + 0xd000, out + 65536 + m->wramCurrentBank * 4096, 4096);
    memcpy(out + 0xe000, out + 0xc000, 0x1e00);
    uint64_t values[STATE_WORDS] = { 1, a->reason, a->hit, a->boundaries, gm_ticks(a), a->mapping_generation,
        cpu->a * 256 + cpu->f.packed, cpu->b * 256 + cpu->c, cpu->d * 256 + cpu->e, cpu->h * 256 + cpu->l, cpu->sp, cpu->pc,
        m->currentBank0, m->currentBank, m->wramCurrentBank, gb->video.vramCurrentBank, m->sramCurrentBank,
        m->ime, cpu->halted, a->stopped, gb->doubleSpeed, 0, m->sramAccess, 0, a->rom_size, gb->sramSize,
        32768, 16384, 0, 0, 0, gb->video.mode==3, gb->video.mode>=2, m->dmaRemaining!=0 };
    memcpy(s, values, sizeof(values));
    return 0;
}
int gm_key(struct Adapter *a, uint32_t key, uint32_t pressed) {
    if (key > 7) return -1;
    if (pressed) a->keys |= 1u << key; else a->keys &= ~(1u << key);
    a->core->setKeys(a->core, ((a->keys & 15) << 4) | (a->keys >> 4));
    return 0;
}
uint32_t gm_key_mask(struct Adapter *a) { return a->keys; }
int gm_frame(struct Adapter *a, uint32_t *out, uint32_t count) {
    if (count != 160 * 144 || sizeof(mColor) != 4) return -1;
    for (unsigned i = 0; i < count; ++i) {
        uint32_t p = a->pixels[i]; // mGBA RGB8 stores red in low byte.
        out[i] = 0xff000000 | ((p & 255) << 16) | (p & 0xff00) | ((p >> 16) & 255);
    }
    return 0;
}
// Diagnostic state copy also establishes capture nondestructiveness in tests.
// Never invoke saveState at HALT_BUG: upstream would execute another opcode.
uint32_t gm_state_size(struct Adapter *a) { return a->core->stateSize(a->core); }
int gm_state_copy(struct Adapter *a, uint8_t *out, uint32_t size) {
    struct SM83Core *cpu = a->core->cpu;
    if (!boundary(a) || cpu->executionState != SM83_CORE_FETCH || size != gm_state_size(a)) return -1;
    return a->core->saveState(a->core, out) ? 0 : -1;
}
