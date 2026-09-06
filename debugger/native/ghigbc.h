#ifndef GHIGBC_H
#define GHIGBC_H
#include <stdint.h>
/* ABI 1: opaque owned machine. All calls serialize, except atomic request_pause.
 * Return 0 success, negative error; run returns stop enum. No borrowed buffers.
 * Memory snapshot layout: CPU 65536, WRAM 32768, VRAM 16384, cart RAM 131072.
 * Unavailable cartridge bytes are excluded by cart_size; do not publish padding.
 */
#define GC_MEMORY_SIZE (65536+32768+16384+131072)
#define GC_MAX_EVENTS 64
#define GC_MAX_BREAKPOINTS 128
typedef struct gc_machine gc_machine;
enum { GC_CPU=0, GC_ROM=1, GC_WRAM=2, GC_VRAM=3, GC_CART=4, GC_BOOT=5, GC_OAM=6, GC_HRAM=7, GC_IO=8, GC_UNKNOWN=9 };
enum { GC_SLICE=0, GC_STEP=1, GC_PAUSE=2, GC_BREAKPOINT=3, GC_WATCHPOINT=4, GC_HALT=5, GC_STOP=6, GC_INTERRUPT=7, GC_ERROR=8 };
enum { GC_EXEC=1, GC_READ=2, GC_WRITE=4, GC_CHANGE=8 };
typedef struct { uint32_t region, bank, offset; } gc_address;
typedef struct {
    uint64_t sequence;
    gc_address target, writer;
    uint32_t cpu_address, writer_pc, origin, access, value, before, after, valid, breakpoint_id;
} gc_event;
typedef struct {
    uint64_t capture_id, epoch, instructions, ticks, mapping_generation, dropped;
    uint32_t abi, reason, hit_id, event_count;
    uint16_t af, bc, de, hl, sp, pc;
    uint16_t rom0, romx, wram, vram, cart;
    uint8_t ime, halted, stopped, double_speed, boot, cart_enabled, rtc_selected, reserved;
    uint32_t rom_size, cart_size;
} gc_state;
gc_machine *gc_create(const char *rom, const char *boot);
/* Copies both input buffers before returning; caller retains buffer ownership.
 * This additive ABI-1 entry point binds the emulator to the bytes fingerprinted
 * by its agent. The file-path entry point remains for legacy C callers. */
gc_machine *gc_create_buffers(const uint8_t *rom, uint32_t rom_size,
                              const uint8_t *boot, uint32_t boot_size);
void gc_destroy(gc_machine *m);
uint64_t gc_ticks(gc_machine *m);
void gc_request_pause(gc_machine *m);
void gc_prepare_run(gc_machine *m);
int gc_prepare_step(gc_machine *m, uint32_t mode);
int gc_run(gc_machine *m, uint32_t instruction_limit, uint32_t tick_limit, uint32_t step);
int gc_snapshot(gc_machine *m, gc_state *state, uint8_t *memory, uint32_t size, gc_event *events, uint32_t capacity);
int gc_breakpoint(gc_machine *m, uint32_t id, gc_address address, uint32_t length, uint32_t kinds, uint32_t enabled);
int gc_remove_breakpoint(gc_machine *m, uint32_t id);
int gc_state_save(gc_machine *m, const char *path);
int gc_state_load(gc_machine *m, const char *path);
int gc_edit_register(gc_machine *m, uint32_t index, uint16_t value);
int gc_edit_memory(gc_machine *m, uint16_t address, uint8_t value);
/* Debugger WRAM edit, bypassing CPU bus restrictions and guest watch hooks. */
int gc_edit_wram(gc_machine *m, uint32_t bank, uint32_t offset, uint8_t value);
int gc_copy_frame(gc_machine *m, uint32_t *pixels, uint32_t count);
int gc_key(gc_machine *m, uint32_t key, uint32_t pressed);
/* Read the emulator's held-button state without guest bus accesses. */
uint32_t gc_key_mask(gc_machine *m);
#endif
