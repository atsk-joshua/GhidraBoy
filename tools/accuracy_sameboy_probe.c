/* Validation only: compile once against pristine SameBoy and once including the
 * real adapter. Never install these executables as a runtime library. */
#define GB_INTERNAL
#include "Core/gb.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef ACCURACY_INSTRUMENTED
#include "ghigbc.c"
#endif

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(2); }
}
static uint32_t encode(GB_gameboy_t *gb, uint8_t r, uint8_t g, uint8_t b) {
    (void)gb; return 0xff000000u | r << 16 | g << 8 | b;
}
static void word(FILE *out, uint64_t value) {
    for (unsigned i=0;i<8;i++) { require(fputc(value & 255, out)!=EOF,"write failed"); value>>=8; }
}
static void bytes(FILE *out, const void *data, size_t size) {
    word(out,size); require(!size || fwrite(data,1,size,out)==size,"write failed");
}
/* No CPU bus reads: raw allocation bytes are compared only under identical
 * seeded startup. They are not hardware expectations or a portable state ABI. */
static void observe(FILE *out, GB_gameboy_t *g, uint64_t runs, uint64_t ticks,
                    uint32_t *pixels) {
    uint64_t values[]={runs,ticks,g->af,g->bc,g->de,g->hl,g->sp,g->pc,
        g->ime,g->halted,g->stopped,g->cgb_mode,g->cgb_double_speed,
        g->boot_rom_finished,g->mbc_ram_enable,g->interrupt_enable};
    for (unsigned i=0;i<sizeof(values)/sizeof(*values);i++) word(out,values[i]);
    GB_direct_access_t regions[]={GB_DIRECT_ACCESS_RAM,GB_DIRECT_ACCESS_VRAM,
        GB_DIRECT_ACCESS_CART_RAM,GB_DIRECT_ACCESS_ROM0,GB_DIRECT_ACCESS_ROM};
    for (unsigned i=0;i<sizeof(regions)/sizeof(*regions);i++) {
        size_t size=0; uint16_t bank=0;
        void *data=GB_get_direct_access(g,regions[i],&size,&bank);
        word(out,bank);
        if(i<3) bytes(out,data,size);
    }
    bytes(out,g->oam,sizeof(g->oam)); bytes(out,g->hram,sizeof(g->hram));
    bytes(out,g->io_registers,sizeof(g->io_registers));
    bytes(out,pixels,160*144*sizeof(*pixels));
}

int main(int argc, char **argv) {
    require(argc==8,"usage: probe ROM BOOT DMG-B|CGB-E OUTPUT MAX_RUNS mooneye|synthetic INSPECT");
    bool dmg=!strcmp(argv[3],"DMG-B"), mooneye=!strcmp(argv[6],"mooneye");
    require(dmg || !strcmp(argv[3],"CGB-E"),"unsupported model");
    uint64_t limit=strtoull(argv[5],NULL,0),ticks=0,runs=0,inspections=0,events_seen=0,inspection_changes=0;
    require(limit>0,"invalid run limit");
    GB_random_seed(0x676869647261626fULL);
#ifdef ACCURACY_INSTRUMENTED
    gc_machine *machine=allocate_machine(dmg?GB_MODEL_DMG_B:GB_MODEL_CGB_E);
    require(machine!=NULL,"allocate adapter"); GB_gameboy_t *g=machine->gb;
    require(!GB_load_rom(g,argv[1]) && !GB_load_boot_rom(g,argv[2]),"load inputs");
    require(configure_machine(machine)!=NULL,"configure adapter");
    uint32_t *pixels=machine->pixels;
    require(!gc_breakpoint(machine,1,(gc_address){GC_CPU,0,0},65536,GC_WRITE,1),"arm CPU write watch");
    uint8_t *memory=malloc(GC_MEMORY_SIZE); gc_event event[GC_MAX_EVENTS];
    gc_state state; gc_hardware hardware;
#else
    GB_gameboy_t *g=GB_init(GB_alloc(),dmg?GB_MODEL_DMG_B:GB_MODEL_CGB_E);
    require(g!=NULL,"allocate core");
    require(!GB_load_rom(g,argv[1]) && !GB_load_boot_rom(g,argv[2]),"load inputs");
    GB_debugger_set_disabled(g,true); GB_set_async_input_callback(g,NULL);
    GB_set_turbo_mode(g,true,true); GB_set_rtc_mode(g,GB_RTC_MODE_ACCURATE);
    uint32_t *pixels=calloc(160*144,sizeof(*pixels));
    GB_set_pixels_output(g,pixels); GB_set_rgb_encode_callback(g,encode);
#endif
    (void)encode;
    FILE *out=fopen(argv[4],"wb"); require(out!=NULL,"open output");
    int result=0;
    for (;;) {
        if (g->boot_rom_finished && !g->halted && !g->stopped &&
            GB_safe_read_memory(g,g->pc)==0x40 && mooneye) {
            if(g->bc==0x0305 && g->de==0x080d && g->hl==0x1522) result=1;
            else if(g->bc==0x4242 && g->de==0x4242 && g->hl==0x4242) result=-1;
        }
        if(!mooneye && g->boot_rom_finished && g->pc==0x4567) result=1;
        if (!(runs%16384) || result || runs==limit) {
#ifdef ACCURACY_INSTRUMENTED
          if(atoi(argv[7])) {
            size_t size=GB_get_save_state_size(g);
            uint8_t *before=calloc(1,size),*after=calloc(1,size);
            require(before && after && memory,"allocate snapshot verification");
            GB_save_state_to_buffer(g,before);
            require(!gc_snapshot_hardware(machine,&state,memory,GC_MEMORY_SIZE,event,
                                          GC_MAX_EVENTS,&hardware),"capture");
            GB_save_state_to_buffer(g,after);
            if(memcmp(before,after,size)) {
                for(size_t i=0;i<size;i++)if(before[i]!=after[i])
                    fprintf(stderr,"snapshot difference offset %zu: %02x -> %02x at run %"PRIu64"\n",i,before[i],after[i],runs);
                inspection_changes++;
            }
            free(before);free(after);inspections++;
          }
#endif
            observe(out,g,runs,ticks,pixels);
        }
        if(result || runs==limit)break;
#ifdef ACCURACY_INSTRUMENTED
        gc_prepare_run(machine);
        require(gc_run(machine,1,UINT32_MAX,0)>=0,"adapter execution");
        ticks=machine->ticks; events_seen+=machine->count;
#else
        ticks+=GB_run(g);
#endif
        runs++;
    }
    require(!fclose(out),"close output");
    printf("{\"result\":\"%s\",\"runs\":%"PRIu64",\"ticks8MHz\":%"PRIu64
           ",\"pc\":%u,\"bc\":%u,\"de\":%u,\"hl\":%u,\"cgbMode\":%u,"
           "\"bootFinished\":%u,\"inspections\":%"PRIu64",\"writeEvents\":%"PRIu64
           ",\"inspectionStateChanges\":%"PRIu64"}\n",
           result==1?"PASS":result==-1?"FAIL":"TIMEOUT",runs,ticks,g->pc,g->bc,g->de,g->hl,
           g->cgb_mode,g->boot_rom_finished,inspections,events_seen,inspection_changes);
#ifdef ACCURACY_INSTRUMENTED
    free(memory);gc_destroy(machine);
#else
    free(pixels);GB_free(g);free(g);
#endif
    return result==1 && !inspection_changes?0:1;
}
