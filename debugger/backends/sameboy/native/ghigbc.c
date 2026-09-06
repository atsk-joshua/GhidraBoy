#define GB_INTERNAL
#include "Core/gb.h"
#include "ghigbc.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint32_t id, length, kinds, enabled; gc_address address; } breakpoint;
struct gc_machine {
    GB_gameboy_t *gb;
    /* Device reads can flush lazy APU/PPU work even through safe_read_memory.
     * Resolve CPU-view bytes on a private engine restored from the stopped state. */
    GB_gameboy_t *inspection;
    uint8_t *inspection_state;
    size_t inspection_state_size;
    uint32_t inspection_pixels[160*144];
    pthread_mutex_t lock;
    atomic_bool pause;
    uint64_t captures, epoch, instructions, ticks, generation, sequence, dropped;
    uint32_t reason, hit_id, count, retired, skip_id, step_mode;
    int32_t step_depth;
    bool execute_checked;
    gc_address writer, skip_address;
    uint16_t writer_pc;
    gc_event events[GC_MAX_EVENTS];
    breakpoint breakpoints[GC_MAX_BREAKPOINTS];
    uint32_t pixels[160*144];
};
static uint16_t bank(gc_machine *m, GB_direct_access_t type) {
    uint16_t b=0;size_t size;GB_get_direct_access(m->gb,type,&size,&b);
    /* SameBoy's direct-access bank mask assumes whole 8 KiB cart banks. */
    return type==GB_DIRECT_ACCESS_CART_RAM && size<0x2000?0:b;
}
static gc_address physical(gc_machine *m, uint16_t a) {
    GB_gameboy_t *g=m->gb;
    if (a<0x8000) {
        if (!g->boot_rom_finished && (a<0x100 || (GB_is_cgb(g) && a>=0x200 && a<0x900))) return (gc_address){GC_BOOT,0,a};
        return (gc_address){GC_ROM,bank(m,a<0x4000?GB_DIRECT_ACCESS_ROM0:GB_DIRECT_ACCESS_ROM),a&0x3fff};
    }
    if (a<0xa000) return (gc_address){GC_VRAM,bank(m,GB_DIRECT_ACCESS_VRAM),a&0x1fff};
    if (a<0xc000) {
        if (g->cartridge_type->mbc_type==GB_MBC3 && g->mbc3.rtc_mapped) return (gc_address){GC_UNKNOWN,0,a&0x1fff};
        /* Small cartridge RAM is mirrored in the CPU window. Keep the persisted
         * cartridge region ID and report its canonical physical byte. */
        uint32_t offset=a&0x1fff;
        if (g->mbc_ram_size && g->mbc_ram_size<0x2000) offset%=g->mbc_ram_size;
        return (gc_address){GC_CART,bank(m,GB_DIRECT_ACCESS_CART_RAM),offset};
    }
    if (a<0xfe00) { if (a>=0xe000) a-=0x2000; return (gc_address){GC_WRAM,a<0xd000?0:bank(m,GB_DIRECT_ACCESS_RAM),a&0xfff}; }
    if (a<0xfea0) return (gc_address){GC_OAM,0,a-0xfe00};
    if (a<0xff00) return (gc_address){GC_UNKNOWN,0,a};
    if (a<0xff80 || a==0xffff) return (gc_address){GC_IO,0,a-0xff00};
    return (gc_address){GC_HRAM,0,a-0xff80};
}
static uint32_t region_size(gc_machine *m, uint32_t region, uint32_t selected_bank) {
    size_t size;uint32_t stride;GB_direct_access_t type;
    switch(region) {
        case GC_CPU:return selected_bank?0:65536;
        case GC_ROM:type=GB_DIRECT_ACCESS_ROM;stride=0x4000;break;
        case GC_WRAM:type=GB_DIRECT_ACCESS_RAM;stride=0x1000;break;
        case GC_VRAM:type=GB_DIRECT_ACCESS_VRAM;stride=0x2000;break;
        case GC_CART:type=GB_DIRECT_ACCESS_CART_RAM;stride=0x2000;break;
        case GC_BOOT:return selected_bank?0:GB_is_cgb(m->gb)?0x900:0x100;
        case GC_OAM:return selected_bank?0:160;
        case GC_HRAM:return selected_bank?0:127;
        case GC_IO:return selected_bank?0:256;
        default:return 0;
    }
    GB_get_direct_access(m->gb,type,&size,NULL);
    uint64_t start=(uint64_t)selected_bank*stride;
    return start>=size?0:size-start<stride?(uint32_t)(size-start):stride;
}
static bool valid_range(gc_machine *m, gc_address a, uint32_t length) {
    uint32_t size=region_size(m,a.region,a.bank);
    if(!length||a.offset>=size||length>size-a.offset)return false;
    if(a.region==GC_BOOT && a.offset<0x200 && a.offset+length>0x100)return false;
    if(a.region==GC_IO && a.offset!=0xff && (a.offset>=0x80||length>0x80-a.offset))return false;
    return true;
}
static uint8_t raw(gc_machine *m, gc_address a, uint32_t *valid) {
    if(!valid_range(m,a,1)){*valid=0;return 0;}
    GB_direct_access_t t; uint32_t stride;
    switch(a.region) {
        case GC_ROM:t=GB_DIRECT_ACCESS_ROM;stride=0x4000;break;
        case GC_WRAM:t=GB_DIRECT_ACCESS_RAM;stride=0x1000;break;
        case GC_VRAM:t=GB_DIRECT_ACCESS_VRAM;stride=0x2000;break;
        case GC_CART:t=GB_DIRECT_ACCESS_CART_RAM;stride=0x2000;break;
        case GC_BOOT:t=GB_DIRECT_ACCESS_BOOTROM;stride=0;break;
        case GC_OAM:t=GB_DIRECT_ACCESS_OAM;stride=0;break;
        case GC_HRAM:t=GB_DIRECT_ACCESS_HRAM;stride=0;break;
        default:*valid=0;return 0;
    }
    size_t n;uint8_t *p=GB_get_direct_access(m->gb,t,&n,NULL);
    uint64_t offset=(uint64_t)a.bank*stride+a.offset;
    *valid=p&&offset<n;
    uint8_t value=*valid?p[offset]:0;
    /* SameBoy retains irrelevant upper bits in its backing allocation. MBC2
     * physically stores four bits; CPU reads independently drive the high F. */
    return a.region==GC_CART && m->gb->cartridge_type->mbc_type==GB_MBC2?value&0xf:value;
}
static bool equal(gc_address a,gc_address b) {return a.region==b.region&&a.bank==b.bank&&a.offset==b.offset;}
static bool matches(breakpoint *b, gc_address a, uint16_t cpu, uint32_t kind) {
    if (!b->enabled || !(b->kinds&kind)) return false;
    if (b->address.region==GC_CPU) return cpu>=b->address.offset&&(uint32_t)cpu-b->address.offset<b->length;
    return b->address.region==a.region&&b->address.bank==a.bank&&a.offset>=b->address.offset&&a.offset-b->address.offset<b->length;
}
static bool execute_breakpoint(gc_machine *m) {
    for(unsigned j=0;j<GC_MAX_BREAKPOINTS;j++) {
        breakpoint *b=&m->breakpoints[j];
        if(matches(b,m->writer,m->writer_pc,GC_EXEC) && !(m->skip_id&&equal(m->skip_address,m->writer))) {
            m->reason=GC_BREAKPOINT;m->hit_id=b->id;return true;
        }
    }
    return false;
}
static bool before_opcode(GB_gameboy_t *g,uint16_t address) {
    gc_machine *m=GB_get_user_data(g);
    m->writer_pc=address;m->writer=physical(m,address);
    /* Ordinary runnable boundaries were checked before GB_run. The hook also
     * reaches wake-and-fetch paths occurring within that same core call. */
    return !m->execute_checked && execute_breakpoint(m);
}
static void bus(GB_gameboy_t *g,uint16_t a,uint8_t v,bool write,uint8_t origin) {
    gc_machine *m=GB_get_user_data(g);
    if (origin!=1) return; /* Interrupt accesses deliberately excluded from CPU watchpoints. */
    gc_address target=physical(m,a);
    for (unsigned i=0;i<GC_MAX_BREAKPOINTS;i++) {
        breakpoint *b=&m->breakpoints[i];
        if (!matches(b,target,a,write?GC_WRITE:GC_READ)) continue;
        if (m->count==GC_MAX_EVENTS) {m->dropped++;m->reason=GC_WATCHPOINT;continue;}
        gc_event *e=&m->events[m->count++];memset(e,0,sizeof(*e));
        e->sequence=++m->sequence;e->target=target;e->writer=m->writer;e->writer_pc=m->writer_pc;
        e->cpu_address=a;e->origin=origin;e->access=write?GC_WRITE:GC_READ;e->value=v;e->breakpoint_id=b->id;
        e->before=raw(m,target,&e->valid);e->after=e->before;
    }
}
static void executed(GB_gameboy_t *g,uint16_t address,uint8_t opcode) {
    (void)address;(void)opcode;gc_machine *m=GB_get_user_data(g);m->retired++;m->instructions++;
}
static uint32_t rgb(GB_gameboy_t *g,uint8_t r,uint8_t b,uint8_t c) {(void)g;return 0xff000000u|r<<16|b<<8|c;}
static gc_machine *allocate_machine(GB_model_t model) {
    gc_machine *m=calloc(1,sizeof(*m));if(!m)return NULL;
    pthread_mutex_init(&m->lock,NULL);
    GB_gameboy_t *g=GB_alloc();if(!g){gc_destroy(m);return NULL;}
    m->gb=GB_init(g,model);
    return m;
}
static gc_machine *configure_machine(gc_machine *m) {
    /* RTC selectors are unknown, not RAM. MBC2 uses 512 physical nibble cells. */
    uint8_t mapper=m->gb->rom[0x147];
    if (!(mapper==0 || (mapper>=1&&mapper<=3) || mapper==5 || mapper==6 || (mapper>=0x0f&&mapper<=0x13) || (mapper>=0x19&&mapper<=0x1e))) {gc_destroy(m);return NULL;}
    GB_set_user_data(m->gb,m);GB_debugger_set_disabled(m->gb,true);GB_set_async_input_callback(m->gb,NULL);
    GB_set_execution_callback(m->gb,executed);m->gb->ghigbc_bus_callback=bus;
    m->gb->ghigbc_instruction_callback=before_opcode;
    GB_set_turbo_mode(m->gb,true,true);GB_set_rtc_mode(m->gb,GB_RTC_MODE_ACCURATE);
    GB_set_pixels_output(m->gb,m->pixels);GB_set_rgb_encode_callback(m->gb,rgb);
    m->inspection=GB_alloc();
    if(!m->inspection){gc_destroy(m);return NULL;}
    GB_init(m->inspection,GB_get_model(m->gb));
    GB_load_rom_from_buffer(m->inspection,m->gb->rom,m->gb->rom_size);
    GB_load_boot_rom_from_buffer(m->inspection,m->gb->boot_rom,GB_is_cgb(m->gb)?0x900:0x100);
    GB_debugger_set_disabled(m->inspection,true);
    GB_set_turbo_mode(m->inspection,true,true);
    GB_set_pixels_output(m->inspection,m->inspection_pixels);
    GB_set_rgb_encode_callback(m->inspection,rgb);
    m->inspection_state_size=GB_get_save_state_size(m->gb);
    m->inspection_state=malloc(m->inspection_state_size);
    if(!m->inspection_state){gc_destroy(m);return NULL;}
    m->reason=GC_PAUSE;return m;
}
gc_machine *gc_create(const char *rom,const char *boot) {
    if(!rom||!boot)return NULL;
    gc_machine *m=allocate_machine(GB_MODEL_CGB_E);if(!m)return NULL;
    if(GB_load_rom(m->gb,rom)||GB_load_boot_rom(m->gb,boot)){gc_destroy(m);return NULL;}
    return configure_machine(m);
}
gc_machine *gc_create_buffers(const uint8_t *rom,uint32_t rom_size,const uint8_t *boot,uint32_t boot_size) {
    return gc_create_model_buffers(rom,rom_size,boot,boot_size,GC_MODEL_CGB_E);
}
gc_machine *gc_create_model_buffers(const uint8_t *rom,uint32_t rom_size,const uint8_t *boot,uint32_t boot_size,uint32_t model) {
    if(!rom||!boot||rom_size<32768||rom_size>0x800000||rom_size%16384||model>GC_MODEL_DMG_B)return NULL;
    if(boot_size!=(model==GC_MODEL_DMG_B?0x100:0x900))return NULL;
    gc_machine *m=allocate_machine(model==GC_MODEL_DMG_B?GB_MODEL_DMG_B:GB_MODEL_CGB_E);if(!m)return NULL;
    GB_load_rom_from_buffer(m->gb,rom,rom_size);
    GB_load_boot_rom_from_buffer(m->gb,boot,boot_size);
    return configure_machine(m);
}
static void hardware_locked(gc_machine *m,gc_hardware *hardware) {
    size_t ram=0,vram=0;
    GB_model_t model=GB_get_model(m->gb);
    GB_get_direct_access(m->gb,GB_DIRECT_ACCESS_RAM,&ram,NULL);
    GB_get_direct_access(m->gb,GB_DIRECT_ACCESS_VRAM,&vram,NULL);
    *hardware=(gc_hardware){1,model==GB_MODEL_DMG_B?GC_MODEL_DMG_B:model==GB_MODEL_CGB_E?GC_MODEL_CGB_E:UINT32_MAX,
        m->gb->cgb_mode,(uint32_t)ram,(uint32_t)vram,GB_is_cgb(m->gb)?0x900:0x100};
}
int gc_get_hardware(gc_machine *m,gc_hardware *hardware) {
    if(!m||!hardware)return -1;
    pthread_mutex_lock(&m->lock);hardware_locked(m,hardware);pthread_mutex_unlock(&m->lock);return 0;
}
void gc_destroy(gc_machine *m) {if(!m)return;if(m->inspection)GB_dealloc(m->inspection);free(m->inspection_state);if(m->gb)GB_dealloc(m->gb);pthread_mutex_destroy(&m->lock);free(m);}
uint64_t gc_ticks(gc_machine *m) {pthread_mutex_lock(&m->lock);uint64_t t=m->ticks;pthread_mutex_unlock(&m->lock);return t;}
void gc_request_pause(gc_machine *m) {atomic_store(&m->pause,true);}
void gc_prepare_run(gc_machine *m) {
    pthread_mutex_lock(&m->lock);
    if(m->reason==GC_BREAKPOINT) {m->skip_id=m->hit_id;m->skip_address=physical(m,m->gb->pc);}
    m->count=0;m->hit_id=0;m->step_mode=0;m->reason=GC_SLICE;atomic_store(&m->pause,false);pthread_mutex_unlock(&m->lock);
}
int gc_prepare_step(gc_machine *m,uint32_t mode) {
    if(mode<2||mode>3)return -1;
    gc_prepare_run(m);pthread_mutex_lock(&m->lock);
    if(mode==3&&!m->gb->backtrace_size){pthread_mutex_unlock(&m->lock);return -2;}
    m->step_mode=mode;m->step_depth=m->gb->debug_call_depth-(mode==3?1:0);
    pthread_mutex_unlock(&m->lock);return 0;
}
int gc_run(gc_machine *m,uint32_t limit,uint32_t ticks,uint32_t step) {
    if(!limit||!ticks)return -1;
    pthread_mutex_lock(&m->lock);
    uint64_t start=m->ticks;
    for(uint32_t i=0;i<limit&&m->ticks-start<ticks;i++) {
        if(atomic_load(&m->pause)){m->reason=GC_PAUSE;break;}
        GB_gameboy_t *g=m->gb;
        m->writer_pc=g->pc;m->writer=physical(m,g->pc);m->retired=0;
        m->execute_checked=false;
        bool pending=g->ime&&(g->interrupt_enable&g->io_registers[GB_IO_IF]&31);
        if(!pending&&!g->halted&&!g->stopped) {
            if(execute_breakpoint(m))goto done;
            m->execute_checked=true;
        }
        uint32_t first=m->count;
        uint16_t previous[5]={bank(m,GB_DIRECT_ACCESS_ROM0),bank(m,GB_DIRECT_ACCESS_ROM),bank(m,GB_DIRECT_ACCESS_RAM),bank(m,GB_DIRECT_ACCESS_VRAM),bank(m,GB_DIRECT_ACCESS_CART_RAM)};
        bool boot=g->boot_rom_finished;
        m->ticks+=GB_run(g);
        uint16_t current[5]={bank(m,GB_DIRECT_ACCESS_ROM0),bank(m,GB_DIRECT_ACCESS_ROM),bank(m,GB_DIRECT_ACCESS_RAM),bank(m,GB_DIRECT_ACCESS_VRAM),bank(m,GB_DIRECT_ACCESS_CART_RAM)};
        if(memcmp(previous,current,sizeof(current))||boot!=g->boot_rom_finished)m->generation++;
        if(m->reason==GC_BREAKPOINT)break;
        if(m->retired)m->skip_id=0;
        bool hit=false;
        for(unsigned j=first;j<m->count;j++) {
            gc_event *e=&m->events[j];uint32_t valid;e->after=raw(m,e->target,&valid);e->valid&=valid;
            breakpoint *b=NULL;for(unsigned k=0;k<GC_MAX_BREAKPOINTS;k++)if(m->breakpoints[k].id==e->breakpoint_id)b=&m->breakpoints[k];
            if(b&&(!(b->kinds&GC_CHANGE)||(e->valid&&e->before!=e->after))) {hit=true;m->hit_id=e->breakpoint_id;}
        }
        if(hit){m->reason=GC_WATCHPOINT;break;}
        m->count=first; /* discard non-matching change predicates, bounded per instruction */
        if(m->step_mode && m->retired && g->debug_call_depth<=m->step_depth) {m->step_mode=0;m->reason=GC_STEP;break;}
        if(m->step_mode && !m->retired && (g->halted||g->stopped)) {m->step_mode=0;m->reason=g->stopped?GC_STOP:GC_HALT;break;}
        if(step) {m->reason=m->retired?GC_STEP:pending?GC_INTERRUPT:g->stopped?GC_STOP:g->halted?GC_HALT:GC_SLICE;break;}
    }
done:;
    int reason=m->reason;pthread_mutex_unlock(&m->lock);return reason;
}
static void copy_direct(gc_machine *m,uint8_t *dst,GB_direct_access_t type,size_t capacity) {
    size_t n;void *p=GB_get_direct_access(m->gb,type,&n,NULL);memset(dst,0,capacity);if(p)memcpy(dst,p,n<capacity?n:capacity);
}
static int snapshot_locked(gc_machine *m,gc_state *s,uint8_t *mem,gc_event *events) {
    if(GB_get_save_state_size(m->gb)!=m->inspection_state_size)return -2;
    GB_save_state_to_buffer(m->gb,m->inspection_state);
    if(GB_load_state_from_buffer(m->inspection,m->inspection_state,m->inspection_state_size))return -2;
    memset(s,0,sizeof(*s));GB_gameboy_t *g=m->gb;
    s->abi=1;s->capture_id=++m->captures;s->epoch=m->epoch;s->instructions=m->instructions;s->ticks=m->ticks;s->mapping_generation=m->generation;s->dropped=m->dropped;
    s->reason=m->reason;s->hit_id=m->hit_id;s->event_count=m->count;
    s->af=g->af;s->bc=g->bc;s->de=g->de;s->hl=g->hl;s->sp=g->sp;s->pc=g->pc;
    s->rom0=bank(m,GB_DIRECT_ACCESS_ROM0);s->romx=bank(m,GB_DIRECT_ACCESS_ROM);s->wram=bank(m,GB_DIRECT_ACCESS_RAM);s->vram=bank(m,GB_DIRECT_ACCESS_VRAM);s->cart=bank(m,GB_DIRECT_ACCESS_CART_RAM);
    s->ime=g->ime;s->halted=g->halted;s->stopped=g->stopped;s->double_speed=g->cgb_double_speed;s->boot=!g->boot_rom_finished;s->cart_enabled=g->mbc_ram_enable;s->rtc_selected=(g->cartridge_type->mbc_type==GB_MBC3 && g->mbc3.rtc_mapped);s->rom_size=g->rom_size;s->cart_size=g->mbc_ram_size;
    for(unsigned a=0;a<65536;a++)mem[a]=GB_safe_read_memory(m->inspection,a);
    copy_direct(m,mem+65536,GB_DIRECT_ACCESS_RAM,32768);copy_direct(m,mem+98304,GB_DIRECT_ACCESS_VRAM,16384);copy_direct(m,mem+114688,GB_DIRECT_ACCESS_CART_RAM,131072);
    if(g->cartridge_type->mbc_type==GB_MBC2)for(unsigned i=0;i<s->cart_size;i++)mem[114688+i]&=0xf;
    memcpy(events,m->events,m->count*sizeof(*events));
    return 0;
}
int gc_snapshot(gc_machine *m,gc_state *s,uint8_t *mem,uint32_t size,gc_event *events,uint32_t capacity) {
    if(!m||!s||!mem||!events||size<GC_MEMORY_SIZE||capacity<GC_MAX_EVENTS)return -1;
    pthread_mutex_lock(&m->lock);int result=snapshot_locked(m,s,mem,events);pthread_mutex_unlock(&m->lock);return result;
}
int gc_snapshot_hardware(gc_machine *m,gc_state *s,uint8_t *mem,uint32_t size,gc_event *events,uint32_t capacity,gc_hardware *hardware) {
    if(!m||!s||!mem||!events||!hardware||size<GC_MEMORY_SIZE||capacity<GC_MAX_EVENTS)return -1;
    pthread_mutex_lock(&m->lock);int result=snapshot_locked(m,s,mem,events);if(!result)hardware_locked(m,hardware);pthread_mutex_unlock(&m->lock);return result;
}
int gc_breakpoint(gc_machine *m,uint32_t id,gc_address a,uint32_t length,uint32_t kinds,uint32_t enabled) {
    if(!m||!id||!kinds||(kinds&~15u)||((kinds&GC_CHANGE)&&!(kinds&GC_WRITE)))return -1;
    pthread_mutex_lock(&m->lock);
    if(!valid_range(m,a,length)){pthread_mutex_unlock(&m->lock);return -1;}
    breakpoint *slot=NULL;
    for(unsigned i=0;i<GC_MAX_BREAKPOINTS;i++) {if(m->breakpoints[i].id==id){slot=&m->breakpoints[i];break;}if(!m->breakpoints[i].id)slot=&m->breakpoints[i];}
    if(slot)*slot=(breakpoint){id,length,kinds,enabled,a};pthread_mutex_unlock(&m->lock);return slot?0:-2;
}
int gc_remove_breakpoint(gc_machine *m,uint32_t id) {pthread_mutex_lock(&m->lock);for(unsigned i=0;i<GC_MAX_BREAKPOINTS;i++)if(m->breakpoints[i].id==id)memset(&m->breakpoints[i],0,sizeof(breakpoint));pthread_mutex_unlock(&m->lock);return 0;}
int gc_state_save(gc_machine *m,const char *path) {pthread_mutex_lock(&m->lock);int r=GB_save_state(m->gb,path);pthread_mutex_unlock(&m->lock);return r;}
int gc_state_load(gc_machine *m,const char *path) {pthread_mutex_lock(&m->lock);int r=GB_load_state(m->gb,path);if(!r){m->epoch++;m->generation++;m->gb->backtrace_size=0;m->gb->debug_call_depth=0;m->step_mode=0;m->count=0;m->skip_id=0;m->hit_id=0;m->reason=GC_PAUSE;m->writer=(gc_address){GC_UNKNOWN,0,0};}pthread_mutex_unlock(&m->lock);return r;}
int gc_edit_register(gc_machine *m,uint32_t index,uint16_t v) {if(index>=6)return -1;pthread_mutex_lock(&m->lock);GB_get_registers(m->gb)->registers[index]=index==0?v&0xfff0:v;m->count=0;m->skip_id=0;m->step_mode=0;if(index>=4){m->gb->backtrace_size=0;m->gb->debug_call_depth=0;}pthread_mutex_unlock(&m->lock);return 0;}
int gc_edit_memory(gc_machine *m,uint16_t a,uint8_t v) {pthread_mutex_lock(&m->lock);GB_write_memory(m->gb,a,v);pthread_mutex_unlock(&m->lock);return 0;}
int gc_edit_wram(gc_machine *m,uint32_t selected_bank,uint32_t offset,uint8_t value) {
    pthread_mutex_lock(&m->lock);
    size_t size;uint8_t *ram=GB_get_direct_access(m->gb,GB_DIRECT_ACCESS_RAM,&size,NULL);
    if(!ram||offset>=0x1000||selected_bank>=size/0x1000){pthread_mutex_unlock(&m->lock);return -1;}
    ram[selected_bank*0x1000+offset]=value;
    m->count=0;m->skip_id=0;m->step_mode=0;m->hit_id=0;m->reason=GC_PAUSE;
    m->writer=(gc_address){GC_UNKNOWN,0,0};
    m->gb->backtrace_size=0;m->gb->debug_call_depth=0;
    pthread_mutex_unlock(&m->lock);return 0;
}
int gc_copy_frame(gc_machine *m,uint32_t *pixels,uint32_t count) {if(count<160*144)return -1;pthread_mutex_lock(&m->lock);memcpy(pixels,m->pixels,sizeof(m->pixels));pthread_mutex_unlock(&m->lock);return 0;}
int gc_key(gc_machine *m,uint32_t key,uint32_t pressed) {if(key>7)return -1;pthread_mutex_lock(&m->lock);GB_set_key_state(m->gb,key,pressed);pthread_mutex_unlock(&m->lock);return 0;}
uint32_t gc_key_mask(gc_machine *m) {
    pthread_mutex_lock(&m->lock);
    uint32_t mask=0;for(unsigned key=0;key<8;key++)if(m->gb->keys[0][key])mask|=1u<<key;
    pthread_mutex_unlock(&m->lock);return mask;
}
