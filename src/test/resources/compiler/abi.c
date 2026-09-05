/* Self-authored redistributable ABI fixture. Compile with pinned GBDK SDCC. */
typedef unsigned char u8;
typedef unsigned int u16;
typedef unsigned long u32;
volatile u8 sink8;
volatile u16 sink16;
volatile u32 sink32;
u8 legacy8(u8 a, u8 b, u8 c) __sdcccall(0) { return a + b + c; }
u16 legacy16(u16 a, u16 b, u8 c) __sdcccall(0) { return a + b + c; }
u32 legacy32(u32 a) __sdcccall(0) { return a + 1; }
u8 current8(u8 a, u8 b, u8 c) __sdcccall(1) { return a + b + c; }
u16 current16(u16 a, u16 b, u8 c) __sdcccall(1) { return a + b + c; }
u32 current32(u32 a) __sdcccall(1) { return a + 1; }
u16 mixed(u8 a, u16 b, u8 c) __sdcccall(1) { return a + b + c; }
u8 pointer(const u8 *p) __sdcccall(1) { return *p; }
void caller(void) {
 sink8=legacy8(1,2,3); sink16=legacy16(0x1234,0x5678,9); sink32=legacy32(0x12345678);
 sink8=current8(1,2,3); sink16=current16(0x1234,0x5678,9); sink32=current32(0x12345678);
 sink16=mixed(1,0x2345,6); sink8=pointer((const u8*)0xc123);
}
u16 mixed2(u16 a, u8 b, u16 c) __sdcccall(1) { return a + b + c; }
/* Additional convention fixtures: compiler behavior, not inferred ABI promises. */
#include <stdarg.h>
struct Pair { u8 first; u16 second; };
u16 variadic(u8 count, ...) { va_list ap; va_start(ap,count); u16 n=va_arg(ap,u16); va_end(ap); return n+count; }
struct Pair aggregate(struct Pair a) { a.first++; return a; }
u8 preserved(u8 a) __preserves_regs(b,c) { return a+1; }
u8 banked(u8 a, u16 b) __banked { return a+b; }
void extraCaller(void) { sink16=variadic(1,0x2345); sink8=preserved(3); sink8=banked(4,0x4567); }
u8 first32_with8(u32 a, u8 b) { return a+b; }
u32 first8_second32(u8 a, u32 b) { return a+b; }
