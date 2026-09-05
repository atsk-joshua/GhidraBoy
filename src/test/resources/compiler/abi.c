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
