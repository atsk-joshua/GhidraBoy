/* Self-authored historical SDCC default-convention fixture, no sdcccall attribute. */
typedef unsigned char u8;
typedef unsigned int u16;
typedef unsigned long u32;
u8 legacy8(u8 a,u8 b,u8 c) { return a+b+c; }
u16 legacy16(u16 a,u16 b,u8 c) { return a+b+c; }
u32 legacy32(u32 a) { return a+1; }
u8 legacyPointer(const u8 *p) { return *p; }
u16 legacyMixed(u8 a,u16 b,u8 c) { return a+b+c; }
