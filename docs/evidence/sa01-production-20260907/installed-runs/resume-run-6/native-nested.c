
/* WARNING: This is an inlined function */
/* WARNING: Function: FUN_0320 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: nested_inner replaced with injection: ghidraboy_may_return_v1 */

code * nested_outer(void)

{
  gb_cartridge_write8(0x2000,3);
  nested_inner(3,banked_destination,2,0xb,0x46);
  gb_cartridge_write8(0x2000,DAT_c0fb);
  return banked_destination;
}

