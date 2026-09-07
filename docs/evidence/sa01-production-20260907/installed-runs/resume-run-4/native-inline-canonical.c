
/* WARNING: Function: FUN_0200 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: banked_destination replaced with injection: ghidraboy_may_return_v1 */
/* WARNING: Removing unreachable block (ram,0x4500) */

undefined * banked_inline_source(void)

{
  gb_cartridge_write8(0x2000,2);
  banked_destination(2);
  return &DAT_rom1__4506;
}

