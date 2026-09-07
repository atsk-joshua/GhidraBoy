
/* WARNING: Function: rst28 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: banked_destination replaced with injection: ghidraboy_may_return_v1 */
/* WARNING: Removing unreachable block (ram,0x4200) */

undefined * banked_source(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  banked_destination();
  return &DAT_rom1__4300;
}

