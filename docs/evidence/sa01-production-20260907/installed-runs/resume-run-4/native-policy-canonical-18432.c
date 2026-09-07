
/* WARNING: Function: FUN_0340 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: policy_target replaced with injection: ghidraboy_may_return_v1 */
/* WARNING: Removing unreachable block (ram,0x4800) */

undefined * constant_banked_source(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  policy_target(3,0x48);
  gb_cartridge_write8(0x2000,3);
  DAT_c103 = 3;
  return &DAT_rom1__4400;
}

