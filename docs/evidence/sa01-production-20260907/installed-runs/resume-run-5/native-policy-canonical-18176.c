
/* WARNING: Function: FUN_0320 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: policy_target replaced with injection: ghidraboy_may_return_v1 */

undefined * restoring_banked_source(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  policy_target(param_1,3,0x47);
  gb_cartridge_write8(0x2000,DAT_c0fd);
  DAT_c102 = 1;
  return &DAT_rom1__4400;
}

