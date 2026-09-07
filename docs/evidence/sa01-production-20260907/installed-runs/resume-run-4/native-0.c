
/* WARNING: Function: FUN_0200 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: physical_target_0 replaced with injection: ghidraboy_may_return_v1 */

undefined2 production_caller_0(void)

{
  gb_cartridge_write8(0x2000,1);
  physical_target_0(1);
  DAT_c100 = 0x51;
  return 0x156;
}

