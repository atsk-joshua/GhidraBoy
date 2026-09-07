
/* WARNING: Function: misannotated_helper replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: physical_target_1 replaced with injection: ghidraboy_may_return_v1 */

undefined2 production_caller_1(void)

{
  gb_cartridge_write8(0x2000,2);
  physical_target_1(2);
  DAT_c100 = 0x52;
  return 0x166;
}

