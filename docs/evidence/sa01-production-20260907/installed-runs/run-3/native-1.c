
/* WARNING: Function: FUN_0200 replaced with injection: ghidraboy_software_call_v1 */

undefined2 production_caller_1(void)

{
  gb_cartridge_write8(0x2000,BYTE_0163);
  physical_target_1(BYTE_0163);
  DAT_c100 = 0x52;
  return 0x166;
}

