
/* WARNING: Function: FUN_0340 replaced with injection: ghidraboy_software_call_v1 */

void terminal_source(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  endless_target(0x83,1);
  return;
}

