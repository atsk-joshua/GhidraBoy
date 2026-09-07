
/* WARNING: Function: FUN_0300 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Removing unreachable block (ram,0x0190) */

undefined2 nonlocal_source(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  nonlocal_target();
  return 0xc0ff;
}

