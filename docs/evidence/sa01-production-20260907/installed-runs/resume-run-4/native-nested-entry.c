
/* WARNING: Function: FUN_0300 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: nested_outer replaced with injection: ghidraboy_may_return_v1 */

undefined2 nested_entry(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  nested_outer();
  return 0x4300;
}

