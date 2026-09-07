
/* WARNING: Function: rst28 replaced with injection: ghidraboy_software_call_v1 */
/* WARNING: Function: banked_destination replaced with injection: ghidraboy_may_return_v1 */

undefined2 banked_source_software_call(undefined1 param_1)

{
  gb_cartridge_write8(0x2000,param_1);
  banked_destination();
  return 0x4300;
}

