
/* WARNING: This is an inlined function */
/* WARNING: GhidraBoy conditional execution model: valid only for the selected reviewed entry state.
   See the Function comment and GhidraBoy Tools execution contexts. */
/* Original shared callee note
   
   GhidraBoy conditional execution context. This decompilation applies only to the following
   reviewed state; other entry states remain unproved. Use GhidraBoy Tools software-call-contexts /
   software-call-select-context to inspect all contexts.
   {
     "state": {
       "cpu": 17920,
       "physical": {
         "region": "ROM",
         "bank": 2,
         "offset": 1536
       },
       "mapper": {
         "romLow": 2,
         "romHigh": 0,
         "mode": 0,
         "ramSelect": 0,
         "ramEnabled": false,
         "vbk": 0,
         "svbk": 1,
         "latch": 0
       },
       "sp": 49406,
       "registers": {
         "a": 2,
         "f": 128,
         "bc": 0,
         "de": 0,
         "hl": 17920
       },
       "memory": [
         {
           "physical": {
             "region": "WRAM",
             "bank": 0,
             "offset": 254
           },
           "value": 145
         },
         {
           "physical": {
             "region": "WRAM",
             "bank": 0,
             "offset": 255
           },
           "value": 1
         }
       ]
     },
     "sourceSite": "0190",
     "origin": "CALLEE"
   } */

void __ghidraboy_state_entry_v1 shared_state_callee(void)

{
  gb_cartridge_write8(0x2000,2);
  DAT_c211 = 0x22;
  return;
}

