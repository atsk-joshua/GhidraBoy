#!/usr/bin/env python3
"""Execute the returned six-case fixture C for all 256 inputs.

The only translation adapts its 16-bit lookup address to the self-authored fixture
byte array. The switch expression/case labels/return values remain unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    generated = (args.fixture / "fixture.c").read_text()
    adapted, count = re.subn(r"\*\(char \*\)CONCAT11\(([^,()]+),([^()]+)\)", r"read_char(CONCAT11(\1,\2))", generated)
    if count != 1 or "*(char *)" in adapted:
        raise ValueError("Unexpected generated lookup expression; refusing semantic rewrite")
    wrapper = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t byte;
static byte DAT_ff80;
static byte memory[0x400];
// Preserve the native bad-data path as a fatal trap; never invent a default value.
static _Noreturn void halt_baddata(void) { fputs("reached native bad-data path\n",stderr); exit(3); }
#define CONCAT11(high,low) ((uint16_t)(((uint16_t)(uint8_t)(high)<<8)|(uint8_t)(low)))
static char read_char(uint16_t address) {
    if(address<0x200 || address>0x202) {fprintf(stderr,"unexpected lookup %x\n",address);exit(2);}
    return (char)memory[address];
}
''' + adapted + r'''
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    FILE *file=fopen(argv[1],"rb");if(file==NULL)return 2;
    if(fread(memory,1,sizeof(memory),file)!=sizeof(memory))return 2;
    fclose(file);
    int failures=0;
    for(unsigned input=0;input<256;++input) {
        DAT_ff80=input;unsigned actual=guarded_phase_switch();unsigned expected=input<6?10*(input+1):0;
        printf("%u %u %u\n",input,actual,expected);failures+=actual!=expected;
    }
    return failures?1:0;
}
'''
    source = args.output / "adapted-fixture.c"
    source.write_text(wrapper)
    binary = args.output / "fixture-test"
    compiled = subprocess.run([args.cc, "-std=c11", "-O0", "-Wall", str(source), "-o", str(binary)], capture_output=True, text=True)
    (args.output / "compile.log").write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    executed = subprocess.run([str(binary.resolve()), str((args.fixture / "fixture.bin").resolve())], capture_output=True, text=True)
    rows = [{"input": int(line.split()[0]), "actual": int(line.split()[1]), "expected": int(line.split()[2])} for line in executed.stdout.splitlines()]
    passed = executed.returncode == 0 and len(rows) == 256 and all(row["actual"] == row["expected"] for row in rows)
    result = {"status": "PASS" if passed else "FAIL", "cases": len(rows), "failures": sum(row["actual"] != row["expected"] for row in rows),
              "generatedCSha256": hashlib.sha256(generated.encode()).hexdigest(), "adaptedCSha256": hashlib.sha256(wrapper.encode()).hexdigest(),
              "fixtureSha256": hashlib.sha256((args.fixture / "fixture.bin").read_bytes()).hexdigest(), "stderr": executed.stderr,
              "rows": rows, "limits": ["Host C execution of generated fixture with a checked CPU-memory read adapter", "This is self-authored code; no commercial ROM bytes are used", "Native instruction semantic validation is a separate provider gate"]}
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "cases", "failures")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
