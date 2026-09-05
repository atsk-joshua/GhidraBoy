#!/usr/bin/env python3
"""Reproducibly derive documentation from the checked-in, pinned CC0 hardware.inc."""
import ast,html,json,pathlib,re
root=pathlib.Path(__file__).resolve().parents[1]
values={}; comments={}; registers={}; section=[]
ops={ast.LShift:lambda a,b:a<<b,ast.RShift:lambda a,b:a>>b,ast.BitOr:lambda a,b:a|b,ast.BitAnd:lambda a,b:a&b,ast.Add:lambda a,b:a+b,ast.Sub:lambda a,b:a-b}
def evaluate(node):
 if isinstance(node,ast.Constant) and isinstance(node.value,int):return node.value
 if isinstance(node,ast.Name):return values[node.id]
 if isinstance(node,ast.BinOp) and type(node.op) in ops:return ops[type(node.op)](evaluate(node.left),evaluate(node.right))
 raise ValueError('Unsupported expression')
for line in (root/'data/manuals/hardware.inc').read_text().splitlines():
 if line.startswith('; -- '):section=[line[5:].split('---')[0].strip()]
 elif line.startswith(';'):section.append(line[1:].strip())
 m=re.match(r'\s*def\s+(\w+)\s+equ\s+([^;]+)(?:;(.*))?$',line,re.I)
 if not m:continue
 name,expr,comment=m.groups();expr=re.sub(r'\$([0-9a-fA-F_]+)',r'0x\1',expr);expr=re.sub(r'%([01_]+)',r'0b\1',expr)
 try: value=evaluate(ast.parse(expr.strip(),mode='eval').body)
 except (ValueError,KeyError,SyntaxError):continue
 values[name]=value;comments[name]=(comment or '').strip()
 if name.startswith('r') and (0xff00<=value<=0xff7f or value==0xffff) and value not in registers:
  description=' '.join(x for x in section if x)
  registers[value]={'address':value,'name':name[1:],'description':description,'cgbOnly':'(CGB' in description,'masks':{}}
for register in registers.values():
 prefix=register['name']+'_'
 register['masks']={name:{'value':value,'description':comments[name]} for name,value in values.items() if name.startswith(prefix) and 0<=value<=255}
output={'source':'gbdev/hardware.inc','revision':'189324b77f99cf287f4153e0001830e8738a4068','license':'CC0-1.0','registers':list(registers.values())}
path=root/'src/main/resources/hardware-registers.json';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(output,indent=2)+'\n')
rows=[]
for r in output['registers']:
 masks='<br>'.join(f'{html.escape(name)} = {mask["value"]:02X} {html.escape(mask["description"])}' for name,mask in r['masks'].items())
 rows.append(f'<tr><td>{r["address"]:04X}</td><td>{r["name"]}</td><td>{html.escape(r["description"])}</td><td>{masks}</td></tr>')
manual='''<!doctype html><html><head><meta charset="utf-8"><title>GhidraBoy static processor reference</title></head><body>
<h1>GhidraBoy static processor reference</h1><p>This is a static analysis extension, not a hardware execution model. CPU pointers are 16 bits. ROM bank selection requires explicit or proven state. HALT, STOP and IME effects remain visible user operations; timing and interrupt delay are not emulated.</p>
<p>Read the primary <a href="https://gbdev.io/pandocs/">Pan Docs</a> and <a href="https://rgbds.gbdev.io/docs/gbz80.7">RGBDS SM83 instruction reference</a>. This local reference contains no proprietary manuals.</p>
<h2>Flags and boundaries</h2><p>Z/N/H/C occupy bits 7/6/5/4 of F. POP AF clears the low nibble. DAA is pure p-code; it preserves N and clears H. Stack byte addresses wrap at 16 bits. Historical one-byte STOP decode is retained; no speed-switch or HALT-bug fidelity is claimed.</p>
<h2>Static mapping and workflows</h2><p>Use GhidraBoyTools in Script Manager for mapping inspection, physical/file/CPU navigation, symbols, analysis preview/apply/remove, export and legacy enhancement. Use GhidraBoyAbi for explicit per-function calling conventions. Current mapping JSON is version 2 and is independent of GhiGBC.</p>
<h2>Hardware registers</h2><p>Definitions below derive from CC0 hardware.inc revision 189324b77f99cf287f4153e0001830e8738a4068. RO/WO/RW describe hardware access; static I/O remains volatile. Unknown/reserved registers are not invented.</p><table border="1" cellpadding="6"><tr><th>CPU</th><th>Name</th><th>Meaning</th><th>Masks / values</th></tr>'''+''.join(rows)+'</table></body></html>\n'
(root/'data/manuals/SM83.html').write_text(manual)
mnemonics=sorted(set(re.findall(r'^:([A-Z]+)',(root/'data/languages/sm83_instructions.sinc').read_text(),re.M)))
(root/'data/manuals/SM83.idx').write_text('@SM83.html [GhidraBoy static reference and primary manual links]\n'+''.join(f'{m}, 1\n' for m in mnemonics))
print(len(registers),'register descriptions generated')
