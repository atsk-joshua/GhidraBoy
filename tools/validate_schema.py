#!/usr/bin/env python3
"""Validate actual exported snapshots using JSON Schema Draft 2020-12 (jsonschema 4.25.1)."""
import argparse,glob,json,pathlib
import jsonschema
p=argparse.ArgumentParser();p.add_argument('files',nargs='+');args=p.parse_args()
schema=json.loads((pathlib.Path(__file__).resolve().parents[1]/'docs/mapping-schema.json').read_text())
jsonschema.Draft202012Validator.check_schema(schema)
validator=jsonschema.Draft202012Validator(schema)
count=0
for pattern in args.files:
 matches=glob.glob(pattern)
 if not matches: raise SystemExit('No snapshots matched '+pattern)
 for filename in matches:
  validator.validate(json.loads(pathlib.Path(filename).read_text()));count+=1
print(json.dumps({'schemaVersion':2,'validatedSnapshots':count}))
