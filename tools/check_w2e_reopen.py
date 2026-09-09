#!/usr/bin/env python3
"""Check actual W2e current-format persistence with the retained independent executor.
The baseline is referenced in place, never relabeled or normalized. No provider code runs here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import check_w2e_native as native


def check(capture, baseline, receipts, fixture):
    read, require, sha = native.read, native.require, native.sha
    historical = read(baseline / 'refreshed-proof.json')
    original = read(baseline / 'program.json')
    fixture_bytes = bytearray(fixture.read_bytes())
    require(sha(fixture) == original['image_sha256'], 'foreign fixture')
    require(fixture_bytes[0xe000] == 0xd3, 'foreign original revision')
    fixture_bytes[0xe000] = 0xe4
    image_hash = hashlib.sha256(fixture_bytes).hexdigest()
    registrations, identities, processes, stages = [], [], [], {}
    expected_provider = original['provider_location']
    for label in ('saved', 'reopened'):
        command = read(receipts / label / 'result.json')
        argv = command['argv']
        require(command['exit_code'] == 0 and command['completion_marker'], 'capture failed')
        require('-process' in argv and '-noanalysis' in argv and '-import' not in argv,
                'not an existing Program without analysis')
        require(('-readOnly' in argv) == (label == 'reopened'), 'wrong save/reopen mode')
        log = (receipts / label / 'output.log').read_text()
        if label == 'saved':
            require('Save succeeded for processed file: /F1234.gb' in log, 'save not established')
        raw = (capture / f'{label}-registration.json').read_bytes()
        require(raw == (capture / f'{label}-registration-after.json').read_bytes(),
                'registration mutated during native invocation')
        registration = json.loads(raw)
        proof = read(capture / f'{label}-proof.json')
        require(registration['proof'] == proof == historical, 'stored proof changed from actual E4 capture')
        native.check_proof(proof, 0xe4)
        require(registration['programId'] == original['program_id'], 'foreign persistent Program')
        require(registration['alias'] == 'gb_ordinary_150::0150', 'foreign saved alias')
        before = read(capture / f'{label}-before-identity.json')
        after = read(capture / f'{label}-after-identity.json')
        require(before == after, 'capture changed Program state or identity')
        require(before['program_id'] == original['program_id']
                and before['original_image_sha256'] == original['image_sha256']
                and before['current_export_sha256'] == image_hash, 'image or Program mismatch')
        require(before['stored_program_instance'] == proof['programInstance']
                and before['stored_revision'] == proof['revision'], 'stored identity differs')
        require(before['provider_location'] == expected_provider, 'wrong provider route')
        sources = before['physical_sources']
        require(len(sources) == 4, 'physical sources incomplete')
        for source, selector in zip(sources, (1, 2, 3, 4)):
            value = {1: 0x31, 2: 0xa7, 3: 0xe4, 4: 0x5c}[selector]
            physical = dict(region='ROM', bank=selector, offset=0x2000)
            require(source['selector'] == selector and source['actual_value'] == value
                    and not source['block_writable'] and source['actual_physical'] == [physical]
                    and source['stored_source']['physical'] == physical
                    and source['stored_source']['value'] == value, 'physical source association differs')
        require(read(capture / f'{label}-canonical.json') == read(baseline / 'canonical-before.json'),
                'canonical instructions changed')
        emitted = read(capture / f'{label}-requested-entry-pcode.json')
        require(emitted == read(baseline / 'refreshed-requested-entry-pcode.json'),
                'emitted payload differs from actual saved E4 revision')
        request = read(capture / f'{label}-request.json')
        require(request['completed'] and request['highfunction_available'] and not request['error'],
                'native invocation failed')
        require(request['entry'] == registration['alias'] and request['owner_java_pid'] == before['java_pid'],
                'wrong alias or Java owner')
        companions = [p for p in request['processes_after']
                      if p.get('binary_sha256') == native.NATIVE and p.get('parent') == before['java_pid']]
        require(len(companions) == 1, 'wrong native binary/owner')
        debug = capture / f'{label}-debug.xml'
        require(sha(debug) == request['debug']['sha256'], 'debug hash mismatch')
        stages[label] = {
            'requested': native.check_domain(emitted, 0xe4),
            'native_high': native.check_domain(native.flatten(read(capture / f'{label}-high.json')), 0xe4, True),
            'actual_requested_binding': native.debug_identity(debug, emitted, request['entry']),
            'native_c': native.check_c(capture / f'{label}.c', 0xe4),
        }
        registrations.append(raw)
        identities.append(before)
        processes.append(dict(java_pid=before['java_pid'], java_start=before['java_start'],
                              native_pid=companions[0]['pid'], live_object_identity_hash=before['live_object_identity_hash'],
                              live_modification_number=before['live_modification_number']))
    require(registrations[0] == registrations[1], 'stored registration changed across processes')
    for key in ('program_id', 'domain_file', 'domain_file_id', 'original_image_sha256',
                'current_export_sha256', 'physical_sources', 'stored_program_instance', 'stored_revision'):
        require(identities[0][key] == identities[1][key], 'persistent identity changed: ' + key)
    require(processes[0]['java_pid'] != processes[1]['java_pid']
            and processes[0]['java_start'] != processes[1]['java_start']
            and processes[0]['native_pid'] != processes[1]['native_pid'], 'not separate processes')
    saved = read(receipts / 'saved/result.json')
    reopened = read(receipts / 'reopened/result.json')
    require(saved['end_utc'] < reopened['start_utc'], 'reopen began before save process exited')
    return dict(status='PASS', revision='actual retained refreshed F1234 bank3=E4',
                persistent_program_id=original['program_id'], domain_file_id=identities[0]['domain_file_id'],
                registration_sha256=hashlib.sha256(registrations[0]).hexdigest(),
                proof_sha256=sha(capture / 'saved-proof.json'), current_image_sha256=image_hash,
                processes=processes, stages=stages,
                identity_note='Stored proof UUID and revision remain exact; Java process, live object identity and session modification counter are recorded separately, without normalization.',
                validation_note='Installed callback performs its existing read-only proof/dependency validation. No script preview, analysis, proof replacement, install or refresh occurs.',
                baseline_sha256={name: sha(baseline / name) for name in (
                    'program.json', 'refreshed-proof.json', 'refreshed-requested-entry-pcode.json', 'refreshed-high.json', 'refreshed.c')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('capture', 'baseline', 'receipts', 'fixture', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = check(args.capture, args.baseline, args.receipts, args.fixture)
    result['checker_sha256'] = native.sha(Path(__file__))
    result['independent_executor_sha256'] = native.sha(Path(native.__file__))
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
