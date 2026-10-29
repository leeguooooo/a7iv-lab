"""Synthetic, complete binary publications only; no files or device access."""
import copy
import hashlib
import json
import unittest

import camera_install_volatile as prior
import camera_install_patch_read as read


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def pending_fixture():
    nonce = bytes(range(16))
    ready = dict.fromkeys(prior.FIELDS, 0)
    ready.update(version=2, phase=1, pid=234, ppid=1, loader_pid=123, flags=13,
                 snapshot_before_status=-11, snapshot_end_status=-11)
    ready.update({name: -1 for name in prior.SNAPSHOT_FIELDS})
    patched = ready | dict(phase=5, flags=765, maps_bytes=136, app_maps_bytes=120, polls=1,
        base_addr=0x40000000, target_addr=0x40000000 + 8016, machine_version=0x602, patched=1,
        app_pid=456, app_base_addr=0x50000000, app_target_addr=0x50000000 + 40219336,
        app_machine_version=0x60002, app_patched=1, app_write_attempted=1,
        proc_candidates=1, identity_checks=6, snapshot_before_status=0, snapshot_end_status=0)
    patched.update({name: 0 for name in prior.SNAPSHOT_FIELDS})
    final = patched | dict(phase=7, identity_checks=8)
    raws = {name: prior.FRAME.pack(prior.MAGIC, nonce, *(row[k] for k in prior.FIELDS))
            for name, row in (('ready', ready), ('patched', patched), ('result', final))}
    binding = dict(body_sha256='b' * 64, plan_sha256='a' * 64, model='ILCE-7M4')
    assets = dict(schema='camera-install-patch-assets/1', patch=dict(nonce=nonce.hex(),
        directory='/MODEL_ONLY/patch', job_dir='/tmp_wbshd/m4ivp_' + nonce.hex(),
        manifest_sha256='1' * 64, module_sha256='2' * 64, native_model_sha256='3' * 64,
        bootstrap_model_sha256='4' * 64), captures=dict(directory='/MODEL_ONLY/captures',
        pre_app=dict(nonce='5' * 32, manifest_sha256='6' * 64, module_sha256='7' * 64),
        pre_ufp=dict(nonce='8' * 32, manifest_sha256='9' * 64, module_sha256='a' * 64)))
    native = prior.validate_publications(raws['ready'], raws['patched'], raws['result'], nonce=nonce, loader_pid=123)
    native.update(**binding, loader_pid=123, asset_reference=assets, reservation={'model_fixture_only': True},
        raw_publications={name: raw.hex() for name, raw in raws.items()}, source_is_hardware=False,
        scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY', service_exit_completed=False)
    terminal = dict(schema='camera-install-patch-session-receipt/1',
        state='INSTALL_PATCH_TERMINAL_DURABLE_BEFORE_STOP', **binding, session_id='MODEL_ONLY_PRIOR',
        intent_event_sha256='c' * 64, consent_scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY',
        patches_remain_acknowledged=True, asset_reference=assets, reservation=native['reservation'],
        review_artifact=dict(path='/MODEL_ONLY/plan.json', sha256=binding['plan_sha256'], payload_sha256='e' * 64),
        lease_identity=dict(device=0, inode=0, instance='f' * 32), native_receipt=native,
        native_receipt_sha256=hashlib.sha256(canonical(native)).hexdigest(), source_is_hardware=False,
        installation_authorized=False, firmware_installation_proven=False, RAM_restoration_proven=False,
        normal_body_reappearance_verified=False, device_execution_proven=False, hardware_admission_proven=False)
    pending = terminal | dict(state='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',
        terminal_artifact=dict(path='/MODEL_ONLY/terminal.json', sha256='1' * 64,
                               payload_sha256=hashlib.sha256(canonical(terminal)).hexdigest()),
        service_events=[dict(event='STOP_RESPONSE', mode='service', success=True, model_fixture_only=True)],
        service_exit_completed=True, model_fixture_only=True)
    terminal['model_fixture_only'] = True
    pending['terminal_artifact']['payload_sha256'] = hashlib.sha256(canonical(terminal)).hexdigest()
    return pending


def spec_fixture():
    return read.target_spec(canonical(pending_fixture()), body_sha256='b' * 64, plan_sha256='a' * 64)


def rows(spec, states=('ORIGINAL', 'ORIGINAL')):
    ready = dict.fromkeys(read.FIELDS, 0)
    ready.update(version=1, phase=1, pid=789, ppid=1, loader_pid=678, flags=read.READY_FLAGS)
    for name in ('lib', 'app'):
        target = spec['targets'][name]
        for field in ('pid', 'base_addr', 'target_addr'):
            ready[f'{name}_{field}'] = target[field]
    result = ready | dict(phase=7, flags=read.COMPLETE_FLAGS, passes=2)
    for name, state in zip(('lib', 'app'), states):
        target = spec['targets'][name]
        word = int.from_bytes(bytes.fromhex(target['original_hex'] if state == 'ORIGINAL' else target['patch_hex']), 'little')
        if state == 'OTHER':
            word = 0xdeadbeef
        result.update({f'{name}_maps_before_bytes': 136, f'{name}_maps_after_bytes': 136,
            f'{name}_start_before': 123456, f'{name}_start_after': 123456,
            f'{name}_word_before': word, f'{name}_word_after': word,
            f'{name}_version_before': target['stock_version'], f'{name}_version_after': target['stock_version'],
            f'{name}_mem_closed': 1})
    return ready, result


def pack(row, spec, nonce=b'r' * 16):
    return read.FRAME.pack(read.MAGIC, nonce, bytes.fromhex(spec['original_patch_nonce']),
                           bytes.fromhex(read.spec_sha256(spec)), *(row[k] for k in read.FIELDS))


def validate(spec, ready, result, nonce=b'r' * 16):
    return read.validate_publications(pack(ready, spec, nonce), pack(result, spec, nonce),
                                      nonce=nonce, loader_pid=678, spec=spec)


class PatchReadTests(unittest.TestCase):
    def test_fixed_spec_comes_from_complete_prior_binary_receipts(self):
        spec = spec_fixture()
        self.assertEqual(spec['targets']['lib']['pid'], 123)
        self.assertEqual(spec['targets']['app']['pid'], 456)
        self.assertEqual(spec['targets']['lib']['target_addr'], 0x40000000 + 8016)
        self.assertEqual(spec['targets']['app']['target_addr'], 0x50000000 + 40219336)
        self.assertFalse(spec['original_source_is_hardware'])
        self.assertFalse(spec['original_hardware_origin_proven'])
        self.assertEqual(read.FRAME.format, '<8s16s16s32s44q')
        self.assertEqual(read.FRAME.size, 424)
        self.assertEqual(read.START_FRAME.size, 48)

    def test_original_patched_mixed_and_other_are_observations_without_authority(self):
        spec = spec_fixture()
        for states, expected in ((('ORIGINAL', 'ORIGINAL'), 'ORIGINAL'),
                                 (('PATCHED', 'PATCHED'), 'PATCHED'),
                                 (('ORIGINAL', 'PATCHED'), 'MIXED'), (('OTHER', 'ORIGINAL'), 'OTHER')):
            with self.subTest(states=states):
                proof = validate(spec, *rows(spec, states))
                self.assertEqual(proof['observation'], expected)
                self.assertEqual(proof['targets']['lib']['observation'], states[0])
                for key in ('original_mm_continuity_proven', 'RAM_restoration_proven', 'cancellation_authorized',
                            'device_execution_proven', 'hardware_admission_proven',
                            'firmware_installation_proven', 'installation_authorized', 'ready_for_confirmation'):
                    self.assertIs(proof[key], False)

    def test_forged_prior_target_nonce_source_and_truncation_are_rejected(self):
        pending = pending_fixture()
        candidates = []
        for name, value in (('source_is_hardware', True), ('device_execution_proven', True),
                            ('state', 'READY_FOR_CONFIRMATION'), ('lease_identity', {}), ('reservation', {})):
            candidates.append(pending | {name: value})
        for field, value in (('nonce', '1' * 32), ('raw_publications', {})):
            changed = copy.deepcopy(pending)
            changed['native_receipt'][field] = value
            changed['native_receipt_sha256'] = hashlib.sha256(canonical(changed['native_receipt'])).hexdigest()
            candidates.append(changed)
        for changed in candidates:
            with self.subTest(changed=changed['state']):
                with self.assertRaises(ValueError):
                    read.target_spec(canonical(changed), body_sha256='b' * 64, plan_sha256='a' * 64)
        with self.assertRaises(ValueError):
            read.target_spec(canonical(pending)[:-1], body_sha256='b' * 64, plan_sha256='a' * 64)
        with self.assertRaises(ValueError):
            read.target_spec(canonical(pending), body_sha256='c' * 64, plan_sha256='a' * 64)

    def test_spec_target_mutation_cannot_create_an_arbitrary_read(self):
        spec = spec_fixture()
        forged = copy.deepcopy(spec)
        forged['targets']['lib']['pid'] = 999
        ready, result = rows(forged)
        with self.assertRaises(ValueError):
            validate(forged, ready, result)

    def test_malformed_spec_and_inconsistent_original_metadata_fail_closed(self):
        spec = spec_fixture()
        for malformed in (None, {}, spec | dict(pending_receipt_raw_hex=None),
                          spec | dict(pending_receipt_raw_hex='0')):
            with self.subTest(spec=type(malformed)):
                with self.assertRaises(ValueError):
                    read.validate_target_spec(malformed)
        pending = pending_fixture()
        pending['native_receipt']['result']['target_addr'] += 4
        pending['native_receipt_sha256'] = hashlib.sha256(canonical(pending['native_receipt'])).hexdigest()
        with self.assertRaises(ValueError):
            read.target_spec(canonical(pending), body_sha256='b' * 64, plan_sha256='a' * 64)

    def test_context_changes_and_failed_close_cannot_produce_stable_observation(self):
        spec = spec_fixture()
        ready, result = rows(spec)
        mutations = dict(lib_start_after=123457, app_word_after=0, lib_maps_status=-116,
            app_anchor_after_status=-84, app_stat_status=-5, lib_mem_status=-5,
            app_mem_closed=0, lib_maps_before_bytes=524289, app_version_after=0x60001,
            lib_pid=124, app_base_addr=0x60000000, passes=1, flags=13, pid=790)
        for name, value in mutations.items():
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    validate(spec, ready, result | {name: value})

    def test_phase90_failures_remain_decodable_but_never_validate_success(self):
        spec = spec_fixture()
        ready, result = rows(spec)
        failed = result | dict(phase=90, error=-3, euid=1, lib_stat_status=-3, lib_mem_closed=0, flags=13)
        raw = pack(failed, spec)
        self.assertEqual(read.decode_record(raw, b'r' * 16, spec), failed)
        with self.assertRaises(ValueError):
            validate(spec, ready, failed)

    def test_read_nonce_prior_nonce_digest_and_length_are_bound(self):
        spec = spec_fixture()
        ready, result = rows(spec)
        raw = pack(result, spec)
        for malformed in (raw[:-1], raw + b'\0', raw[:8] + b'x' * 16 + raw[24:],
                          raw[:24] + b'x' * 16 + raw[40:], raw[:40] + bytes(32) + raw[72:]):
            with self.subTest(length=len(malformed)):
                with self.assertRaises(ValueError):
                    read.decode_record(malformed, b'r' * 16, spec)
        with self.assertRaises(ValueError):
            read.decode_record(pack(result, spec, bytes.fromhex(spec['original_patch_nonce'])),
                               bytes.fromhex(spec['original_patch_nonce']), spec)


if __name__ == '__main__':
    unittest.main()
