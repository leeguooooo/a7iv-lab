"""Pure caller-supplied byte contracts, without files, USB or execution."""
import hashlib
import unittest

import camera_install_volatile as volatile


NONCE = bytes(range(16))


def ready_row():
    row = dict.fromkeys(volatile.FIELDS, 0)
    row.update(version=2, phase=1, pid=234, ppid=1, loader_pid=123, flags=13,
               snapshot_before_status=-11, snapshot_end_status=-11)
    for phase in ('before', 'end'):
        for name in volatile.OBSERVATIONS:
            row[f'{phase}_{name}'] = -1
    return row


def patched_row():
    row = ready_row()
    row.update(phase=5, flags=765, maps_bytes=136, polls=1, base_addr=0x40000000,
               target_addr=0x40000000 + 8016, machine_version=0x0602, patched=1,
               app_pid=456, app_base_addr=0x50000000, app_target_addr=0x50000000 + 40219336,
               app_machine_version=0x00060002, app_patched=1, app_write_attempted=1,
               app_maps_bytes=120, proc_candidates=1, identity_checks=6,
               snapshot_before_status=0, snapshot_end_status=0)
    for phase in ('before', 'end'):
        for name in volatile.OBSERVATIONS:
            row[f'{phase}_{name}'] = 0
    row.update(end_slot1_mount=1, end_target_version=0x600)
    return row


def terminal_row():
    return patched_row() | dict(phase=7, identity_checks=8)


def encode(row, nonce=NONCE, magic=None):
    return volatile.FRAME.pack(magic or volatile.MAGIC, nonce,
                               *(row[name] for name in volatile.FIELDS))


def validate(ready=None, patched=None, terminal=None, **options):
    return volatile.validate_publications(encode(ready or ready_row()),
        encode(patched or patched_row()), encode(terminal or terminal_row()),
        nonce=options.pop('nonce', NONCE), loader_pid=options.pop('loader_pid', 123), **options)


class VolatileContractTests(unittest.TestCase):
    def test_v2_abi_is_exact_and_separate_from_rehearsal(self):
        self.assertEqual(volatile.MAGIC, b'M4IVP001')
        self.assertEqual(volatile.START_MAGIC, b'M4ISTART')
        self.assertEqual(volatile.VERSION, 2)
        self.assertEqual(volatile.FRAME.format, '<8s16s51q')
        self.assertEqual(volatile.FRAME.size, 432)
        self.assertEqual(len(volatile.FIELDS), 51)
        self.assertEqual(volatile.FIELDS, tuple('''version phase error euid pid ppid loader_pid cleanup
            maps_bytes polls target_addr base_addr machine_version patched restored hold_seconds flags
            mem_status restore_status app_pid app_target_addr app_base_addr app_machine_version app_patched
            app_restored app_mem_status app_restore_status app_write_attempted app_maps_bytes proc_candidates
            identity_checks lib_identity_status app_identity_status snapshot_before_status snapshot_end_status
            before_usb_stream before_network_stream before_slot1_mount before_media_error before_target_version
            before_query_error before_inhibited before_debug_exclusion end_usb_stream end_network_stream
            end_slot1_mount end_media_error end_target_version end_query_error end_inhibited
            end_debug_exclusion'''.split()))
        self.assertEqual(volatile.decode_record(encode(terminal_row()), NONCE), terminal_row())
        for magic, version in ((b'M4DWL002', 1), (volatile.MAGIC, 1)):
            with self.subTest(magic=magic, version=version):
                with self.assertRaises(ValueError):
                    volatile.decode_record(encode(terminal_row() | dict(version=version), magic=magic), NONCE)

    def test_success_reports_byte_contract_without_hardware_or_installation_proof(self):
        report = validate()
        self.assertEqual(report['state'], 'VOLATILE_PATCH_APPLIED_NOT_RESTORED')
        for name in ('RAM_restoration_proven', 'firmware_installation_proven',
                     'installation_authorized', 'device_execution_proven'):
            self.assertIs(report[name], False)
        self.assertEqual(report['nonce'], NONCE.hex())
        self.assertEqual(report['ready'], ready_row())
        self.assertEqual(report['patched'], patched_row())
        self.assertEqual(report['result'], terminal_row())
        for name, row in (('ready', ready_row()), ('patched', patched_row()), ('result', terminal_row())):
            self.assertEqual(report['publication_sha256'][name], hashlib.sha256(encode(row)).hexdigest())

    def test_maximum_complete_maps_and_positive_pid_bounds_are_accepted(self):
        ready = ready_row() | dict(pid=0x7ffffffe, loader_pid=0x7fffffff)
        patched = patched_row() | dict(pid=0x7ffffffe, loader_pid=0x7fffffff,
                                      app_pid=0x7ffffffd, maps_bytes=524288, app_maps_bytes=524288)
        terminal = patched | dict(phase=7)
        self.assertEqual(validate(ready, patched, terminal, loader_pid=0x7fffffff)['state'],
                         'VOLATILE_PATCH_APPLIED_NOT_RESTORED')

    def test_raw_lengths_nonce_and_input_types_fail_closed(self):
        raw = encode(terminal_row())
        for value, nonce in ((raw[:-1], NONCE), (raw + b'\0', NONCE),
                             (raw, bytes(16)), (raw, NONCE[:-1]), (bytearray(raw), NONCE),
                             (raw, bytearray(NONCE))):
            with self.subTest(length=len(value), nonce=nonce):
                with self.assertRaises(ValueError):
                    volatile.decode_record(value, nonce)

    def test_readiness_requires_exact_zero_target_contract(self):
        for name, value in dict(target_addr=4, base_addr=4096, app_pid=456, patched=1,
                                flags=765, maps_bytes=1, mem_status=-5,
                                snapshot_before_status=0, before_usb_stream=0).items():
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    validate(ready=ready_row() | {name: value})

    def test_each_bad_patched_field_is_rejected(self):
        mutations = dict(phase=7, flags=13, error=-5, euid=1, pid=1, ppid=123,
            loader_pid=234, cleanup=-5, maps_bytes=0, app_maps_bytes=524289, polls=0,
            base_addr=0, app_base_addr=0x50000001, target_addr=0x40000000 + 8020,
            app_target_addr=0x50000000 + 40219340, machine_version=0x0601,
            app_machine_version=0x00060001, app_pid=234, patched=0, app_patched=0,
            app_write_attempted=0, proc_candidates=2, identity_checks=0,
            mem_status=-5, app_mem_status=-5, restore_status=-5, app_restore_status=-5,
            lib_identity_status=-116, app_identity_status=-116,
            snapshot_before_status=-5, snapshot_end_status=-5, hold_seconds=1)
        for name, value in mutations.items():
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    validate(patched=patched_row() | {name: value})

    def test_restore_flags_and_contradictory_write_flags_never_prove_success(self):
        for changes in (dict(restored=1), dict(app_restored=1), dict(flags=1021),
                        dict(flags=767), dict(patched=2), dict(app_write_attempted=0),
                        dict(patched=0), dict(app_patched=0), dict(flags=637)):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    validate(terminal=terminal_row() | changes)

    def test_partial_write_failure_preserves_reverse_unwind_evidence(self):
        failed = terminal_row() | dict(phase=90, error=-5, patched=0, restored=1,
                                       app_restored=1, flags=893)
        raw = encode(failed)
        self.assertEqual(volatile.decode_record(raw, NONCE), failed)
        with self.assertRaises(ValueError):
            volatile.validate_publications(encode(ready_row()), encode(patched_row()), raw,
                                           nonce=NONCE, loader_pid=123)
        for changes in (dict(error=0), dict(flags=381), dict(app_write_attempted=0),
                        dict(restored=0), dict(phase=7, error=0)):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    volatile.decode_record(encode(failed | changes), NONCE)

    def test_failed_nonroot_lifecycle_remains_decodable_without_success(self):
        for changes in (dict(error=-13, euid=1), dict(error=-13, ppid=123),
                        dict(error=-5, cleanup=-5), dict(error=-22, loader_pid=0)):
            with self.subTest(failure=changes):
                failed = ready_row() | dict(phase=90, flags=0) | changes
                self.assertEqual(volatile.decode_record(encode(failed), NONCE), failed)
                with self.assertRaises(ValueError):
                    validate(terminal=failed)
        for publication in ('ready', 'patched', 'terminal'):
            for changes in (dict(euid=1), dict(ppid=123), dict(cleanup=-5), dict(pid=0), dict(loader_pid=0)):
                with self.subTest(publication=publication, lifecycle=changes):
                    row = {'ready': ready_row, 'patched': patched_row, 'terminal': terminal_row}[publication]()
                    with self.assertRaises(ValueError):
                        validate(**{publication: row | changes})

    def test_terminal_failures_and_nonzero_statuses_never_prove_success(self):
        for name, value in dict(phase=90, error=-5, hold_seconds=600, flags=13,
            mem_status=-5, app_mem_status=-5, lib_identity_status=-116,
            app_identity_status=-116, restore_status=-5, app_restore_status=-5,
            snapshot_before_status=-5, snapshot_end_status=-5).items():
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    validate(terminal=terminal_row() | {name: value})
        with self.assertRaises(ValueError):
            validate(terminal=terminal_row() | dict(phase=90, error=-5))

    def test_worker_targets_versions_and_maps_bind_across_publications(self):
        for name, value in dict(pid=235, loader_pid=124, app_pid=457, base_addr=0x41000000,
            target_addr=0x41000000 + 8016, app_base_addr=0x51000000,
            app_target_addr=0x51000000 + 40219336, maps_bytes=137,
            app_maps_bytes=121, identity_checks=5).items():
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    validate(terminal=terminal_row() | {name: value})
        with self.assertRaises(ValueError):
            validate(loader_pid=124)
        for invalid in (True, 1, 0x80000000):
            with self.subTest(loader=invalid):
                with self.assertRaises(ValueError):
                    validate(loader_pid=invalid)
        with self.assertRaises(ValueError):
            volatile.validate_publications(encode(ready_row()), encode(patched_row(), b'x' * 16),
                                           encode(terminal_row()), nonce=NONCE, loader_pid=123)

    def test_observation_widths_and_snapshot_binding_without_zero_assumption(self):
        patched = patched_row() | dict(before_usb_stream=0xffffffff, end_inhibited=255)
        terminal = patched | dict(phase=7, identity_checks=8)
        self.assertEqual(validate(patched=patched, terminal=terminal)['state'],
                         'VOLATILE_PATCH_APPLIED_NOT_RESTORED')
        for name, value in dict(before_usb_stream=-1, end_target_version=1 << 32,
                                before_inhibited=256, end_debug_exclusion=-1).items():
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    validate(patched=patched_row() | {name: value})
        with self.assertRaises(ValueError):
            validate(terminal=terminal_row() | dict(end_slot1_mount=0))


if __name__ == '__main__':
    unittest.main()
