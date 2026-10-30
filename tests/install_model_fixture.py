"""Synthetic phase fixtures for tests that are not testing installation admission.

Only the explicit test schema is accepted by scoped semantic-validator mocks.
The real state graph, durable ledger and artifact hashes remain in use. These
fixtures make no hardware or installation claims and must never enter a device.
"""
import json
from unittest.mock import patch

import camera_install_journal as ledger
from camera_install_receipts import load_reference, canonical, sha
import camera_install_admission as admission
import camera_install_completion as completion

SCHEMA = 'camera-install-host-test-phase-fixture/1'


def _install(case):
    if getattr(case, '_phase_fixture_installed', False):
        return
    case._phase_fixture_installed = True
    for module, name in ((admission, 'validate_admission_receipt'), (admission, 'validate_start_intent'),
                         (completion, 'validate_completion_receipt'),
                         (completion, 'validate_start_intent'), (completion, 'validate_admission_receipt')):
        original = getattr(module, name)
        def validator(reference, *args, _original=original, **kwargs):
            _, value = load_reference(reference)
            if value.get('schema') == SCHEMA and value.get('model_fixture_only') is True and value.get('source_is_hardware') is False:
                return value
            return _original(reference, *args, **kwargs)
        case.enterContext(patch.object(module, name, validator))
    original = ledger._install_patch_details
    def pending(details, binding, history):
        _, value = load_reference(details.get('install_patch_artifact'))
        if value.get('schema') == SCHEMA and value.get('model_fixture_only') is True and value.get('source_is_hardware') is False:
            ledger._require(details.get('complete_receipt_sha256') == sha(canonical(value)), 'Test fixture payload changed')
            return value
        return original(details, binding, history)
    case.enterContext(patch.object(ledger, '_install_patch_details', pending))


def _artifact(journal, name):
    path = journal.session_dir.parent.parent / f'model-{journal.session_dir.name}-{len(journal.events)}-{name}.json'
    value = dict(schema=SCHEMA, model_fixture_only=True, source_is_hardware=False,
                 installation_authorized=False, session_id=journal.session_dir.name, **journal.binding)
    if name == 'admission':
        pending = journal.events[-1]['details']['install_patch_artifact']
        value['references'] = dict(runtime=pending, approval=pending)
    if name == 'start':
        ready = journal.events[-1]
        value.update(ready_event_sha256=ready['event_sha256'],
                     admission_reference=ready['details']['admission_artifact'])
    path.write_text(json.dumps(value))
    return path, dict(path=str(path), sha256=sha(path.read_bytes())), sha(canonical(value))


def formal_ready(case, journal):
    _install(case)
    if journal.state == 'PLANNED':journal.advance('SD_STAGE_INTENT')
    if journal.state == 'SD_STAGE_INTENT':journal.advance('SD_STAGED')
    if journal.state == 'SD_STAGED':journal.advance('INSTALL_PATCH_MAY_BE_ACTIVE')
    if journal.state == 'INSTALL_PATCH_MAY_BE_ACTIVE':
        _, ref, payload = _artifact(journal, 'pending')
        journal._append('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',
                        dict(install_patch_artifact=ref, complete_receipt_sha256=payload))
    if journal.state == 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT':
        path, _, _ = _artifact(journal, 'admission')
        journal.record_install_admission(path)
    case.assertEqual(journal.state, 'INSTALL_READY_FOR_OPERATOR_START')


def formal_flash(case, journal):
    if journal.state != 'INSTALL_READY_FOR_OPERATOR_START':formal_ready(case, journal)
    path, _, _ = _artifact(journal, 'start')
    journal.record_flash_may_have_started(path)
    case.assertEqual(journal.state, 'FLASH_MAY_HAVE_STARTED')


def formal_complete(case, journal):
    if journal.state != 'FLASH_MAY_HAVE_STARTED':formal_flash(case, journal)
    path, _, _ = _artifact(journal, 'completion')
    journal.record_device_completion(path)
    case.assertEqual(journal.state, 'DEVICE_COMPLETION_REPORTED')
