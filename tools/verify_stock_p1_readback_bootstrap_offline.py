"""Independent reconstruction of compact ELF and embedded readback worker."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from elftools.elf.elffile import ELFFile
from stock_p1_readback_plan import BASE, validate, require


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    m, module = validate()
    raw = (BASE / 'prod/worker.debug.elf').read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    headers = [dict(s.header) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    expected = bytearray(raw[:max(h['p_offset'] + h['p_filesz'] for h in headers)])
    struct.pack_into('<Q', expected, 40, 0)
    struct.pack_into('<3H', expected, 58, 0, 0, 0)
    compact = (BASE / 'bootstrap/worker.elf').read_bytes()
    require(compact == expected, 'Compact worker differs from independent reconstruction')
    ce = ELFFile(io.BytesIO(compact))
    require([dict(s.header) for s in ce.iter_segments() if s['p_type'] == 'PT_LOAD'] == headers
            and ce['e_entry'] == elf['e_entry'], 'Runtime mappings/entry changed')
    require(module.count(compact) == 1, 'Exact worker not embedded once')
    tiny = json.loads((BASE / 'test/job.json').read_text())
    prod = json.loads((BASE / 'prod/job.json').read_text())
    require(tiny['derived_source_sha256'] == prod['derived_source_sha256']
            and tiny['target_header_sha256'] == prod['target_header_sha256']
            and tiny['shared_sources'] == prod['shared_sources'], 'Tiny/production source differs')
    cases = {}
    for name in ('test', 'prod', 'bootstrap'):
        cases[name] = len(json.loads((BASE / name / 'emulation.json').read_text())['tests'])
    result = dict(all_passed=True, module_sha256=sha(module), module_bytes=len(module),
                  compact_sha256=sha(compact), independent_compact_reconstruction_matches=True,
                  program_headers_and_entry_preserved=True, native_cases=cases,
                  production_full_size_success_emulated=False, hardware_operations=0,
                  hardware_acceptance=False, P1_writer_executor_present=False,
                  unknown_after_COMMIT_reconciliation_proven=False,
                  verifier_sha256=sha(Path(__file__).read_bytes()))
    destination = BASE / 'bootstrap/independent-root-audit.json'
    with destination.open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(result, f, indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    for path in [BASE, *BASE.rglob('*')]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
