"""Immutable package identities for offline review, never install permission.

The existing installation journal still accepts only its legacy binding. New
profile registration alone does not enable that candidate in device actors.
"""
from dataclasses import dataclass
import re
from types import MappingProxyType


@dataclass(frozen=True)
class CandidateProfile:
    name: str
    package_sha256: str
    package_bytes: int
    plaintext_sha256: str
    plaintext_bytes: int
    AP_sha256: str
    AP_bytes: int
    role: str
    model_code: int = 0x01030081
    region: int = 0
    checksum_tables: int = 10
    regular_CRC_rows: int = 115
    signing_identity: str = 'INTENTIONALLY_PUBLIC_RESEARCH_KEY_NOT_SONY'


LEGACY = CandidateProfile(
    'FL23_V7',
    'fc8a7865c95059dcb4ac2a347a06b4a76f016b9c37dcc8412dfe9c2c2111de6a', 757480856,
    'ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf', 754521088,
    'd17e61fb4ba193d8e7d802196edff5f578d5691b3fcc4abcd1cbbb6e58bdd8ff', 98212632,
    'FL23_BASELINE')
OBSERVER = CandidateProfile(
    'AP_OBSERVER_20261101',
    '443acbe1a9913c4bdd5b98b09617ff33f92e121fdc6b000e9d42c6da285154ca', 916391320,
    '44c586cde31e3d6e9839cc83f8cb6f7b0a8c6dad89d9411ca74e744c0be54f2f', 912811008,
    '228b5dd694b25f946485c448fc3714b71d699556a1990cad9db73c3e550fc503', 175701968,
    'DIAGNOSTIC_MESSAGE_OBSERVER_NOT_CUSTOM_SOUND')
PROFILES = MappingProxyType({p.package_sha256: p for p in (LEGACY, OBSERVER)})
SHA = re.compile(r'[0-9a-f]{64}\Z')


def profile_for_digest(digest):
    if not isinstance(digest, str) or digest not in PROFILES:
        raise ValueError('Unknown signed package identity')
    return PROFILES[digest]


def profile_for_binding(binding):
    """Resolve identities without changing journal bytes or opening a flow.

    Three fields always mean the legacy package, regardless of any other default.
    Four fields explicitly select a registered final signed package identity.
    """
    base = {'body_sha256', 'plan_sha256', 'model'}
    if (not isinstance(binding, dict) or set(binding) not in (base, base | {'candidate_sha256'})
            or binding.get('model') != 'ILCE-7M4'
            or any(not isinstance(binding.get(k), str) or not SHA.fullmatch(binding[k])
                   for k in ('body_sha256', 'plan_sha256'))):
        raise ValueError('Exact body/plan/model/candidate binding required')
    return profile_for_digest(binding['candidate_sha256']) if 'candidate_sha256' in binding else LEGACY


def require_matching_candidate(binding, candidate_sha256):
    profile = profile_for_binding(binding)
    if candidate_sha256 != profile.package_sha256:
        raise ValueError('Candidate differs from the bound package')
    return profile


def report_binding_fields(binding):
    """Construct candidate evidence once, avoiding duplicate keyword overrides."""
    profile = profile_for_binding(binding)
    fields = dict(binding)
    if 'candidate_sha256' not in fields:
        fields['candidate_sha256'] = profile.package_sha256
    return fields
