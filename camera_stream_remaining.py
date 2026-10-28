"""Offline-prepared fixed remaining profiles using the proven stream protocol.

No discovery, USB entry point or module selection from arbitrary user paths.
Default pilot APIs continue to reject these larger targets.
"""
from camera_stream_profiles import PROFILES, profile
from camera_stream_receiver import StreamReceiver
from camera_stream_collect import _collect_profile
from camera_stream_execution import BootstrapChannel, _execute_profile


class RemainingReceiver(StreamReceiver):
    ALLOWED_TARGETS = tuple(p.target for p in PROFILES)


class RemainingChannel(BootstrapChannel):
    def __init__(self, device, nonce, target_name, **kwargs):
        self.profile = profile(target_name)
        super().__init__(device, nonce, **kwargs)
        self.ACK_CHUNKS = self.profile.chunks


def collect_remaining(channel, directory, **kwargs):
    selected = profile(channel.profile.name)
    if channel.profile != selected:
        raise ValueError("Remaining profile changed")
    return _collect_profile(channel, directory, selected.target, RemainingReceiver, **kwargs)


def execute_remaining_authenticated(channel, module, expected_hash, evidence, **kwargs):
    selected = profile(channel.profile.name)
    if channel.profile != selected:
        raise ValueError("Remaining profile changed")
    return _execute_profile(channel, module, expected_hash, evidence,
                            selected.target, selected.chunks, collect_remaining, **kwargs)
