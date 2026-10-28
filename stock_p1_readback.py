"""Fixed P1 readback on an already authenticated channel; no connection entry point.

Worker/bootstrap artifacts are prepared offline. These host classes alone do
not admit a hardware operation or prove current camera/session identity.
"""
from camera_stream_collect import _collect_profile, NATIVE, native_status
from camera_stream_execution import BootstrapChannel, LAUNCH, validate_launch, _execute_profile, durable_new
from camera_stream_receiver import StreamReceiver
from stock_p1_readback_plan import BASE

TARGET = ('cnflasha1', 129, 25100288)
CHUNKS = 3
GLOBAL_ATTEMPT = BASE / 'fixed-readback-attempt.json'


class P1ReadbackReceiver(StreamReceiver):
    ALLOWED_TARGETS = (TARGET,)


class P1ReadbackChannel(BootstrapChannel):
    def __init__(self, device, nonce, *, writer_nonce, **kwargs):
        if (not isinstance(writer_nonce, bytes) or len(writer_nonce) != 16
                or not isinstance(nonce, bytes) or len(nonce) != 16 or nonce == writer_nonce):
            raise ValueError('Independent P1 readback needs a distinct bound nonce')
        super().__init__(device, nonce, **kwargs)
        self.ACK_CHUNKS = CHUNKS
        self.writer_nonce = writer_nonce
        self.loader_pid = None
        self.worker_identity = None

    def read(self, name, missing=False):
        raw = super().read(name, missing)
        try:
            if name == 'launch' and raw is not None and len(raw) == LAUNCH.size:
                self.loader_pid = validate_launch(raw, self.nonce)
            if name in ('ready', 'result') and raw is not None and len(raw) == NATIVE.size:
                state = native_status(raw, self.nonce)
                identity = state['pid'], state['loader_pid']
                if (state['pid'] <= 1 or state['pid'] == state['loader_pid'] or state['euid'] != 0
                        or state['ppid'] != 1 or state['loader_pid'] != self.loader_pid or state['cleanup']):
                    raise ValueError('Readback process identity differs')
                if name == 'ready':
                    if state['phase'] != 1 or state['error'] or state['flags'] != 3:
                        raise ValueError('Readback readiness rejected')
                    if self.worker_identity is not None and self.worker_identity != identity:
                        raise ValueError('Readback readiness identity changed')
                    self.worker_identity = identity
                elif self.worker_identity != identity:
                    raise ValueError('Readback final identity not bound to readiness')
            return raw
        except BaseException:
            self.healthy = False
            raise


def collect_p1_readback(channel, directory, **kwargs):
    return _collect_profile(channel, directory, TARGET, P1ReadbackReceiver, **kwargs)


def execute_after_writer_authenticated(boundary, evidence, *, source_is_hardware=False, **kwargs):
    """Injected-channel only. Caller owns body identity and explicit operation approval.

    A missing final receipt or unhealthy preceding channel is rejected before
    any camera access. No reconnect, reboot, write retry or host rollback exists.
    """
    from stock_p1_readback_plan import validate
    if type(source_is_hardware) is not bool:
        raise ValueError('Explicit source evidence kind required')
    manifest, module = validate()
    nonce = bytes.fromhex(manifest['nonce'])
    boundary.reserve_readback(nonce)
    durable_new(GLOBAL_ATTEMPT, {'reader_nonce': nonce.hex(),
        'writer_nonce': boundary.proposal.nonce.hex(), 'source_is_hardware': source_is_hardware,
        'state': 'RESERVED_BEFORE_ANY_READBACK_USB', 'automatic_retry': False})
    channel = P1ReadbackChannel(boundary.channel.device, nonce,
                                writer_nonce=boundary.proposal.nonce)
    channel.source_is_hardware = source_is_hardware
    try:
        return _execute_profile(channel, module, manifest['module']['sha256'], evidence,
                                TARGET, CHUNKS, collect_p1_readback, **kwargs)
    except BaseException:
        boundary.channel.healthy = False
        raise
