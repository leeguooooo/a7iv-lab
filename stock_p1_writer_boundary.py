"""Pure host guard: a lost COMMIT outcome never authorizes a new USB job.

Caller must bind channel and ready bytes to the reviewed native writer before
COMMIT. No USB commands, writes, rollback, reset, or exit operations live here.
"""
from stock_p1_write_outcome import FRAME, FIELDS, classify, decode_final


class WriterTerminalBoundary:
    def __init__(self, proposal, channel, ready_receipt):
        if not isinstance(ready_receipt, bytes) or len(ready_receipt) != FRAME.size:
            raise ValueError('Complete immutable writer readiness required')
        magic, nonce, *values = FRAME.unpack(ready_receipt)
        state = dict(zip(FIELDS, values[:15]))
        if (magic != b'M4P1WR01' or nonce != proposal.nonce or state['version'] != 1
                or state['phase'] != 2 or state['error'] or state['euid'] or state['ppid'] != 1
                or state['pid'] <= 1 or state['loader_pid'] <= 1 or state['pid'] == state['loader_pid']
                or state['cleanup'] or state['mode'] != proposal.mode or state['rows'] != proposal.rows
                or state['write_calls'] or state['write_bytes'] or state['rollback']
                or state['io_status'] or state['flags'] != 3
                or values[15:] != [bytes(32), bytes(32)]
                or channel.nonce != proposal.nonce or channel.healthy is not True):
            raise ValueError('Writer readiness/channel not bound to fixed proposal')
        self.proposal, self.channel = proposal, channel
        self.identity = state['pid'], state['loader_pid']
        self.final_receipt = None
        self.readback_reserved = False

    def observe_final(self, raw):
        if self.channel.healthy is not True:
            raise RuntimeError('Unknown channel outcome; no further job admitted')
        if not isinstance(raw, bytes):
            raise ValueError('Immutable terminal receipt required')
        state = decode_final(raw, self.proposal)
        if (state['pid'], state['loader_pid']) != self.identity:
            raise ValueError('Writer final identity differs from pre-COMMIT readiness')
        outcome = classify(self.proposal, raw)
        if not outcome['native_writer_terminal_proven']:
            raise ValueError('Writer descriptor closure not proven')
        if self.final_receipt is not None and self.final_receipt != raw:
            raise ValueError('Conflicting writer terminal receipts')
        self.final_receipt = raw
        return outcome

    def reserve_readback(self, nonce):
        if (self.channel.healthy is not True or self.final_receipt is None
                or self.readback_reserved):
            raise RuntimeError('Readback requires a known healthy terminal writer; no replay')
        if not isinstance(nonce, bytes) or len(nonce) != 16 or nonce == self.proposal.nonce:
            raise ValueError('Separate readback nonce required')
        self.readback_reserved = True
