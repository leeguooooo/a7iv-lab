from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stock_p1_write_outcome import Proposal, FRAME
from stock_p1_writer_boundary import WriterTerminalBoundary
from stock_p1_readback import execute_after_writer_authenticated


class BoundaryTests(unittest.TestCase):
    proposal = Proposal(bytes(range(16)), 1, 3, 7120, '1' * 64, '2' * 64)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        patcher = patch('stock_p1_readback.GLOBAL_ATTEMPT', Path(temporary.name) / 'readback-claim.json')
        patcher.start();self.addCleanup(patcher.stop)

    def receipt(self, *, ready=False, pid=234, loader=123, io=0):
        p = self.proposal
        return FRAME.pack(b'M4P1WR01', p.nonce, 1, 2 if ready else (90 if io else 6),
                          io, 0, pid, 1, loader, 0, 1, 3, 0 if ready else 3,
                          0 if ready else 7120, 0, 3 if ready else 255, io,
                          bytes(32) if ready else bytes.fromhex(p.source_sha256),
                          bytes(32) if ready else bytes.fromhex(p.target_sha256))

    def boundary(self):
        channel = SimpleNamespace(nonce=self.proposal.nonce, healthy=True, device=object())
        return WriterTerminalBoundary(self.proposal, channel, self.receipt(ready=True))

    def test_missing_terminal_receipt_never_admits_readback(self):
        guard = self.boundary()
        with self.assertRaises(RuntimeError):
            guard.reserve_readback(b'x' * 16)

    def test_transport_unknown_even_with_cached_final_never_admits_readback(self):
        guard = self.boundary()
        guard.observe_final(self.receipt())
        guard.channel.healthy = False
        with self.assertRaises(RuntimeError):
            guard.reserve_readback(b'x' * 16)
        with self.assertRaises(RuntimeError):
            guard.observe_final(self.receipt())

    def test_final_process_must_match_precommit_ready(self):
        for raw in (self.receipt(pid=235), self.receipt(loader=124)):
            guard = self.boundary()
            with self.assertRaises(ValueError):
                guard.observe_final(raw)
            self.assertIsNone(guard.final_receipt)

    def test_close_failure_does_not_admit_readback(self):
        guard = self.boundary()
        with self.assertRaises(ValueError):
            guard.observe_final(self.receipt(io=-5))
        self.assertIsNone(guard.final_receipt)

    def test_readback_reservation_is_one_shot_and_nonce_separated(self):
        guard = self.boundary()
        guard.observe_final(self.receipt())
        with self.assertRaises(ValueError):
            guard.reserve_readback(self.proposal.nonce)
        guard.reserve_readback(b'x' * 16)
        with self.assertRaises(RuntimeError):
            guard.reserve_readback(b'y' * 16)

    def test_invalid_ready_rejected_before_any_session(self):
        guard = self.boundary()
        for raw in (b'', self.receipt(), self.receipt(ready=True, pid=123)):
            with self.assertRaises(ValueError):
                WriterTerminalBoundary(self.proposal, guard.channel, raw)

    def test_unknown_never_reaches_injected_execution(self):
        guard = self.boundary()
        with patch('stock_p1_readback._execute_profile') as execute:
            with self.assertRaises(RuntimeError):
                execute_after_writer_authenticated(guard, '/unused')
            execute.assert_not_called()

    def test_known_terminal_uses_exact_frozen_module_once(self):
        guard = self.boundary()
        guard.observe_final(self.receipt())
        with patch('stock_p1_readback._execute_profile', return_value='verified') as execute:
            self.assertEqual(execute_after_writer_authenticated(guard, '/unused'), 'verified')
            channel, module, digest, *_ = execute.call_args.args
            self.assertIs(channel.device, guard.channel.device)
            self.assertEqual(len(module), 12752)
            self.assertEqual(digest, '51b7fd1006e93f944c6a85441e6578ee926d9fbcc2e93fcb8bdb88cf39fb5e7d')
            with self.assertRaises(RuntimeError):
                execute_after_writer_authenticated(guard, '/unused')
            self.assertEqual(execute.call_count, 1)

    def test_readback_failure_poison_previous_channel_without_retry(self):
        guard = self.boundary()
        guard.observe_final(self.receipt())
        with patch('stock_p1_readback._execute_profile', side_effect=OSError('unknown')) as execute:
            with self.assertRaises(OSError):
                execute_after_writer_authenticated(guard, '/unused')
            self.assertFalse(guard.channel.healthy)
            with self.assertRaises(RuntimeError):
                execute_after_writer_authenticated(guard, '/unused')
            self.assertEqual(execute.call_count, 1)

    def test_readback_compiled_nonce_cannot_replay_via_another_boundary(self):
        first, second = self.boundary(), self.boundary()
        first.observe_final(self.receipt());second.observe_final(self.receipt())
        with patch('stock_p1_readback._execute_profile', return_value='verified') as execute:
            execute_after_writer_authenticated(first, '/unused')
            with self.assertRaises(FileExistsError):
                execute_after_writer_authenticated(second, '/another-folder')
            self.assertEqual(execute.call_count, 1)


if __name__ == '__main__':
    unittest.main()
