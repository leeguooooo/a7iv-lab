import unittest
from stock_p1_write_outcome import FRAME, Proposal, classify


class OutcomeTests(unittest.TestCase):
    p = Proposal(bytes(range(16)), 1, 2, 8192, "1" * 64, "2" * 64)

    def receipt(self, *, phase=6, error=0, calls=2, written=8192, rollback=0, flags=255, after=None, io=0):
        return FRAME.pack(b"M4P1WR01", self.p.nonce, 1, phase, error, 0, 234, 1, 123, 0,
                          1, 2, calls, written, rollback, flags, io,
                          bytes.fromhex(self.p.source_sha256), bytes.fromhex(after or self.p.target_sha256))

    def read(self, value=None):
        digest = value or self.p.target_sha256
        return {"bytes": 25100288, "camera_body_matched": True, "source_reads_equal": True,
                "host_readback_verified": True, "reader_nonce": "f" * 32,
                "first_sha256": digest, "second_sha256": digest, "host_sha256": digest}

    def test_unknown_never_releases_power_or_mutates_even_if_target_observed(self):
        result = classify(self.p, independent_read=self.read())
        self.assertFalse(result["native_writer_terminal_proven"])
        self.assertFalse(result["evidence_supports_session_end"])
        self.assertFalse(result["automatic_recommit"])
        self.assertFalse(result["automatic_host_rollback"])

    def test_short_write_or_EINTR_calls_need_not_equal_window_count(self):
        result = classify(self.p, self.receipt(calls=7), self.read())
        self.assertEqual(result["state"], "TARGET_VERIFIED_AND_INDEPENDENTLY_RECONCILED")

    def test_native_success_alone_still_requires_independent_read(self):
        self.assertFalse(classify(self.p, self.receipt())["evidence_supports_session_end"])

    def test_wrong_nonce_and_nonterminal_receipt_rejected(self):
        b = bytearray(self.receipt());b[8] ^= 1
        for raw in (bytes(b), self.receipt(phase=3), self.receipt()[:-1]):
            with self.assertRaises(ValueError):
                classify(self.p, raw)

    def test_native_rollback_and_original_read(self):
        r = self.receipt(phase=90, error=-5, calls=3, written=12288, rollback=1,
                         flags=63, after=self.p.source_sha256)
        self.assertEqual(classify(self.p, r, self.read(self.p.source_sha256))["state"],
                         "ORIGINAL_VERIFIED_AFTER_NATIVE_ROLLBACK")

    def test_rollback_failed_never_claims_recovery(self):
        r = self.receipt(phase=90, error=-5, calls=3, written=12288, rollback=2, flags=63,
                         after="3" * 64)
        self.assertFalse(classify(self.p, r, self.read(self.p.source_sha256))["evidence_supports_session_end"])

    def test_conflicting_readback_is_not_success(self):
        result = classify(self.p, self.receipt(), self.read(self.p.source_sha256))
        self.assertEqual(result["state"], "NATIVE_AND_INDEPENDENT_READ_CONTRADICT")

    def test_partial_or_reused_reader_not_accepted(self):
        for values in ({"bytes": 4096}, {"reader_nonce": self.p.nonce.hex()},
                       {"reader_nonce": self.p.nonce.hex().upper()},
                       {"camera_body_matched": False},
                       {"first_sha256": None, "second_sha256": None, "host_sha256": None},
                       {"first_sha256": "x" * 64, "second_sha256": "x" * 64, "host_sha256": "x" * 64}):
            with self.assertRaises(ValueError):
                classify(self.p, self.receipt(), self.read() | values)

    def test_invalid_proposal_types_and_identical_images_rejected(self):
        base = dict(nonce=self.p.nonce, mode=1, rows=2, forward_bytes=8192,
                    source_sha256=self.p.source_sha256, target_sha256=self.p.target_sha256)
        for changes in ({"nonce": "a" * 16}, {"mode": True}, {"rows": True},
                        {"forward_bytes": True}, {"source_sha256": None},
                        {"target_sha256": self.p.source_sha256}):
            with self.assertRaises(ValueError):
                Proposal(**(base | changes))

    def test_impossible_positive_native_error_or_io_rejected(self):
        for raw in (self.receipt(phase=90, error=5), self.receipt(io=5)):
            with self.assertRaises(ValueError):
                classify(self.p, raw)

    def test_close_failure_does_not_prove_descriptor_closed(self):
        raw = self.receipt(phase=90, error=-5, io=-5)
        result = classify(self.p, raw, self.read())
        self.assertEqual(result["state"], "NATIVE_CLOSE_FAILED_REQUIRES_MANUAL_REVIEW")
        self.assertFalse(result["native_writer_terminal_proven"])
        self.assertFalse(result["evidence_supports_session_end"])


if __name__ == "__main__":
    unittest.main()
