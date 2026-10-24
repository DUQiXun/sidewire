#!/usr/bin/env python3
"""Unit tests for the wire format, plus a compatibility check against the
standalone agent daemon (which carries its own copy of the protocol code).

    python tests/test_protocol.py
"""

import importlib.util
import os
import sys
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from crosswire import protocol as P  # noqa: E402


def load_agentd():
    path = os.path.join(ROOT, "agent", "crosswire_agentd.py")
    spec = importlib.util.spec_from_file_location("crosswire_agentd_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AGENT = load_agentd()


class TestFraming(unittest.TestCase):
    def test_header_is_16_bytes(self):
        self.assertEqual(P.HEADER_SIZE, 16)
        self.assertEqual(len(P.encode_frame(P.T_PING)), 16)

    def test_roundtrip(self):
        payload = b'{"hello":"world"}'
        raw = P.encode_frame(P.T_REQ, 7, payload, P.F_SEALED)
        ftype, flags, stream, length, crc = P.decode_header(raw[:16])
        self.assertEqual(ftype, P.T_REQ)
        self.assertEqual(flags, P.F_SEALED)
        self.assertEqual(stream, 7)
        self.assertEqual(length, len(payload))
        body = raw[16:]
        P.verify_payload(body, crc)
        self.assertEqual(body, payload)

    def test_crc_catches_corruption(self):
        raw = bytearray(P.encode_frame(P.T_RES, 1, b"abcdef"))
        raw[-1] ^= 0xFF
        ftype, flags, stream, length, crc = P.decode_header(bytes(raw[:16]))
        with self.assertRaises(P.ProtocolError):
            P.verify_payload(bytes(raw[16:]), crc)

    def test_bad_magic_rejected(self):
        with self.assertRaises(P.ProtocolError):
            P.decode_header(b"XXXX" + b"\x00" * 12)

    def test_oversize_payload_rejected(self):
        with self.assertRaises(P.ProtocolError):
            P.encode_frame(P.T_REQ, 0, b"x" * (P.MAX_PAYLOAD + 1))

    def test_stream_id_range(self):
        with self.assertRaises(P.ProtocolError):
            P.encode_frame(P.T_REQ, 70000, b"")

    def test_agent_and_client_frames_are_identical(self):
        for ftype, stream, payload, flags in [
            (P.T_REQ, 0, b"", 0),
            (P.T_BLOB, 101, b"\x00\x01\x02binary\xff", P.F_FIN),
            (P.T_EVT, 3, '{"k":"blob_done"}'.encode(), 0),
        ]:
            self.assertEqual(P.encode_frame(ftype, stream, payload, flags),
                             AGENT.encode_frame(ftype, stream, payload, flags),
                             "frame mismatch for type 0x%02x" % ftype)


class TestCrypto(unittest.TestCase):
    def test_seal_open_roundtrip(self):
        key = os.urandom(32)
        a, b = P.Sealer(key), P.Sealer(key)
        for i in range(5):
            msg = ("message-%d" % i).encode() * (i + 1)
            self.assertEqual(b.open(a.seal(msg)), msg)

    def test_ciphertext_differs_from_plaintext(self):
        key = os.urandom(32)
        s = P.Sealer(key)
        ct = s.seal(b"the quick brown fox jumps over the lazy dog")
        self.assertNotIn(b"quick brown", ct)

    def test_tag_detects_tampering(self):
        key = os.urandom(32)
        a, b = P.Sealer(key), P.Sealer(key)
        ct = bytearray(a.seal(b"payload"))
        ct[0] ^= 0x01
        with self.assertRaises(P.ProtocolError):
            b.open(bytes(ct))

    def test_out_of_order_is_detected(self):
        key = os.urandom(32)
        a = P.Sealer(key)
        first = a.seal(b"one")
        second = a.seal(b"two")
        # a receiver that missed frame #1 must not silently accept frame #2,
        # and after that desync it stays broken — which is the point.
        b = P.Sealer(key)
        with self.assertRaises(P.ProtocolError):
            b.open(second)
        with self.assertRaises(P.ProtocolError):
            b.open(first)
        # a receiver that sees them in order is fine
        c = P.Sealer(key)
        self.assertEqual(c.open(first), b"one")
        self.assertEqual(c.open(second), b"two")

    def test_agent_sealer_interops(self):
        key = os.urandom(32)
        client, server = P.Sealer(key), AGENT.Sealer(key)
        msg = b"cross implementation payload" * 10
        self.assertEqual(server.open(client.seal(msg)), msg)
        self.assertEqual(client.open(server.seal(msg)), msg)

    def test_handshake_proofs_match(self):
        key = os.urandom(32)
        nc, ns = os.urandom(16), os.urandom(16)
        self.assertEqual(P.client_proof(key, nc, ns), AGENT.client_proof(key, nc, ns))
        self.assertEqual(P.server_proof(key, nc, ns), AGENT.server_proof(key, nc, ns))
        self.assertNotEqual(P.client_proof(key, nc, ns), P.server_proof(key, nc, ns))
        self.assertEqual(P.session_key(key, nc, ns), AGENT.session_key(key, nc, ns))

    def test_wrong_key_cannot_open(self):
        a = P.Sealer(os.urandom(32))
        b = P.Sealer(os.urandom(32))
        with self.assertRaises(P.ProtocolError):
            b.open(a.seal(b"secret"))


class TestKeys(unittest.TestCase):
    def test_parse_and_format(self):
        raw = os.urandom(32)
        text = P.format_key(raw)
        self.assertTrue(text.startswith("cw1_"))
        self.assertEqual(P.parse_key(text), raw)
        self.assertEqual(P.parse_key(text[4:]), raw)

    def test_short_key_rejected(self):
        with self.assertRaises(P.AuthError):
            P.parse_key("abcd")

    def test_non_hex_rejected(self):
        with self.assertRaises(P.AuthError):
            P.parse_key("zzzz" * 8)

    def test_agent_parses_the_same_key(self):
        text = P.format_key(os.urandom(32))
        self.assertEqual(AGENT.parse_key(text), P.parse_key(text))


if __name__ == "__main__":
    unittest.main(verbosity=2)
