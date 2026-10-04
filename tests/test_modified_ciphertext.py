"""Test 2 - modified ciphertext must be rejected with AuthenticationFailure."""
import struct

import pytest

import secure_record as sr

COMMAND = b'{"action":"READ","path":"notes.txt"}'  # 36 bytes


def flip(data: bytes, index: int, mask: int = 0x01) -> bytes:
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_flipped_ciphertext_bit_is_rejected(channels, where):
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)
    start, end = sr.HEADER_LEN, len(record) - sr.TAG_LEN
    index = {"first": start, "middle": (start + end) // 2, "last": end - 1}[where]

    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(c.n_recv, flip(record, index))

    assert c.n_recv.expected_seq == 0           # a rejected record changes no state
    assert sr.open_record(c.n_recv, record) == (1, COMMAND)  # genuine one still works


def test_task1_bitflip_attack_is_now_detected(channels):
    """The exact Task 1 attack: XOR READ^EXEC into the ciphertext."""
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)
    offset = sr.HEADER_LEN + COMMAND.index(b"READ")
    delta = bytes(a ^ b for a, b in zip(b"READ", b"EXEC"))

    forged = bytearray(record)
    for i, d in enumerate(delta):
        forged[offset + i] ^= d

    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(c.n_recv, bytes(forged))
    assert c.n_recv.expected_seq == 0


def test_modified_tag_is_rejected(channels):
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)
    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(c.n_recv, flip(record, len(record) - 1))
    assert c.n_recv.expected_seq == 0


def test_truncated_ciphertext_is_malformed(channels):
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)
    truncated = record[:sr.HEADER_LEN + 10] + record[-sr.TAG_LEN:]  # drop ciphertext bytes
    with pytest.raises(sr.MalformedRecord):
        sr.open_record(c.n_recv, truncated)
    assert c.n_recv.expected_seq == 0


def test_extended_ciphertext_is_malformed(channels):
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)
    extended = record[:-sr.TAG_LEN] + b"\x00extra" + record[-sr.TAG_LEN:]
    with pytest.raises(sr.MalformedRecord):
        sr.open_record(c.n_recv, extended)


def test_truncating_and_fixing_the_length_field_still_fails_the_mac(channels):
    """Attacker shortens the ciphertext AND rewrites the length to match."""
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)
    new_len = 10
    header = bytearray(record[:sr.HEADER_LEN])
    header[11:15] = struct.pack(">I", new_len)
    forged = (bytes(header)
              + record[sr.HEADER_LEN:sr.HEADER_LEN + new_len]
              + record[-sr.TAG_LEN:])
    with pytest.raises(sr.AuthenticationFailure):  # length is covered by the MAC
        sr.open_record(c.n_recv, forged)


def test_record_shorter_than_header_plus_tag_is_malformed(channels):
    with pytest.raises(sr.MalformedRecord):
        sr.open_record(channels.n_recv, b"\x01\x01short")
