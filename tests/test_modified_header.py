"""
Test 3 - modified authenticated header fields.

Header layout (15 bytes):
    offset 0      version
    offset 1      direction
    offset 2-9    sequence
    offset 10     message_type
    offset 11-14  ciphertext_length

Which exception fires depends on which check catches the change first:
  * version and direction are checked in the clear, before the MAC, so a
    record that is plainly not for us never reaches MAC verification;
  * a changed length no longer matches the actual record size (structural);
  * sequence and message_type can only be caught by the MAC, which covers the
    whole header, so tampering with them is an AuthenticationFailure.
"""
import pytest

import secure_record as sr

COMMAND = b'{"action":"READ","path":"notes.txt"}'


def flip(data: bytes, index: int, mask: int = 0x01) -> bytes:
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


@pytest.mark.parametrize(
    "offset, mask, expected",
    [
        (0, 0x01, sr.UnsupportedVersion),     # version
        (1, 0x03, sr.WrongDirection),         # direction 1 -> 2 (the other valid value)
        (2, 0x80, sr.AuthenticationFailure),  # sequence, high byte
        (9, 0x01, sr.AuthenticationFailure),  # sequence, low byte (0 -> 1)
        (10, 0x01, sr.AuthenticationFailure), # message_type
        (14, 0x01, sr.MalformedRecord),       # ciphertext_length, low byte
    ],
    ids=["version", "direction", "sequence-high", "sequence-low",
         "message-type", "length"],
)
def test_modified_header_field_is_rejected(channels, offset, mask, expected):
    c = channels
    record = sr.seal(c.g_send, 1, COMMAND)

    with pytest.raises(expected):
        sr.open_record(c.n_recv, flip(record, offset, mask))

    assert c.n_recv.expected_seq == 0                        # state untouched
    assert sr.open_record(c.n_recv, record) == (1, COMMAND)  # original still accepted


def test_attacker_cannot_rewrite_sequence_to_dodge_replay_detection(channels):
    """Replay record 0 with its sequence number bumped to 1 (the next expected)."""
    c = channels
    record0 = sr.seal(c.g_send, 1, b"first")
    sr.open_record(c.n_recv, record0)                # receiver now expects 1

    disguised = flip(record0, 9, 0x01)               # sequence 0 -> 1
    with pytest.raises(sr.AuthenticationFailure):    # not mistaken for a valid next record
        sr.open_record(c.n_recv, disguised)
    assert c.n_recv.expected_seq == 1


def test_header_is_readable_but_authenticated(channels):
    """The header travels in the clear (the receiver needs it first)."""
    record = sr.seal(channels.g_send, 7, COMMAND)
    assert record[0] == sr.VERSION
    assert record[1] == sr.DIR_G2N
    assert record[10] == 7
