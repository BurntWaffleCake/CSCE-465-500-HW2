"""Test 5 - a record reflected into the opposite direction."""
import pytest

import secure_record as sr


def flip(data: bytes, index: int, mask: int = 0x01) -> bytes:
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


def test_gateway_record_reflected_back_to_gateway(channels):
    c = channels
    record = sr.seal(c.g_send, 1, b"gateway says hello")
    with pytest.raises(sr.WrongDirection):
        sr.open_record(c.g_recv, record)        # attacker echoes it to its sender
    assert c.g_recv.expected_seq == 0
    assert sr.open_record(c.n_recv, record) == (1, b"gateway says hello")  # real delivery fine


def test_node_record_reflected_back_to_node(channels):
    c = channels
    record = sr.seal(c.n_send, 2, b"node says hello")
    with pytest.raises(sr.WrongDirection):
        sr.open_record(c.n_recv, record)
    assert c.n_recv.expected_seq == 0
    assert sr.open_record(c.g_recv, record) == (2, b"node says hello")


def test_rewriting_the_direction_byte_does_not_help(channels):
    """Attacker relabels a gateway record as node-to-gateway before reflecting it."""
    c = channels
    record = sr.seal(c.g_send, 1, b"gateway says hello")
    relabelled = flip(record, 1, 0x03)          # direction 1 -> 2
    assert relabelled[1] == sr.DIR_N2G
    with pytest.raises(sr.AuthenticationFailure):  # wrong key AND the header is MAC'd
        sr.open_record(c.g_recv, relabelled)
    assert c.g_recv.expected_seq == 0


def test_directions_use_different_keys(channels):
    g = channels.gateway_session
    assert g.k_g2n_enc != g.k_n2g_enc
    assert g.k_g2n_mac != g.k_n2g_mac
    # A state built with the wrong direction's keys cannot read the record.
    record = sr.seal(channels.g_send, 1, b"secret")
    wrong = sr.RecvState(g.k_n2g_enc, g.k_n2g_mac, g.session_id, sr.DIR_G2N)
    with pytest.raises(sr.AuthenticationFailure):
        sr.open_record(wrong, record)


def test_reflection_does_not_release_plaintext(channels):
    c = channels
    record = sr.seal(c.g_send, 1, b"must not leak")
    result = None
    with pytest.raises(sr.RecordError):
        result = sr.open_record(c.g_recv, record)
    assert result is None
