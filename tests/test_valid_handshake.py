"""Test 1 - a valid handshake followed by bidirectional protected messages."""
import struct

import secure_record as sr

COMMAND = b'{"action":"READ","path":"notes.txt"}'


def _sequence_of(record: bytes) -> int:
    return struct.unpack(sr.HEADER_FMT, record[:sr.HEADER_LEN])[2]


def test_both_sides_derive_identical_session(channels):
    gs, ns = channels.gateway_session, channels.node_session
    assert gs.session_id == ns.session_id
    assert gs.transcript_hash == ns.transcript_hash
    # What one side sends with, the other receives with.
    assert gs.send_keys() == ns.recv_keys()
    assert gs.recv_keys() == ns.send_keys()


def test_all_four_directional_keys_are_distinct(channels):
    gs = channels.gateway_session
    keys = [gs.k_g2n_enc, gs.k_g2n_mac, gs.k_n2g_enc, gs.k_n2g_mac]
    assert all(len(k) == 32 for k in keys)
    assert len(set(keys)) == 4  # key separation: no key serves two purposes
    assert len(gs.session_id) == 8


def test_messages_flow_in_both_directions(channels):
    c = channels
    for i in range(5):
        command = COMMAND + b" #%d" % i
        reply = b"reply to command %d" % i
        assert sr.open_record(c.n_recv, sr.seal(c.g_send, 1, command)) == (1, command)
        assert sr.open_record(c.g_recv, sr.seal(c.n_send, 2, reply)) == (2, reply)
    assert c.g_send.next_seq == c.n_recv.expected_seq == 5
    assert c.n_send.next_seq == c.g_recv.expected_seq == 5


def test_sequence_numbers_start_at_zero_in_each_direction(channels):
    c = channels
    assert _sequence_of(sr.seal(c.g_send, 1, b"first from gateway")) == 0
    assert _sequence_of(sr.seal(c.n_send, 1, b"first from node")) == 0


def test_directions_keep_independent_counters(channels):
    c = channels
    for _ in range(3):
        sr.seal(c.g_send, 1, b"gateway traffic")
    # Gateway sending three records must not advance the node's counter.
    assert _sequence_of(sr.seal(c.n_send, 1, b"node traffic")) == 0


def test_record_size_is_header_plus_ciphertext_plus_tag(channels):
    record = sr.seal(channels.g_send, 1, COMMAND)
    assert len(record) == sr.HEADER_LEN + len(COMMAND) + sr.TAG_LEN
    assert sr.HEADER_LEN == 15 and sr.TAG_LEN == 32


def test_ciphertext_does_not_contain_the_plaintext(channels):
    record = sr.seal(channels.g_send, 1, COMMAND)
    assert b"READ" not in record and b"notes.txt" not in record


def test_empty_and_large_payloads_round_trip(channels):
    c = channels
    for payload in (b"", b"x" * 5000):
        assert sr.open_record(c.n_recv, sr.seal(c.g_send, 3, payload)) == (3, payload)


def test_each_handshake_produces_a_new_session(channel_factory):
    a, b = channel_factory(), channel_factory()
    assert a.gateway_session.session_id != b.gateway_session.session_id
    assert a.gateway_session.k_g2n_enc != b.gateway_session.k_g2n_enc
    assert a.gateway_session.transcript_hash != b.gateway_session.transcript_hash
