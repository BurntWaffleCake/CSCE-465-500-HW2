"""Test 4 - replayed (and dropped / reordered) records."""
import struct

import pytest

import secure_record as sr


def test_immediate_replay_is_rejected(channels):
    c = channels
    record = sr.seal(c.g_send, 1, b"transfer once")
    assert sr.open_record(c.n_recv, record) == (1, b"transfer once")

    with pytest.raises(sr.ReplayedRecord):
        sr.open_record(c.n_recv, record)       # byte-for-byte copy
    assert c.n_recv.expected_seq == 1          # the replay did not advance state


def test_replay_of_an_old_record_after_later_traffic(channels):
    c = channels
    old = sr.seal(c.g_send, 1, b"old")
    sr.open_record(c.n_recv, old)
    for i in range(3):
        sr.open_record(c.n_recv, sr.seal(c.g_send, 1, b"newer %d" % i))

    with pytest.raises(sr.ReplayedRecord):
        sr.open_record(c.n_recv, old)
    assert c.n_recv.expected_seq == 4


def test_dropped_record_is_detected_and_state_survives(channels):
    c = channels
    first = sr.seal(c.g_send, 1, b"one")
    second = sr.seal(c.g_send, 1, b"two")

    with pytest.raises(sr.OutOfOrderRecord):   # attacker dropped `first`
        sr.open_record(c.n_recv, second)
    assert c.n_recv.expected_seq == 0

    assert sr.open_record(c.n_recv, first) == (1, b"one")   # delivery in order still works
    assert sr.open_record(c.n_recv, second) == (1, b"two")


def test_reordered_delivery_is_rejected(channels):
    c = channels
    records = [sr.seal(c.g_send, 1, b"msg %d" % i) for i in range(3)]
    with pytest.raises(sr.OutOfOrderRecord):
        sr.open_record(c.n_recv, records[2])
    with pytest.raises(sr.OutOfOrderRecord):
        sr.open_record(c.n_recv, records[1])
    for i, record in enumerate(records):       # correct order is accepted
        assert sr.open_record(c.n_recv, record) == (1, b"msg %d" % i)


def test_record_from_another_session_is_rejected(channel_factory):
    """Replaying a record captured in a previous session."""
    old_session, new_session = channel_factory(), channel_factory()
    captured = sr.seal(old_session.g_send, 1, b"from the old session")
    with pytest.raises(sr.AuthenticationFailure):   # different session keys
        sr.open_record(new_session.n_recv, captured)
    assert new_session.n_recv.expected_seq == 0


def test_sender_never_reuses_a_sequence_number_or_iv(channels):
    c = channels
    records = [sr.seal(c.g_send, 1, b"identical plaintext") for _ in range(50)]
    sequences = [struct.unpack(sr.HEADER_FMT, r[:sr.HEADER_LEN])[2] for r in records]
    assert sequences == list(range(50))                       # 0, 1, 2, ... no gaps or repeats
    ciphertexts = {r[sr.HEADER_LEN:-sr.TAG_LEN] for r in records}
    assert len(ciphertexts) == 50                             # same plaintext, 50 different ciphertexts


def test_sender_refuses_to_wrap_the_sequence_number(channels):
    c = channels
    c.g_send.next_seq = sr.SEQ_LIMIT          # 2**64: every number has been used
    with pytest.raises(sr.SequenceExhausted):
        sr.seal(c.g_send, 1, b"too late")
