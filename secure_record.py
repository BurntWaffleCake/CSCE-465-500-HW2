#!/usr/bin/env python3
"""
Task 3 - Encrypt-then-MAC record layer.

Wire format of one record:

    header (15 bytes) || ciphertext || tag (32 bytes)

    header = version(1) || direction(1) || sequence(8) ||
             message_type(1) || ciphertext_length(4)          (big-endian)
    iv     = session_id(8) || sequence(8)     (derived, NOT sent on the wire)
    ciphertext = AES-256-CTR(K_enc, iv, plaintext)
    tag    = HMAC-SHA-256(K_mac, header || iv || ciphertext)

Receiver check order (nothing is decrypted until the MAC has verified):
    1. structure / declared length   -> MalformedRecord
    2. version                       -> UnsupportedVersion
    3. direction                     -> WrongDirection
    4. HMAC (constant-time, library) -> AuthenticationFailure
    5. exact next sequence number    -> ReplayedRecord / OutOfOrderRecord
    6. decrypt, then advance the expected sequence number

State only advances after a record is fully accepted, and no plaintext is
returned on any error path.

KNOWN LIMITATION (inherent to the specified IV format): the IV is the initial
128-bit counter block, and CTR increments the whole block per 16 bytes. A record
longer than 16 bytes at sequence n therefore consumes counter values that
record n+1 also uses, so keystream blocks overlap between neighbouring records
even though no IV is ever reused. See the security note.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --------------------------------------------------------------------------
# Format constants
# --------------------------------------------------------------------------
VERSION = 1
DIR_G2N = 1  # gateway -> node
DIR_N2G = 2  # node -> gateway

HEADER_FMT = ">BBQBI"  # version, direction, sequence, message_type, ct_length
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 15 bytes
TAG_LEN = 32
KEY_LEN = 32
SESSION_ID_LEN = 8
SEQ_LIMIT = 2**64
MAX_CT_LEN = 2**32 - 1


# --------------------------------------------------------------------------
# Errors (distinct types so tests can assert a specific safe failure)
# --------------------------------------------------------------------------
class RecordError(Exception):
    """Base class: the record was rejected and no plaintext was released."""


class MalformedRecord(RecordError):
    """Too short, or declared ciphertext length does not match the data."""


class UnsupportedVersion(RecordError):
    """Header version is not the one this implementation speaks."""


class WrongDirection(RecordError):
    """Record is for the opposite direction (e.g. a reflected record)."""


class AuthenticationFailure(RecordError):
    """HMAC tag did not verify: header or ciphertext was modified."""


class SequenceError(RecordError):
    """Base class for sequence-number rejections."""


class ReplayedRecord(SequenceError):
    """Authentic record whose sequence number was already consumed."""


class OutOfOrderRecord(SequenceError):
    """Authentic record that skips ahead of the expected sequence number."""


class SequenceExhausted(RecordError):
    """The sender ran out of sequence numbers; a new session is required."""


# --------------------------------------------------------------------------
# Per-direction state
# --------------------------------------------------------------------------
def _check_keys(enc_key: bytes, mac_key: bytes, session_id: bytes, direction: int):
    if len(enc_key) != KEY_LEN or len(mac_key) != KEY_LEN:
        raise ValueError(f"enc and mac keys must be {KEY_LEN} bytes")
    if len(session_id) != SESSION_ID_LEN:
        raise ValueError(f"session_id must be {SESSION_ID_LEN} bytes")
    if direction not in (DIR_G2N, DIR_N2G):
        raise ValueError("direction must be DIR_G2N or DIR_N2G")
    if enc_key == mac_key:
        raise ValueError("encryption and MAC keys must be independent")


@dataclass
class SendState:
    """Outgoing direction. Sequence numbers start at zero."""
    enc_key: bytes
    mac_key: bytes
    session_id: bytes
    direction: int
    next_seq: int = 0

    def __post_init__(self):
        _check_keys(self.enc_key, self.mac_key, self.session_id, self.direction)


@dataclass
class RecvState:
    """Incoming direction. Expects the exact next sequence number."""
    enc_key: bytes
    mac_key: bytes
    session_id: bytes
    direction: int  # the direction of records this side ACCEPTS
    expected_seq: int = 0

    def __post_init__(self):
        _check_keys(self.enc_key, self.mac_key, self.session_id, self.direction)


def channel_from_session(session) -> tuple[SendState, RecvState]:
    """
    Build (send, recv) state from a handshake.SessionKeys object.

    Duck-typed on purpose so this module can be tested with hard-coded keys
    and does not import the handshake.
    """
    if session.role == b"gateway":
        send_dir, recv_dir = DIR_G2N, DIR_N2G
    elif session.role == b"node":
        send_dir, recv_dir = DIR_N2G, DIR_G2N
    else:
        raise ValueError("unknown role")
    s_enc, s_mac = session.send_keys()
    r_enc, r_mac = session.recv_keys()
    return (
        SendState(s_enc, s_mac, session.session_id, send_dir),
        RecvState(r_enc, r_mac, session.session_id, recv_dir),
    )


# --------------------------------------------------------------------------
# Library-backed primitives
# --------------------------------------------------------------------------
def _aes256_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()  # 32-byte key = AES-256
    return c.update(data) + c.finalize()


def _hmac(key: bytes, data: bytes) -> hmac.HMAC:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h


def _iv(session_id: bytes, sequence: int) -> bytes:
    return session_id + sequence.to_bytes(8, "big")


# --------------------------------------------------------------------------
# seal / open_record
# --------------------------------------------------------------------------
def seal(state: SendState, message_type: int, plaintext: bytes) -> bytes:
    """Encrypt-then-MAC one record and advance the send sequence number."""
    if not 0 <= message_type <= 0xFF:
        raise ValueError("message_type must fit in one byte")
    if len(plaintext) > MAX_CT_LEN:
        raise ValueError("plaintext too long for a 4-byte length field")
    if state.next_seq >= SEQ_LIMIT:
        raise SequenceExhausted("sequence numbers exhausted; re-handshake")

    seq = state.next_seq
    state.next_seq += 1  # consume the number first: an IV is never reused

    iv = _iv(state.session_id, seq)
    ciphertext = _aes256_ctr(state.enc_key, iv, plaintext)
    header = struct.pack(
        HEADER_FMT, VERSION, state.direction, seq, message_type, len(ciphertext)
    )
    tag = _hmac(state.mac_key, header + iv + ciphertext).finalize()
    return header + ciphertext + tag


def open_record(state: RecvState, record: bytes) -> tuple[int, bytes]:
    """
    Verify then decrypt one record. Returns (message_type, plaintext).

    On any failure a RecordError is raised, no plaintext is released, and the
    expected sequence number is left unchanged.
    """
    record = bytes(record)
    if len(record) < HEADER_LEN + TAG_LEN:
        raise MalformedRecord("record shorter than header plus tag")

    header = record[:HEADER_LEN]
    version, direction, seq, message_type, ct_len = struct.unpack(HEADER_FMT, header)
    if ct_len != len(record) - HEADER_LEN - TAG_LEN:
        raise MalformedRecord("declared ciphertext length does not match record")
    ciphertext = record[HEADER_LEN:HEADER_LEN + ct_len]
    tag = record[HEADER_LEN + ct_len:]

    if version != VERSION:
        raise UnsupportedVersion(f"unsupported version {version}")
    if direction != state.direction:
        raise WrongDirection("record is for the opposite direction")

    iv = _iv(state.session_id, seq)
    try:
        _hmac(state.mac_key, header + iv + ciphertext).verify(tag)  # constant time
    except InvalidSignature:
        raise AuthenticationFailure("MAC verification failed") from None

    # Only an authentic header reaches this point, so the sequence number can
    # be trusted: stale means replay, ahead means a record was dropped.
    if seq < state.expected_seq:
        raise ReplayedRecord(f"sequence {seq} already consumed")
    if seq > state.expected_seq:
        raise OutOfOrderRecord(f"expected {state.expected_seq}, got {seq}")

    plaintext = _aes256_ctr(state.enc_key, iv, ciphertext)  # decrypt after verify
    state.expected_seq += 1
    return message_type, plaintext


# --------------------------------------------------------------------------
# Demo with throwaway keys (no handshake needed)
# --------------------------------------------------------------------------
def _demo() -> None:
    import os

    sid, k_enc, k_mac = os.urandom(8), os.urandom(32), os.urandom(32)
    sender = SendState(k_enc, k_mac, sid, DIR_G2N)
    receiver = RecvState(k_enc, k_mac, sid, DIR_G2N)

    msg = b'{"action":"READ","path":"notes.txt"}'
    rec = seal(sender, 1, msg)
    print(f"record: {len(rec)} bytes = {HEADER_LEN} header + {len(msg)} ct + {TAG_LEN} tag")
    mtype, pt = open_record(receiver, rec)
    print(f"accepted: type={mtype} plaintext={pt!r}")

    for label, bad in (
        ("replay", rec),
        ("bit-flipped ciphertext", rec[:HEADER_LEN] + bytes([rec[HEADER_LEN] ^ 1]) + rec[HEADER_LEN + 1:]),
    ):
        try:
            open_record(receiver, bad)
        except RecordError as e:
            print(f"rejected {label}: {type(e).__name__}")


if __name__ == "__main__":
    _demo()
