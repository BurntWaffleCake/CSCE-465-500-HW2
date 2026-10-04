#!/usr/bin/env python3
"""
Task 2 - Authenticated finite-field Diffie-Hellman handshake (in-process).

A simulated gateway (initiator) and node (responder) agree on session keys:

    gateway                                   node
       |---- ClientHello(id, dh_pub, nonce) --->|
       |<--- ServerHello(id, dh_pub, nonce, sig_node) ---|
       |---- Finished(sig_gateway) ------------>|

Both sides build the SAME canonical transcript, sign  role || SHA-256(transcript)
with RSA-PSS, verify the peer's signature, and only then derive keys.

Only maintained library primitives are used (cryptography): RSA-PSS, SHA-256,
HMAC-SHA-256 and finite-field DH. No big-number DH/RSA math is hand-written;
the only integer work is encoding and range comparison.

Transcript field order (length-prefixed, 4-byte big-endian each):
    1 label  2 group id  3 gateway id  4 node id
    5 gateway DH public  6 node DH public  7 gateway nonce  8 node nonce
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
KDF_LABEL = b"CSCE465-KDF-v1"

ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"
GATEWAY_ID = b"gateway.local"
NODE_ID = b"node.local"

DH_BYTES = 384      # byte width of the ffdhe3072 modulus (3072 bits)
NONCE_BYTES = 16
RSA_BITS = 3072
NUM_FIELDS = 8

# The group file lives next to this script (hw2/ffdhe3072.pem).
GROUP_FILE = Path(__file__).resolve().with_name("ffdhe3072.pem")


class HandshakeError(Exception):
    """Any condition under which the handshake must be aborted."""


# --------------------------------------------------------------------------
# Library-backed primitives
# --------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _pss() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )


def sign(key: rsa.RSAPrivateKey, role: bytes, th: bytes) -> bytes:
    """RSA-PSS / SHA-256 signature over  role || TH."""
    return key.sign(role + th, _pss(), hashes.SHA256())


def verify(pub: rsa.RSAPublicKey, signature: bytes, role: bytes, th: bytes) -> None:
    try:
        pub.verify(signature, role + th, _pss(), hashes.SHA256())
    except InvalidSignature:
        raise HandshakeError("invalid RSA-PSS signature") from None


# --------------------------------------------------------------------------
# Canonical transcript: length-prefixed (TLV-style) encoding + strict parser
# --------------------------------------------------------------------------
def encode_transcript(fields: list[bytes]) -> bytes:
    if len(fields) != NUM_FIELDS:
        raise HandshakeError(f"transcript needs {NUM_FIELDS} fields, got {len(fields)}")
    return b"".join(len(f).to_bytes(4, "big") + f for f in fields)


def parse_transcript(data: bytes) -> list[bytes]:
    """Strictly parse and validate a transcript. Raises before anything is hashed."""
    fields: list[bytes] = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise HandshakeError("malformed transcript: truncated length prefix")
        n = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        if n > len(data) - pos:
            raise HandshakeError("malformed transcript: declared length exceeds data")
        fields.append(data[pos:pos + n])
        pos += n
    if len(fields) != NUM_FIELDS:
        raise HandshakeError(f"malformed transcript: {len(fields)} fields, expected {NUM_FIELDS}")

    label, group, gw_id, nd_id, gw_pub, nd_pub, gw_nonce, nd_nonce = fields
    if label != PROTOCOL_LABEL:
        raise HandshakeError("malformed transcript: wrong protocol label")
    if group != GROUP_ID:
        raise HandshakeError("malformed transcript: wrong group identifier")
    if not gw_id or not nd_id:
        raise HandshakeError("malformed transcript: empty identity")
    if len(gw_pub) != DH_BYTES or len(nd_pub) != DH_BYTES:
        raise HandshakeError("malformed transcript: DH public value has wrong length")
    if len(gw_nonce) != NONCE_BYTES or len(nd_nonce) != NONCE_BYTES:
        raise HandshakeError("malformed transcript: nonce has wrong length")
    return fields


def transcript_hash(transcript: bytes) -> bytes:
    """TH = SHA-256(transcript). Validation always happens before hashing."""
    parse_transcript(transcript)
    return sha256(transcript)


# --------------------------------------------------------------------------
# Diffie-Hellman (ffdhe3072) helpers
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Group:
    params: dh.DHParameters
    p: int
    g: int


def load_group(path: Path | str = GROUP_FILE) -> Group:
    """Load the ffdhe3072 parameter file generated in Lab Preparation."""
    try:
        params = serialization.load_pem_parameters(Path(path).read_bytes())
    except (OSError, ValueError) as e:
        raise HandshakeError(f"cannot load group file {path}: {e}") from None
    nums = params.parameter_numbers()
    p, g = nums.p, nums.g
    ones = (1 << 64) - 1
    # Sanity checks only (no DH math): ffdhe primes are 3072 bits, start and
    # end with 64 one-bits, and use generator 2 (RFC 7919).
    if p.bit_length() != 3072 or g != 2 or (p >> (3072 - 64)) != ones or (p & ones) != ones:
        raise HandshakeError("group file is not the standard ffdhe3072 group")
    return Group(params=params, p=p, g=g)


def encode_dh_public(pub: dh.DHPublicKey) -> bytes:
    return pub.public_numbers().y.to_bytes(DH_BYTES, "big")


def decode_dh_public(group: Group, data: bytes) -> dh.DHPublicKey:
    """Validate a peer's DH public value: exact width and 2 <= y <= p-2."""
    if len(data) != DH_BYTES:
        raise HandshakeError("DH public value has wrong length")
    y = int.from_bytes(data, "big")
    if not 2 <= y <= group.p - 2:
        raise HandshakeError("DH public value out of range")
    nums = dh.DHPublicNumbers(y, dh.DHParameterNumbers(group.p, group.g))
    return nums.public_key()


def shared_secret(priv: dh.DHPrivateKey, peer_pub: dh.DHPublicKey) -> bytes:
    """Z as a 384-byte big-endian string, zero-padded on the left."""
    try:
        raw = priv.exchange(peer_pub)
    except ValueError as e:
        raise HandshakeError(f"DH exchange failed: {e}") from None
    return int.from_bytes(raw, "big").to_bytes(DH_BYTES, "big")


# --------------------------------------------------------------------------
# Key derivation (exactly as specified in the assignment)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class SessionKeys:
    role: bytes
    session_id: bytes
    transcript_hash: bytes
    k_g2n_enc: bytes = field(repr=False)
    k_g2n_mac: bytes = field(repr=False)
    k_n2g_enc: bytes = field(repr=False)
    k_n2g_mac: bytes = field(repr=False)

    def send_keys(self) -> tuple[bytes, bytes]:
        """(enc, mac) used by THIS party to protect outgoing records."""
        if self.role == ROLE_GATEWAY:
            return self.k_g2n_enc, self.k_g2n_mac
        return self.k_n2g_enc, self.k_n2g_mac

    def recv_keys(self) -> tuple[bytes, bytes]:
        """(enc, mac) used by THIS party to verify/decrypt incoming records."""
        if self.role == ROLE_GATEWAY:
            return self.k_n2g_enc, self.k_n2g_mac
        return self.k_g2n_enc, self.k_g2n_mac


def derive_session(role: bytes, z: bytes, th: bytes) -> SessionKeys:
    k_master = sha256(KDF_LABEL + z + th)
    return SessionKeys(
        role=role,
        session_id=hmac_sha256(k_master, b"session identifier" + th)[:8],
        transcript_hash=th,
        k_g2n_enc=hmac_sha256(k_master, b"gateway-to-node encryption" + th),
        k_g2n_mac=hmac_sha256(k_master, b"gateway-to-node MAC" + th),
        k_n2g_enc=hmac_sha256(k_master, b"node-to-gateway encryption" + th),
        k_n2g_mac=hmac_sha256(k_master, b"node-to-gateway MAC" + th),
    )


# --------------------------------------------------------------------------
# Handshake messages
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ClientHello:
    identity: bytes
    dh_public: bytes
    nonce: bytes


@dataclass(frozen=True)
class ServerHello:
    identity: bytes
    dh_public: bytes
    nonce: bytes
    signature: bytes


@dataclass(frozen=True)
class Finished:
    signature: bytes


# --------------------------------------------------------------------------
# A handshake endpoint
# --------------------------------------------------------------------------
class Party:
    def __init__(
        self,
        role: bytes,
        identity: bytes,
        signing_key: rsa.RSAPrivateKey,
        peer_identity: bytes,
        peer_public_key: rsa.RSAPublicKey,
        group: Group,
    ):
        if role not in (ROLE_GATEWAY, ROLE_NODE):
            raise ValueError("role must be gateway or node")
        if signing_key.key_size != RSA_BITS:
            raise ValueError(f"signing key must be {RSA_BITS}-bit RSA")
        self.role = role
        self.peer_role = ROLE_NODE if role == ROLE_GATEWAY else ROLE_GATEWAY
        self.identity = identity
        self._signing_key = signing_key
        self.peer_identity = peer_identity
        self._peer_public_key = peer_public_key
        self.group = group

        self._state = "init"
        self._priv: dh.DHPrivateKey | None = None
        self._pub_bytes = b""
        self._nonce = b""
        self._th = b""
        self._pending: SessionKeys | None = None
        self._session: SessionKeys | None = None

    # ---- shared helpers --------------------------------------------------
    def _expect_state(self, state: str) -> None:
        if self._state != state:
            raise HandshakeError(f"unexpected message in state '{self._state}'")

    def _new_ephemeral(self) -> None:
        self._priv = self.group.params.generate_private_key()  # fresh per session
        self._pub_bytes = encode_dh_public(self._priv.public_key())
        self._nonce = os.urandom(NONCE_BYTES)  # fresh 16-byte nonce

    def _check_peer_hello(self, identity: bytes, dh_public: bytes, nonce: bytes):
        if identity != self.peer_identity:
            raise HandshakeError("unexpected peer identity")
        if len(nonce) != NONCE_BYTES:
            raise HandshakeError("peer nonce has wrong length")
        if self._nonce and nonce == self._nonce:
            raise HandshakeError("reflected handshake message (own nonce echoed back)")
        if self._pub_bytes and dh_public == self._pub_bytes:
            raise HandshakeError("reflected handshake message (own DH value echoed back)")
        return decode_dh_public(self.group, dh_public)

    def _transcript(self, gw_id, nd_id, gw_pub, nd_pub, gw_nonce, nd_nonce) -> bytes:
        return encode_transcript(
            [PROTOCOL_LABEL, GROUP_ID, gw_id, nd_id, gw_pub, nd_pub, gw_nonce, nd_nonce]
        )

    @property
    def session(self) -> SessionKeys:
        if self._session is None:
            raise HandshakeError("handshake not complete")
        return self._session

    # ---- gateway (initiator) --------------------------------------------
    def initiate(self) -> ClientHello:
        if self.role != ROLE_GATEWAY:
            raise HandshakeError("only the gateway initiates")
        self._expect_state("init")
        self._new_ephemeral()
        self._state = "sent_client_hello"
        return ClientHello(self.identity, self._pub_bytes, self._nonce)

    def process_server_hello(self, msg: ServerHello) -> Finished:
        if self.role != ROLE_GATEWAY:
            raise HandshakeError("only the gateway processes ServerHello")
        self._expect_state("sent_client_hello")
        peer_pub = self._check_peer_hello(msg.identity, msg.dh_public, msg.nonce)

        transcript = self._transcript(
            self.identity, msg.identity,
            self._pub_bytes, msg.dh_public,
            self._nonce, msg.nonce,
        )
        th = transcript_hash(transcript)
        verify(self._peer_public_key, msg.signature, ROLE_NODE, th)  # entity auth

        z = shared_secret(self._priv, peer_pub)
        self._session = derive_session(self.role, z, th)
        self._state = "done"
        return Finished(sign(self._signing_key, ROLE_GATEWAY, th))

    # ---- node (responder) -----------------------------------------------
    def process_client_hello(self, msg: ClientHello) -> ServerHello:
        if self.role != ROLE_NODE:
            raise HandshakeError("only the node processes ClientHello")
        self._expect_state("init")
        self._new_ephemeral()
        peer_pub = self._check_peer_hello(msg.identity, msg.dh_public, msg.nonce)

        transcript = self._transcript(
            msg.identity, self.identity,
            msg.dh_public, self._pub_bytes,
            msg.nonce, self._nonce,
        )
        self._th = transcript_hash(transcript)
        z = shared_secret(self._priv, peer_pub)
        # Keys are held back until the gateway's signature has been verified.
        self._pending = derive_session(self.role, z, self._th)
        self._state = "sent_server_hello"
        return ServerHello(
            self.identity, self._pub_bytes, self._nonce,
            sign(self._signing_key, ROLE_NODE, self._th),
        )

    def process_finished(self, msg: Finished) -> None:
        if self.role != ROLE_NODE:
            raise HandshakeError("only the node processes Finished")
        self._expect_state("sent_server_hello")
        verify(self._peer_public_key, msg.signature, ROLE_GATEWAY, self._th)
        self._session = self._pending
        self._pending = None
        self._state = "done"


# --------------------------------------------------------------------------
# Convenience helpers for tests and the demo
# --------------------------------------------------------------------------
def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def make_pair(
    group: Group,
    gateway_key: rsa.RSAPrivateKey,
    node_key: rsa.RSAPrivateKey,
) -> tuple[Party, Party]:
    """Build a gateway and node that each pin the other's RSA public key."""
    gateway = Party(ROLE_GATEWAY, GATEWAY_ID, gateway_key, NODE_ID, node_key.public_key(), group)
    node = Party(ROLE_NODE, NODE_ID, node_key, GATEWAY_ID, gateway_key.public_key(), group)
    return gateway, node


def run_handshake(gateway: Party, node: Party) -> tuple[SessionKeys, SessionKeys]:
    hello = gateway.initiate()
    server_hello = node.process_client_hello(hello)
    finished = gateway.process_server_hello(server_hello)
    node.process_finished(finished)
    return gateway.session, node.session


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------
def _expect_failure(label: str, fn) -> None:
    try:
        fn()
    except HandshakeError as e:
        print(f"  [rejected] {label}: {e}")
    else:
        raise AssertionError(f"{label} was NOT rejected")


def main() -> None:
    group = load_group()
    print("loaded ffdhe3072 group (3072-bit p, g = 2)")
    print("generating 3072-bit RSA keys (slow under emulation)...")
    gw_key, nd_key = generate_rsa_key(), generate_rsa_key()

    gateway, node = make_pair(group, gw_key, nd_key)
    gw_s, nd_s = run_handshake(gateway, node)

    print("\nValid handshake")
    print(f"  session_id (gateway): {gw_s.session_id.hex()}")
    print(f"  session_id (node)   : {nd_s.session_id.hex()}")
    print(f"  transcript hashes match: {gw_s.transcript_hash == nd_s.transcript_hash}")
    assert gw_s.session_id == nd_s.session_id
    assert gw_s.send_keys() == nd_s.recv_keys()
    assert gw_s.recv_keys() == nd_s.send_keys()
    four = {gw_s.k_g2n_enc, gw_s.k_g2n_mac, gw_s.k_n2g_enc, gw_s.k_n2g_mac}
    print(f"  four directional keys all distinct: {len(four) == 4}")
    assert len(four) == 4

    print("\nAttacks")
    # 1. Changed nonce in ServerHello -> transcript differs -> signature fails.
    g1, n1 = make_pair(group, gw_key, nd_key)
    sh = n1.process_client_hello(g1.initiate())
    _expect_failure("changed nonce",
                    lambda: g1.process_server_hello(replace(sh, nonce=os.urandom(16))))

    # 2. Wrong peer identity.
    g2, n2 = make_pair(group, gw_key, nd_key)
    sh = n2.process_client_hello(g2.initiate())
    _expect_failure("unexpected identity",
                    lambda: g2.process_server_hello(replace(sh, identity=b"mallory")))

    # 3. Reflected ClientHello sent back to the gateway as a ServerHello.
    g3, _ = make_pair(group, gw_key, nd_key)
    ch = g3.initiate()
    _expect_failure("reflected hello",
                    lambda: g3.process_server_hello(
                        ServerHello(ch.identity, ch.dh_public, ch.nonce, b"\x00" * 384)))

    # 4. Malformed transcript (bad declared length) rejected before hashing.
    bad = (1000).to_bytes(4, "big") + b"short"
    _expect_failure("malformed transcript", lambda: transcript_hash(bad))


if __name__ == "__main__":
    main()
