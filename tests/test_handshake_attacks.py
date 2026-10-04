"""
Test 6 - attacks on the handshake: wrong RSA public key, invalid RSA-PSS
transcript signatures, reflected handshake messages, tampering, malformed
transcripts and bad DH values. Every test asserts a specific HandshakeError
and that no session was established.
"""
import os
from dataclasses import replace

import pytest

import handshake as hs
from handshake import HandshakeError


def flip(data: bytes, index: int = 0, mask: int = 0x01) -> bytes:
    out = bytearray(data)
    out[index] ^= mask
    return bytes(out)


def hellos(gateway, node):
    """Run the first two flights; return (ClientHello, ServerHello)."""
    client_hello = gateway.initiate()
    server_hello = node.process_client_hello(client_hello)
    return client_hello, server_hello


def transcript_hash_for(client_hello, server_hello) -> bytes:
    return hs.transcript_hash(hs.encode_transcript([
        hs.PROTOCOL_LABEL, hs.GROUP_ID, hs.GATEWAY_ID, hs.NODE_ID,
        client_hello.dh_public, server_hello.dh_public,
        client_hello.nonce, server_hello.nonce,
    ]))


def assert_no_session(*parties):
    for p in parties:
        with pytest.raises(HandshakeError, match="not complete"):
            _ = p.session


# --------------------------------------------------------------------------
# Wrong RSA key / invalid RSA-PSS signatures
# --------------------------------------------------------------------------
def test_incorrect_rsa_public_key_is_rejected(group, gateway_key, node_key, attacker_key):
    """The gateway has pinned the WRONG public key for the node."""
    gateway = hs.Party(hs.ROLE_GATEWAY, hs.GATEWAY_ID, gateway_key,
                       hs.NODE_ID, attacker_key.public_key(), group)
    node = hs.Party(hs.ROLE_NODE, hs.NODE_ID, node_key,
                    hs.GATEWAY_ID, gateway_key.public_key(), group)
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        hs.run_handshake(gateway, node)
    assert_no_session(gateway)


def test_corrupted_node_signature_is_rejected(parties):
    gateway, node = parties
    _, server_hello = hellos(gateway, node)
    forged = replace(server_hello, signature=flip(server_hello.signature))
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(forged)
    assert_no_session(gateway)


def test_corrupted_gateway_signature_is_rejected(parties):
    gateway, node = parties
    _, server_hello = hellos(gateway, node)
    finished = gateway.process_server_hello(server_hello)
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        node.process_finished(replace(finished, signature=flip(finished.signature)))
    assert_no_session(node)


def test_well_formed_signature_from_an_impostor_key_is_rejected(parties, attacker_key):
    """Attacker signs the correct transcript hash, but with its own key."""
    gateway, node = parties
    client_hello, server_hello = hellos(gateway, node)
    th = transcript_hash_for(client_hello, server_hello)
    forged = replace(server_hello, signature=hs.sign(attacker_key, hs.ROLE_NODE, th))
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(forged)
    assert_no_session(gateway)


def test_signature_over_the_wrong_role_is_rejected(parties, node_key):
    """Right key, right transcript, but signed with the other side's role label."""
    gateway, node = parties
    client_hello, server_hello = hellos(gateway, node)
    th = transcript_hash_for(client_hello, server_hello)
    forged = replace(server_hello, signature=hs.sign(node_key, hs.ROLE_GATEWAY, th))
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(forged)


# --------------------------------------------------------------------------
# Reflected handshake messages
# --------------------------------------------------------------------------
def test_client_hello_reflected_back_to_gateway(parties):
    gateway, _ = parties
    client_hello = gateway.initiate()
    reflected = hs.ServerHello(client_hello.identity, client_hello.dh_public,
                               client_hello.nonce, os.urandom(384))
    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        gateway.process_server_hello(reflected)
    assert_no_session(gateway)


def test_server_hello_reflected_back_to_node(parties, group, gateway_key, node_key):
    _, node = parties
    other_gateway, other_node = hs.make_pair(group, gateway_key, node_key)
    _, server_hello = hellos(other_gateway, other_node)  # a ServerHello to echo
    reflected = hs.ClientHello(server_hello.identity, server_hello.dh_public,
                               server_hello.nonce)
    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        node.process_client_hello(reflected)
    assert_no_session(node)


def test_peer_echoing_our_nonce_is_rejected(parties):
    gateway, _ = parties
    client_hello = gateway.initiate()
    echo = hs.ServerHello(hs.NODE_ID, os.urandom(384), client_hello.nonce, os.urandom(384))
    with pytest.raises(HandshakeError, match="reflected"):
        gateway.process_server_hello(echo)


def test_peer_echoing_our_dh_value_is_rejected(parties):
    gateway, _ = parties
    client_hello = gateway.initiate()
    echo = hs.ServerHello(hs.NODE_ID, client_hello.dh_public, os.urandom(16), os.urandom(384))
    with pytest.raises(HandshakeError, match="reflected"):
        gateway.process_server_hello(echo)


def test_node_signature_reflected_as_gateway_finished(parties):
    gateway, node = parties
    _, server_hello = hellos(gateway, node)
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        node.process_finished(hs.Finished(server_hello.signature))
    assert_no_session(node)


def test_replayed_client_hello_is_out_of_state(parties):
    gateway, node = parties
    client_hello, _ = hellos(gateway, node)
    with pytest.raises(HandshakeError, match="unexpected message"):
        node.process_client_hello(client_hello)


def test_server_hello_before_client_hello_is_out_of_state(parties, group, gateway_key, node_key):
    gateway, _ = parties
    other_gateway, other_node = hs.make_pair(group, gateway_key, node_key)
    _, server_hello = hellos(other_gateway, other_node)
    with pytest.raises(HandshakeError, match="unexpected message"):
        gateway.process_server_hello(server_hello)


# --------------------------------------------------------------------------
# Tampering with transcript fields in transit
# --------------------------------------------------------------------------
def test_changed_node_nonce_is_rejected(parties):
    gateway, node = parties
    _, server_hello = hellos(gateway, node)
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(replace(server_hello, nonce=os.urandom(16)))


def test_changed_client_nonce_breaks_the_signature(parties):
    gateway, node = parties
    client_hello = gateway.initiate()
    server_hello = node.process_client_hello(replace(client_hello, nonce=os.urandom(16)))
    # The node signed a transcript with the altered nonce; the gateway's differs.
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(server_hello)


def test_changed_dh_public_value_is_rejected(parties):
    gateway, node = parties
    _, server_hello = hellos(gateway, node)
    forged = replace(server_hello, dh_public=flip(server_hello.dh_public, -1))
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(forged)


def test_man_in_the_middle_dh_substitution_is_rejected(parties, group):
    """Attacker swaps in its own DH value; it cannot also fix the signature."""
    gateway, node = parties
    _, server_hello = hellos(gateway, node)
    mallory_pub = hs.encode_dh_public(group.params.generate_private_key().public_key())
    with pytest.raises(HandshakeError, match="invalid RSA-PSS signature"):
        gateway.process_server_hello(replace(server_hello, dh_public=mallory_pub))
    assert_no_session(gateway)


def test_unexpected_identity_is_rejected_by_both_sides(parties, group, gateway_key, node_key):
    gateway, node = parties
    client_hello = gateway.initiate()
    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        node.process_client_hello(replace(client_hello, identity=b"mallory"))
    gateway2, node2 = hs.make_pair(group, gateway_key, node_key)
    _, server_hello = hellos(gateway2, node2)
    with pytest.raises(HandshakeError, match="unexpected peer identity"):
        gateway2.process_server_hello(replace(server_hello, identity=b"mallory"))


# --------------------------------------------------------------------------
# DH public value validation
# --------------------------------------------------------------------------
@pytest.mark.parametrize("label, value", [("zero", 0), ("one", 1), ("p-1", None)])
def test_degenerate_dh_public_values_are_rejected(parties, group, label, value):
    _, node = parties
    y = group.p - 1 if value is None else value
    bad = hs.ClientHello(hs.GATEWAY_ID, y.to_bytes(hs.DH_BYTES, "big"), os.urandom(16))
    with pytest.raises(HandshakeError, match="out of range"):
        node.process_client_hello(bad)


def test_dh_public_value_of_wrong_length_is_rejected(parties):
    _, node = parties
    bad = hs.ClientHello(hs.GATEWAY_ID, os.urandom(383), os.urandom(16))
    with pytest.raises(HandshakeError, match="wrong length"):
        node.process_client_hello(bad)


def test_nonce_of_wrong_length_is_rejected(parties, group):
    _, node = parties
    good_pub = hs.encode_dh_public(group.params.generate_private_key().public_key())
    with pytest.raises(HandshakeError, match="nonce has wrong length"):
        node.process_client_hello(hs.ClientHello(hs.GATEWAY_ID, good_pub, os.urandom(8)))


# --------------------------------------------------------------------------
# Malformed transcripts: rejected before anything is hashed
# --------------------------------------------------------------------------
def valid_fields():
    return [hs.PROTOCOL_LABEL, hs.GROUP_ID, hs.GATEWAY_ID, hs.NODE_ID,
            os.urandom(384), os.urandom(384), os.urandom(16), os.urandom(16)]


def test_a_valid_transcript_parses():
    fields = valid_fields()
    assert hs.parse_transcript(hs.encode_transcript(fields)) == fields


def _declared_length_too_large():
    return b"\xff\xff\xff\xff" + hs.encode_transcript(valid_fields())[4:]


def _truncated_length_prefix():
    # A complete transcript followed by a 2-byte stub where a 4-byte prefix should be.
    return hs.encode_transcript(valid_fields()) + b"\x00\x00"


def _truncated_last_field():
    return hs.encode_transcript(valid_fields())[:-3]


def _trailing_extra_field():
    return hs.encode_transcript(valid_fields()) + (1).to_bytes(4, "big") + b"x"


def _missing_field():
    return b"".join(len(f).to_bytes(4, "big") + f for f in valid_fields()[:-1])


def _wrong_label():
    f = valid_fields()
    f[0] = b"CSCE465-HS-v1"
    return hs.encode_transcript(f)


def _wrong_group():
    f = valid_fields()
    f[1] = b"ffdhe2048"
    return hs.encode_transcript(f)


def _short_dh_value():
    f = valid_fields()
    f[4] = os.urandom(383)
    return hs.encode_transcript(f)


def _short_nonce():
    f = valid_fields()
    f[7] = os.urandom(15)
    return hs.encode_transcript(f)


@pytest.mark.parametrize("build", [
    _declared_length_too_large, _truncated_length_prefix, _truncated_last_field,
    _trailing_extra_field, _missing_field, _wrong_label, _wrong_group,
    _short_dh_value, _short_nonce,
], ids=lambda f: f.__name__.strip("_"))
def test_malformed_transcript_is_rejected_before_hashing(build, monkeypatch):
    def hashing_must_not_happen(_data):
        raise AssertionError("transcript was hashed before validation")

    monkeypatch.setattr(hs, "sha256", hashing_must_not_happen)
    with pytest.raises(HandshakeError, match="malformed transcript"):
        hs.transcript_hash(build())


def test_length_prefixes_make_the_encoding_unambiguous():
    """('ab','c') and ('a','bc') concatenate identically, but not when length-prefixed."""
    assert b"ab" + b"c" == b"a" + b"bc"
    f1, f2 = valid_fields(), valid_fields()
    f1[2], f1[3] = b"ab", b"c"
    f2[2], f2[3] = b"a", b"bc"
    f2[4:] = f1[4:]
    assert hs.encode_transcript(f1) != hs.encode_transcript(f2)
