#!/usr/bin/env python3
"""
Task 1 - Why encryption alone is insufficient (AES-CTR with NO MAC).

Demonstrates two failures of unauthenticated CTR:
  1. Malleability: an on-path relay changes READ -> EXEC without the key.
  2. Replay: the receiver happily processes the same ciphertext twice.

Everything is local and in-process. The "command" is a harmless string; the
receiver only prints what it would do.
"""
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMAND = b'{"action":"READ","path":"notes.txt"}'


# --------------------------------------------------------------------------
# Plain AES-256-CTR helpers (no integrity protection - that is the point)
# --------------------------------------------------------------------------
def ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CTR. Encryption and decryption are the same operation."""
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


# --------------------------------------------------------------------------
# Sender
# --------------------------------------------------------------------------
class Sender:
    def __init__(self, key: bytes):
        self.key = key

    def send(self, plaintext: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(16)  # fresh IV, sent in the clear with the message
        return iv, ctr_crypt(self.key, iv, plaintext)


# --------------------------------------------------------------------------
# Attacker relay: knows NO key. Assumes it knows the command format
# (a known-plaintext assumption: the field layout is fixed and public).
# --------------------------------------------------------------------------
def relay_modify(iv: bytes, ct: bytes, old: bytes, new: bytes, offset: int):
    """Return (iv, modified_ct, delta). Only uses public info: old/new/offset."""
    assert len(old) == len(new), "replacement must be the same length"
    delta = xor_bytes(old, new)  # old XOR new
    forged = bytearray(ct)
    for i, d in enumerate(delta):
        forged[offset + i] ^= d  # flip exactly the bits that differ
    return iv, bytes(forged), delta


# --------------------------------------------------------------------------
# Receiver: decrypts and acts. No MAC, no sequence number, no replay check.
# --------------------------------------------------------------------------
class Receiver:
    def __init__(self, key: bytes):
        self.key = key
        self.processed = 0

    def receive(self, iv: bytes, ct: bytes) -> bytes:
        pt = ctr_crypt(self.key, iv, ct)
        self.processed += 1
        print(f"  [receiver] processed message #{self.processed}: {pt!r}")
        return pt


def banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main() -> None:
    key = os.urandom(32)  # shared AES-256 key; the attacker never sees it
    sender, receiver = Sender(key), Receiver(key)

    # ---------------- Part A: bit-flipping ----------------
    banner("Part A: CTR bit-flip (malleability)")
    iv, ct = sender.send(COMMAND)
    print(f"original plaintext : {COMMAND!r} ({len(COMMAND)} bytes)")
    print(f"IV (public)        : {iv.hex()}")
    print(f"original ciphertext: {ct.hex()}")

    old, new = b"READ", b"EXEC"  # equal length, so nothing shifts
    offset = COMMAND.index(old)
    print(f"\nrelay changes {old!r} -> {new!r} at byte offset {offset} (no key used)")
    iv2, forged_ct, delta = relay_modify(iv, ct, old, new, offset)
    print(f"delta = old XOR new: {delta.hex()}")
    print(f"forged ciphertext  : {forged_ct.hex()}")

    # Show the XOR relation: C XOR C' == P XOR P'
    modified_pt_expected = COMMAND[:offset] + new + COMMAND[offset + len(old):]
    c_xor = xor_bytes(ct, forged_ct)
    p_xor = xor_bytes(COMMAND, modified_pt_expected)
    print("\nXOR relation  C XOR C'  ==  P XOR P'")
    print(f"  C  XOR C' : {c_xor.hex()}")
    print(f"  P  XOR P' : {p_xor.hex()}")
    print(f"  equal?      {c_xor == p_xor}")

    print("\nReceiver gets the forged ciphertext:")
    result = receiver.receive(iv2, forged_ct)
    assert result == modified_pt_expected
    print("  -> accepted with no error: the attacker changed the command.")

    # ---------------- Part B: replay ----------------
    banner("Part B: replay")
    receiver = Receiver(key)  # fresh receiver so the count starts at 0
    iv, ct = sender.send(COMMAND)
    print("Sender sends one legitimate message; attacker records and resends it.")
    receiver.receive(iv, ct)  # legitimate delivery
    receiver.receive(iv, ct)  # replayed, byte-for-byte identical
    print(f"\nmessages processed from ONE send: {receiver.processed}")
    assert receiver.processed == 2
    print("  -> receiver cannot tell a replay from the original.")


if __name__ == "__main__":
    main()
