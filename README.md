# CSCE 465/765 Homework 2: Protect Agent Messages with Classic Cryptography

This submission builds a small secure channel from standard library primitives
(AES-CTR, HMAC-SHA-256, finite-field Diffie-Hellman, RSA-PSS, SHA-256).
`report.pdf` is the graded submission; everything else here lets you run and
verify the work the report describes.

## Contents

```
hw2/
  report.pdf            the submission (answers, explanations, evidence)
  README.md             this file
  AI_USAGE.md           AI-use statement
  baseline_ctr.py       Task 1  AES-CTR without a MAC: bit-flip and replay demo
  handshake.py          Task 2  authenticated ffdhe3072 handshake (gateway <-> node)
  secure_record.py      Task 3  encrypt-then-MAC record layer: seal() / open_record()
  ffdhe3072.pem         DH group file generated in Task 0
  tests/                Task 4  automated adversarial tests (pytest)
```

## 1. Environment setup (Task 0, simplified)

Everything runs inside the course Ubuntu 24.04 VM (NAT networking). No network
sockets are used; all parties run in-process.

**Check OpenSSL** (needs 3.0 or newer; Ubuntu 24.04 ships 3.0.13):

```bash
openssl version
```

**Create the Python environment** and install the two pinned packages:

```bash
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

Activate the environment (`source .venv/bin/activate`) in every new shell
before running anything below. The prompt should show `(.venv)`.

**Generate the Diffie-Hellman group file** (once; already included as
`ffdhe3072.pem`):

```bash
cd "$HOME/csce465-agentsec/hw2"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
openssl dhparam -in ffdhe3072.pem -text -noout | head -3
```

The check should print `DH Parameters: (3072 bit)` and `GROUP: ffdhe3072`.

**Record the versions** for the report's Lab Preparation section:

```bash
{
  echo "$ python3 --version";           python3 --version
  echo; echo "$ openssl version";       openssl version
  echo; echo "$ pip show cryptography pytest"; pip show cryptography pytest
} 2>&1 | tee prelab.txt
```

## 2. Running the programs

Run these from `hw2/` with the virtual environment active.

| Task | Command | What you should see |
|---|---|---|
| 1 | `python baseline_ctr.py` | READ changed to EXEC without the key; the XOR relation `C xor C' = P xor P'` printed as equal; one send processed twice |
| 2 | `python handshake.py` | A valid handshake (matching session IDs, four distinct keys) followed by rejected attacks |
| 3 | `python secure_record.py` | A sealed record accepted once, then a replay and a bit-flip both rejected |

`handshake.py` generates two 3072-bit RSA keys when it starts, which can take
several seconds (longer under x86 emulation). It loads `ffdhe3072.pem` from
its own directory.

## 3. Running the tests (Task 4)

```bash
cd "$HOME/csce465-agentsec/hw2"
source .venv/bin/activate
python -m pytest tests/ -v
```

Useful variations:

```bash
python -m pytest tests/test_replay.py -v      # one file
python -m pytest tests/ -k reflect -v         # tests whose name contains "reflect"
python -m pytest tests/ -q                    # compact output
```

Notes:

- Run from `hw2/` (or anywhere): `tests/conftest.py` adds `hw2/` to the import
  path itself, so nothing needs to be installed.
- `ffdhe3072.pem` must be in `hw2/`, next to `handshake.py`.
- The three RSA keys are generated once per test session. Expect a pause at
  the start of a run; the tests themselves are fast.
- Each test performs its own fresh handshake, so tests do not share state.
- The library prints a deprecation notice that finite-field DH may be removed
  in a future release. The tests suppress it; it does not affect results.

### What each test file covers

| Required test | File | Failure asserted |
|---|---|---|
| 1. Valid handshake and bidirectional messages | `test_valid_handshake.py` | Success; both sides agree on session ID and keys; sequence numbers start at 0 |
| 2. Modified ciphertext | `test_modified_ciphertext.py` | `AuthenticationFailure` (truncation: `MalformedRecord`) |
| 3. Modified authenticated header | `test_modified_header.py` | `UnsupportedVersion`, `WrongDirection`, `AuthenticationFailure`, or `MalformedRecord`, depending on the field |
| 4. Replayed record | `test_replay.py` | `ReplayedRecord`; dropped or reordered records give `OutOfOrderRecord` |
| 5. Record reflected into the opposite direction | `test_record_reflection.py` | `WrongDirection`, or `AuthenticationFailure` if the direction byte is rewritten |
| 6. Wrong RSA key, bad signature, or reflected handshake message | `test_handshake_attacks.py` | `HandshakeError` with a specific message |

`tests/conftest.py` holds the shared fixtures (group, RSA keys, fresh channels).
Every test also checks that a rejected input changes no state and releases no
plaintext.

## 4. Design notes

- **Handshake:** the gateway sends a hello; the node replies with its hello and
  an RSA-PSS signature over `role || SHA-256(transcript)`; the gateway
  verifies it and answers with its own signature. Keys are derived from the
  DH secret Z and the transcript hash using the KDF specified in the
  assignment. The transcript is eight length-prefixed fields in a fixed order
  (label, group id, gateway id, node id, gateway DH value, node DH value,
  gateway nonce, node nonce).
- **Record layer:** `header (15 bytes) || ciphertext || tag (32 bytes)`, with
  `iv = session_id || sequence` (derived, not sent). The receiver checks
  structure, version and direction, verifies the HMAC, checks the exact next
  sequence number, and only then decrypts.
- **Known limitation:** because the specified IV is also the starting CTR
  counter block, records longer than 16 bytes share keystream blocks with the
  next record, even though no IV repeats. This is discussed in the security
  note in the report.

## 5. Rules followed

All work was done inside the course VM on a NAT network, using only fake
secrets, local in-process parties, and harmless test data. No external hosts
were contacted.
