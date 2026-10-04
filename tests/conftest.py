"""
Shared fixtures for the Task 4 adversarial tests.

Run from the hw2/ directory:

    python -m pytest tests/ -v

RSA-3072 key generation is slow (especially under emulation), so the keys are
generated once per test session. Everything else is rebuilt per test so that
no test can leak sequence-number state into another.
"""
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path

import pytest

HW2_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HW2_DIR))

import handshake as hs  # noqa: E402
import secure_record as sr  # noqa: E402

FFDH_WARNING = "Diffie-Hellman over finite fields"  # library deprecation notice


@dataclass
class Channels:
    """Both endpoints of one completed handshake, with record-layer state."""
    gateway_session: hs.SessionKeys
    node_session: hs.SessionKeys
    g_send: sr.SendState   # gateway -> node
    g_recv: sr.RecvState   # accepts node -> gateway
    n_send: sr.SendState   # node -> gateway
    n_recv: sr.RecvState   # accepts gateway -> node


@pytest.fixture(autouse=True)
def _quiet_ffdh_deprecation():
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=FFDH_WARNING)
        yield


@pytest.fixture(scope="session")
def group():
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=FFDH_WARNING)
        return hs.load_group()  # reads hw2/ffdhe3072.pem


@pytest.fixture(scope="session")
def gateway_key():
    return hs.generate_rsa_key()


@pytest.fixture(scope="session")
def node_key():
    return hs.generate_rsa_key()


@pytest.fixture(scope="session")
def attacker_key():
    """An RSA key that neither honest party has pinned."""
    return hs.generate_rsa_key()


@pytest.fixture
def parties(group, gateway_key, node_key):
    """A fresh (gateway, node) pair that has not started a handshake."""
    return hs.make_pair(group, gateway_key, node_key)


@pytest.fixture
def channel_factory(group, gateway_key, node_key):
    """Call to run a brand-new handshake and get fresh record-layer state."""
    def make() -> Channels:
        gateway, node = hs.make_pair(group, gateway_key, node_key)
        g_sess, n_sess = hs.run_handshake(gateway, node)
        g_send, g_recv = sr.channel_from_session(g_sess)
        n_send, n_recv = sr.channel_from_session(n_sess)
        return Channels(g_sess, n_sess, g_send, g_recv, n_send, n_recv)
    return make


@pytest.fixture
def channels(channel_factory):
    return channel_factory()
