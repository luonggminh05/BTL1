import pytest

from secure_chat import crypto
from secure_chat.config import GroupConfig, ConfigError


def _is_prime(n, rounds=12):
    import random
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29] + [random.randrange(2, n - 2) for _ in range(rounds)]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def test_dh_prime_is_safe_prime():
    assert crypto.DH_P.bit_length() == 2048
    assert _is_prime(crypto.DH_P) and _is_prime(crypto.DH_Q)
    assert hex(crypto.DH_P).startswith("0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1")


def test_dh_agreement():
    a, b = crypto.DHKeyPair(), crypto.DHKeyPair()
    assert a.exchange(b.public_bytes) == b.exchange(a.public_bytes)


@pytest.mark.parametrize("bad", [0, 1, crypto.DH_P - 1, crypto.DH_P, crypto.DH_P + 5])
def test_dh_rejects_degenerate_public(bad):
    a = crypto.DHKeyPair()
    with pytest.raises(crypto.CryptoError):
        a.exchange(bad.to_bytes(crypto.DH_LEN, "big"))


def test_dh_rejects_non_subgroup_element():
    a = crypto.DHKeyPair()
    # phần tử sinh g' = p-1 có bậc 2; phần tử không thuộc nhóm con bậc q -> bị từ chối
    nonresidue = next(x for x in range(2, 1000) if pow(x, crypto.DH_Q, crypto.DH_P) != 1)
    with pytest.raises(crypto.CryptoError):
        a.exchange(nonresidue.to_bytes(crypto.DH_LEN, "big"))


def test_rsa_sign_verify(idents):
    i = idents["alice"]
    sig = crypto.rsa_sign(i.private_key, b"msg")
    pub = crypto.pub_from_der(i.public_der)
    assert crypto.rsa_verify(pub, sig, b"msg")
    assert not crypto.rsa_verify(pub, sig, b"msG")


def test_k0_and_hello():
    g = GroupConfig(("2411508", "2312075"))
    import hashlib
    assert g.initial_key == hashlib.sha256(b"24115082312075").digest()
    assert g.hello == "Hello, We are 2411508, 2312075"
    with pytest.raises(ConfigError):
        GroupConfig(("abc",))
    with pytest.raises(ConfigError):
        GroupConfig(())
