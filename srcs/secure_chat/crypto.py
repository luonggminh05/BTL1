"""Các nguyên thủy mật mã dùng trong giao thức (bọc thư viện 'cryptography').

Ánh xạ với nội dung môn học:
  * Diffie-Hellman trên trường hữu hạn GF(p)  (Chương IV)  - nhóm MODP 2048-bit RFC 3526 #14
  * RSA-PSS 3072-bit  (Chương IV)             - chữ ký số xác thực danh tính
  * Lũy thừa modulo nhanh (Square & Multiply) - do OpenSSL thực hiện (Chương II)
  * AES-256-GCM  (mã hóa đối xứng + xác thực)
  * HMAC-SHA256  (xác nhận khóa - key confirmation)
  * HKDF-SHA256  (dẫn xuất khóa phiên từ bí mật DH + khóa khởi tạo K0)
Không tự cài đặt thuật toán mật mã lõi; chỉ ghép nối + kiểm tra tham số.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os

import warnings

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as _chmac
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# ---------------------------------------------------------------- Diffie-Hellman
# RFC 3526, nhóm 14 (MODP 2048-bit). p là số nguyên tố an toàn: p = 2q + 1, q nguyên tố.
# p = 2^2048 - 2^1984 - 1 + 2^64 * ( floor(2^1918 * pi) + 124476 ),  g = 2
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_P = int(_P_HEX, 16)
DH_G = 2
DH_Q = (DH_P - 1) // 2
DH_LEN = 256  # byte

_PARAM_NUMBERS = dh.DHParameterNumbers(DH_P, DH_G)
_PARAMS = _PARAM_NUMBERS.parameters()


class CryptoError(Exception):
    pass


def validate_dh_public(y: int) -> None:
    """Chặn giá trị suy biến / small-subgroup: 2 <= y <= p-2 và y^q = 1 (mod p)."""
    if not (2 <= y <= DH_P - 2):
        raise CryptoError("Khóa công khai DH nằm ngoài khoảng hợp lệ")
    if pow(y, DH_Q, DH_P) != 1:
        raise CryptoError("Khóa công khai DH không thuộc nhóm con bậc q")


class DHKeyPair:
    """Cặp khóa DH tạm thời (ephemeral): x ngẫu nhiên, y = g^x mod p."""

    def __init__(self) -> None:
        self._priv = _PARAMS.generate_private_key()
        y = self._priv.public_key().public_numbers().y
        self.public_bytes = y.to_bytes(DH_LEN, "big")

    def exchange(self, peer_public: bytes) -> bytes:
        if len(peer_public) != DH_LEN:
            raise CryptoError("Độ dài khóa công khai DH không đúng")
        y = int.from_bytes(peer_public, "big")
        validate_dh_public(y)
        peer = dh.DHPublicNumbers(y, _PARAM_NUMBERS).public_key()
        return self._priv.exchange(peer)  # K = y_peer^x mod p (256 byte)


# ---------------------------------------------------------------- RSA-PSS
RSA_BITS = 3072
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def rsa_generate(bits: int = RSA_BITS) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def rsa_sign(priv: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return priv.sign(data, _PSS, hashes.SHA256())


def rsa_verify(pub: rsa.RSAPublicKey, sig: bytes, data: bytes) -> bool:
    try:
        pub.verify(sig, data, _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def pub_to_der(pub: rsa.RSAPublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def pub_from_der(der: bytes) -> rsa.RSAPublicKey:
    try:
        pub = serialization.load_der_public_key(der)
    except Exception as e:  # noqa: BLE001
        raise CryptoError("Khóa công khai RSA không đọc được") from e
    if not isinstance(pub, rsa.RSAPublicKey):
        raise CryptoError("Chỉ chấp nhận khóa RSA")
    if pub.key_size < 2048:
        raise CryptoError("Khóa RSA quá yếu (< 2048 bit)")
    return pub


def fingerprint(der: bytes) -> str:
    """Vân tay khóa công khai: SHA-256(DER) dạng 'ab:cd:...' để so sánh ngoài kênh."""
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


# ---------------------------------------------------------------- Hash / HMAC / HKDF / AEAD
def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = _chmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def ct_equal(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)  # ném InvalidTag nếu sai/bị sửa


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
