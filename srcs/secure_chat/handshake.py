"""Giao thức bắt tay 3 thông điệp (kiểu SIGMA): DH tạm thời + chữ ký RSA-PSS + HMAC xác nhận khóa.

  I (Initiator)                                      R (Responder)
  HS1: {id_I, hello, pub_I, nonce_I, dh_I}  ───────────────►
                                             ◄─────────────  HS2: {id_R, hello, pub_R, nonce_R, dh_R,
                                                                    sig_R, mac_R}
  HS3: {sig_I, mac_I}                        ───────────────►
  (sau đó: MSG_GREETING mã hóa 2 chiều chứa 'Hello, We are <MSSV...>')

  T1 = enc(HS1) || enc(HS2 không chữ ký/mac)         H1 = SHA256(T1)
  Z  = DH(dh_I, dh_R)                                 (bí mật chung, 256B)
  keys = HKDF-SHA256(ikm = Z, salt = K0, info = "E2E-CHAT-v1 keys" || H1)
         với K0 = SHA256(MSSV_1 || MSSV_2 || ...)  (khóa khởi tạo theo đề bài)
  sig_R = RSA-PSS(R, "E2E-CHAT-v1 R-sig" || H1)       mac_R = HMAC(k_conf, "R-finished" || H1)
  T2 = T1 || sig_R || mac_R                           H2 = SHA256(T2)
  sig_I = RSA-PSS(I, "E2E-CHAT-v1 I-sig" || H2)
  T3 = T2 || sig_I                                    mac_I = HMAC(k_conf, "I-finished" || SHA256(T3))

Chữ ký phủ toàn bộ transcript (gồm cả 2 giá trị DH, 2 nonce, 2 danh tính, 2 khóa công khai) nên kẻ
Man-in-the-Middle thay bất kỳ giá trị DH nào cũng làm chữ ký sai -> bị phát hiện.
"""
from __future__ import annotations

import base64
import binascii
import re

from . import crypto
from .config import GroupConfig
from .identity import Identity, TrustStore, TrustError, USERNAME_RE
from .session import KeyMaterial, Session

VERSION = 1
LABEL = b"E2E-CHAT-v1"
NONCE_LEN = 32
MAX_HELLO = 256
MAX_PUB = 1024


class HandshakeError(Exception):
    pass


def _lp(*parts: bytes) -> bytes:
    """Mã hóa có tiền tố độ dài (tránh nhập nhằng khi nối chuỗi)."""
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: object, field: str, exact: int | None = None, maxlen: int | None = None) -> bytes:
    if not isinstance(s, str):
        raise HandshakeError(f"Trường '{field}' sai kiểu")
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise HandshakeError(f"Trường '{field}' không phải base64 hợp lệ") from e
    if exact is not None and len(b) != exact:
        raise HandshakeError(f"Trường '{field}' sai độ dài")
    if maxlen is not None and len(b) > maxlen:
        raise HandshakeError(f"Trường '{field}' quá dài")
    return b


def _parse_hello_part(m: dict, tag: bytes) -> tuple[dict, bytes]:
    """Kiểm tra cấu trúc HS1 / HS2core, trả về (trường đã giải mã, encoding chuẩn cho transcript)."""
    if not isinstance(m, dict) or m.get("v") != VERSION:
        raise HandshakeError("Phiên bản giao thức không hỗ trợ")
    ident, hello = m.get("id"), m.get("hello")
    if not isinstance(ident, str) or not USERNAME_RE.match(ident):
        raise HandshakeError("Danh tính không hợp lệ")
    if not isinstance(hello, str) or len(hello) > MAX_HELLO:
        raise HandshakeError("Chuỗi hello không hợp lệ")
    f = {
        "id": ident,
        "hello": hello,
        "pub": _b64d(m.get("pub"), "pub", maxlen=MAX_PUB),
        "nonce": _b64d(m.get("nonce"), "nonce", exact=NONCE_LEN),
        "dh": _b64d(m.get("dh"), "dh", exact=crypto.DH_LEN),
    }
    enc = _lp(tag, bytes([VERSION]), ident.encode(), hello.encode(), f["pub"], f["nonce"], f["dh"])
    return f, enc


def _derive(group: GroupConfig, z: bytes, h1: bytes) -> KeyMaterial:
    okm = crypto.hkdf(z, group.initial_key, LABEL + b" keys" + h1, 32 + 32 + 32 + 4 + 4 + 16)
    return KeyMaterial(
        k_i2r=okm[0:32], k_r2i=okm[32:64], k_conf=okm[64:96],
        iv_i2r=okm[96:100], iv_r2i=okm[100:104], session_id=okm[104:120],
    )


def _check_hello(group: GroupConfig, hello: str) -> None:
    if hello != group.hello:
        raise HandshakeError(
            f"Chuỗi Hello của đối tác ({hello!r}) không khớp nhóm MSSV của bạn ({group.hello!r})"
        )


class Initiator:
    def __init__(self, ident: Identity, peer: str, group: GroupConfig, trust: TrustStore):
        self.ident, self.peer, self.group, self.trust = ident, peer, group, trust
        self._dh: crypto.DHKeyPair | None = None
        self._enc1: bytes | None = None

    def start(self) -> dict:
        self._dh = crypto.DHKeyPair()
        msg = {
            "v": VERSION,
            "id": self.ident.username,
            "hello": self.group.hello,
            "pub": _b64e(self.ident.public_der),
            "nonce": _b64e(crypto.random_bytes(NONCE_LEN)),
            "dh": _b64e(self._dh.public_bytes),
        }
        _, self._enc1 = _parse_hello_part(msg, b"hs1")
        return msg

    def on_hs2(self, m: dict) -> tuple[dict, Session]:
        if self._dh is None or self._enc1 is None:
            raise HandshakeError("Chưa gọi start()")
        f, enc2 = _parse_hello_part(m, b"hs2")
        if f["id"] != self.peer:
            raise HandshakeError(f"HS2 tuyên bố danh tính '{f['id']}' khác đối tác '{self.peer}'")
        _check_hello(self.group, f["hello"])
        try:
            self.trust.verify_peer(self.peer, f["pub"])
        except TrustError as e:
            raise HandshakeError(str(e)) from e
        pub_r = crypto.pub_from_der(f["pub"])
        sig_r = _b64d(m.get("sig"), "sig", maxlen=1024)
        mac_r = _b64d(m.get("mac"), "mac", exact=32)

        t1 = self._enc1 + enc2
        h1 = crypto.sha256(t1)
        if not crypto.rsa_verify(pub_r, sig_r, LABEL + b" R-sig" + h1):
            raise HandshakeError("CHỮ KÝ của đối tác trong HS2 KHÔNG HỢP LỆ (nghi ngờ MitM / giả mạo)")
        try:
            z = self._dh.exchange(f["dh"])
        except crypto.CryptoError as e:
            raise HandshakeError(f"Khóa DH của đối tác không hợp lệ: {e}") from e
        km = _derive(self.group, z, h1)
        if not crypto.ct_equal(mac_r, crypto.hmac_sha256(km.k_conf, b"R-finished" + h1)):
            raise HandshakeError("HMAC xác nhận khóa sai (khác nhóm MSSV hoặc bị sửa đổi)")

        t2 = t1 + _lp(sig_r, mac_r)
        sig_i = crypto.rsa_sign(self.ident.private_key, LABEL + b" I-sig" + crypto.sha256(t2))
        t3 = t2 + _lp(sig_i)
        mac_i = crypto.hmac_sha256(km.k_conf, b"I-finished" + crypto.sha256(t3))
        self._dh = None  # xóa khóa DH tạm thời (forward secrecy)
        return {"sig": _b64e(sig_i), "mac": _b64e(mac_i)}, Session(self.peer, "I", km)


class Responder:
    def __init__(self, ident: Identity, peer: str, group: GroupConfig, trust: TrustStore):
        self.ident, self.peer, self.group, self.trust = ident, peer, group, trust
        self._t2: bytes | None = None
        self._pub_i = None
        self._km: KeyMaterial | None = None

    def on_hs1(self, m: dict) -> dict:
        f, enc1 = _parse_hello_part(m, b"hs1")
        if f["id"] != self.peer:
            raise HandshakeError(f"HS1 tuyên bố danh tính '{f['id']}' khác người gửi '{self.peer}'")
        _check_hello(self.group, f["hello"])
        try:
            self.trust.verify_peer(self.peer, f["pub"])
        except TrustError as e:
            raise HandshakeError(str(e)) from e
        self._pub_i = crypto.pub_from_der(f["pub"])

        dhk = crypto.DHKeyPair()
        core = {
            "v": VERSION,
            "id": self.ident.username,
            "hello": self.group.hello,
            "pub": _b64e(self.ident.public_der),
            "nonce": _b64e(crypto.random_bytes(NONCE_LEN)),
            "dh": _b64e(dhk.public_bytes),
        }
        _, enc2 = _parse_hello_part(core, b"hs2")
        t1 = enc1 + enc2
        h1 = crypto.sha256(t1)
        try:
            z = dhk.exchange(f["dh"])
        except crypto.CryptoError as e:
            raise HandshakeError(f"Khóa DH của đối tác không hợp lệ: {e}") from e
        self._km = _derive(self.group, z, h1)
        sig_r = crypto.rsa_sign(self.ident.private_key, LABEL + b" R-sig" + h1)
        mac_r = crypto.hmac_sha256(self._km.k_conf, b"R-finished" + h1)
        self._t2 = t1 + _lp(sig_r, mac_r)
        return {**core, "sig": _b64e(sig_r), "mac": _b64e(mac_r)}

    def on_hs3(self, m: dict) -> Session:
        if self._t2 is None or self._km is None or self._pub_i is None:
            raise HandshakeError("Chưa nhận HS1")
        if not isinstance(m, dict):
            raise HandshakeError("HS3 sai định dạng")
        sig_i = _b64d(m.get("sig"), "sig", maxlen=1024)
        mac_i = _b64d(m.get("mac"), "mac", exact=32)
        if not crypto.rsa_verify(self._pub_i, sig_i, LABEL + b" I-sig" + crypto.sha256(self._t2)):
            raise HandshakeError("CHỮ KÝ của đối tác trong HS3 KHÔNG HỢP LỆ (nghi ngờ giả mạo)")
        t3 = self._t2 + _lp(sig_i)
        if not crypto.ct_equal(mac_i, crypto.hmac_sha256(self._km.k_conf, b"I-finished" + crypto.sha256(t3))):
            raise HandshakeError("HMAC xác nhận khóa trong HS3 sai")
        km, self._km = self._km, None
        return Session(self.peer, "R", km)
