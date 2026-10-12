"""Record layer: AES-256-GCM với số thứ tự (seq) chống phát lại / đảo thứ tự / xóa gói.

  nonce (12B) = iv_prefix (4B, dẫn xuất từ HKDF)  ||  seq (8B big-endian)
  AAD         = session_id (16B) || hướng (1B) || seq (8B)
  plaintext   = loại_thông_điệp (1B) || nội dung

Mỗi hướng (I->R và R->I) có KHÓA RIÊNG và bộ đếm riêng -> không bao giờ trùng (key, nonce).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag

from . import crypto

MSG_TEXT = 1
MSG_GREETING = 2
MSG_FILE_OFFER = 3
MSG_FILE_CHUNK = 4
MSG_FILE_END = 5

MAX_SEQ = 2**32  # giới hạn an toàn thực dụng cho GCM với nonce tuần tự


class SessionError(Exception):
    pass


@dataclass(frozen=True)
class KeyMaterial:
    k_i2r: bytes
    k_r2i: bytes
    k_conf: bytes
    iv_i2r: bytes
    iv_r2i: bytes
    session_id: bytes


class Session:
    def __init__(self, peer: str, role: str, km: KeyMaterial):
        assert role in ("I", "R")
        self.peer = peer
        self.role = role
        self.session_id = km.session_id
        if role == "I":
            self._sk, self._rk, self._siv, self._riv, self._sdir, self._rdir = (
                km.k_i2r, km.k_r2i, km.iv_i2r, km.iv_r2i, 0, 1)
        else:
            self._sk, self._rk, self._siv, self._riv, self._sdir, self._rdir = (
                km.k_r2i, km.k_i2r, km.iv_r2i, km.iv_i2r, 1, 0)
        self.send_seq = 0
        self.recv_seq = 0
        self.alive = True

    def _aad(self, direction: int, seq: int) -> bytes:
        return self.session_id + bytes([direction]) + seq.to_bytes(8, "big")

    def seal(self, mtype: int, body: bytes) -> dict:
        if not self.alive:
            raise SessionError("Phiên đã bị đóng")
        if self.send_seq >= MAX_SEQ:
            raise SessionError("Hết số thứ tự: cần bắt tay lại để đổi khóa")
        seq = self.send_seq
        nonce = self._siv + seq.to_bytes(8, "big")
        ct = crypto.aes_gcm_encrypt(self._sk, nonce, bytes([mtype]) + body, self._aad(self._sdir, seq))
        self.send_seq += 1
        return {"n": seq, "c": base64.b64encode(ct).decode("ascii")}

    def open(self, rec: dict) -> tuple[int, bytes]:
        if not self.alive:
            raise SessionError("Phiên đã bị đóng")
        try:
            seq = rec["n"]
            ct = base64.b64decode(rec["c"], validate=True)
        except Exception as e:  # noqa: BLE001
            raise SessionError("Bản ghi sai định dạng") from e
        if not isinstance(seq, int) or seq != self.recv_seq:
            raise SessionError(
                f"Sai số thứ tự (nhận {seq!r}, cần {self.recv_seq}): phát lại / đảo thứ tự / mất gói"
            )
        nonce = self._riv + seq.to_bytes(8, "big")
        try:
            pt = crypto.aes_gcm_decrypt(self._rk, nonce, ct, self._aad(self._rdir, seq))
        except InvalidTag as e:
            raise SessionError("Xác thực thất bại: bản mã bị sửa hoặc giả mạo") from e
        if not pt:
            raise SessionError("Bản ghi rỗng")
        self.recv_seq += 1
        return pt[0], pt[1:]

    def close(self) -> None:
        self.alive = False
