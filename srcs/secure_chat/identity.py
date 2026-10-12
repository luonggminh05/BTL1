"""Danh tính dài hạn (RSA) và kho khóa tin cậy (trust store).

* Mỗi người dùng có 1 cặp RSA-3072 dài hạn:  data/identities/<user>.key|.pub
* Khóa công khai của đối tác được 'ghim' (pin) tại: data/trusted/<peer>.pub
  - Chính sách 'strict' (mặc định): chỉ chấp nhận đối tác ĐÃ được ghim.
  - Chính sách 'tofu' : lần đầu gặp thì tự ghim (Trust On First Use) + in vân tay để so sánh.
  - Khóa của đối tác đã ghim mà thay đổi  -> luôn TỪ CHỐI (nghi ngờ MitM).
* Điểm mở rộng: ở mục 1.2 có thể thay bước này bằng kiểm tra chứng thư X.509 do CA cấp
  (xem TrustStore.verify_peer).
"""
from __future__ import annotations

import os
import re
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import crypto

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class TrustError(Exception):
    pass


def check_username(name: str) -> str:
    if not isinstance(name, str) or not USERNAME_RE.match(name):
        raise ValueError("Tên người dùng chỉ gồm A-Z a-z 0-9 _ . - (tối đa 32 ký tự)")
    return name


def _write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class Identity:
    def __init__(self, username: str, private_key: rsa.RSAPrivateKey):
        self.username = check_username(username)
        self.private_key = private_key
        self.public_der = crypto.pub_to_der(private_key.public_key())

    @property
    def fingerprint(self) -> str:
        return crypto.fingerprint(self.public_der)

    @classmethod
    def load_or_create(cls, data_dir: str, username: str, bits: int = crypto.RSA_BITS) -> "Identity":
        check_username(username)
        idir = os.path.join(data_dir, "identities")
        os.makedirs(idir, exist_ok=True)
        key_path = os.path.join(idir, f"{username}.key")
        pub_path = os.path.join(idir, f"{username}.pub")
        passphrase = os.environ.get("E2E_KEY_PASSPHRASE")
        pw = passphrase.encode() if passphrase else None
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=pw)
            if not isinstance(priv, rsa.RSAPrivateKey):
                raise ValueError("Khóa riêng không phải RSA")
        else:
            priv = crypto.rsa_generate(bits)
            enc = serialization.BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
            _write_private(
                key_path,
                priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc),
            )
        ident = cls(username, priv)
        with open(pub_path, "wb") as f:
            f.write(
                priv.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        return ident


def pem_to_der(pem: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pem)
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class TrustStore:
    def __init__(self, directory: str, policy: str = "strict", notify: Callable[[str], None] | None = None):
        if policy not in ("strict", "tofu"):
            raise ValueError("policy phải là 'strict' hoặc 'tofu'")
        self.dir = directory
        self.policy = policy
        self.notify = notify or (lambda s: None)
        os.makedirs(directory, exist_ok=True)

    def _path(self, peer: str) -> str:
        return os.path.join(self.dir, check_username(peer) + ".pub")

    def lookup(self, peer: str) -> bytes | None:
        p = self._path(peer)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return pem_to_der(f.read())

    def pin(self, peer: str, pub_der: bytes) -> None:
        pub = crypto.pub_from_der(pub_der)
        with open(self._path(peer), "wb") as f:
            f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def pin_file(self, peer: str, pub_file: str) -> str:
        with open(pub_file, "rb") as f:
            der = pem_to_der(f.read())
        self.pin(peer, der)
        return crypto.fingerprint(der)

    def verify_peer(self, peer: str, pub_der: bytes) -> None:
        """Kiểm tra khóa công khai mà đối tác trình ra có khớp khóa đã tin cậy không."""
        crypto.pub_from_der(pub_der)  # kiểm tra định dạng + độ dài
        pinned = self.lookup(peer)
        if pinned is not None:
            if not crypto.ct_equal(pinned, pub_der):
                raise TrustError(
                    f"KHÓA CỦA '{peer}' KHÁC với khóa đã ghim -> nghi ngờ tấn công MitM. "
                    f"Vân tay nhận được: {crypto.fingerprint(pub_der)}"
                )
            return
        if self.policy == "tofu":
            self.pin(peer, pub_der)
            self.notify(
                f"[TOFU] Lần đầu gặp '{peer}' - đã ghim khóa. Hãy so sánh vân tay NGOÀI KÊNH:\n"
                f"       {crypto.fingerprint(pub_der)}"
            )
            return
        raise TrustError(
            f"Chưa tin cậy khóa của '{peer}' (chính sách strict). Vân tay đối tác trình: "
            f"{crypto.fingerprint(pub_der)}. Dùng /trust {peer} <file.pub> hoặc chạy với --trust tofu."
        )
