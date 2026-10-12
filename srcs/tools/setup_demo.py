"""Tạo danh tính RSA cho các user và GHIM chéo khóa công khai (dùng chung trên 1 máy).

  python -m tools.setup_demo alice bob [--data-dir data]

Khi chạy trên 2 máy khác nhau: mỗi máy tự sinh khóa (chạy client 1 lần), rồi sao chép file
data/identities/<user>.pub sang data/trusted/ của máy kia (và đối chiếu vân tay qua kênh khác).
"""
from __future__ import annotations

import argparse
import os

from secure_chat.identity import Identity, TrustStore


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("users", nargs="+")
    ap.add_argument("--data-dir", default="data")
    a = ap.parse_args(argv)
    idents = [Identity.load_or_create(a.data_dir, u) for u in a.users]
    ts = TrustStore(os.path.join(a.data_dir, "trusted"), "strict")
    for i in idents:
        ts.pin(i.username, i.public_der)
        print(f"{i.username:>10}  {i.fingerprint}")
    print(f"\nĐã tạo khóa trong {a.data_dir}/identities và ghim vào {a.data_dir}/trusted")


if __name__ == "__main__":
    main()
