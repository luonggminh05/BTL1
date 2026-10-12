import os

import pytest

from secure_chat.filetransfer import IncomingFiles, OutgoingFile, TransferError, sanitize_filename
from secure_chat.session import Session, SessionError, KeyMaterial


def pair():
    km = KeyMaterial(os.urandom(32), os.urandom(32), os.urandom(32), os.urandom(4), os.urandom(4), os.urandom(16))
    return Session("b", "I", km), Session("a", "R", km)


def test_roundtrip_and_directions():
    i, r = pair()
    assert r.open(i.seal(1, b"hi")) == (1, b"hi")
    assert i.open(r.seal(1, b"yo")) == (1, b"yo")


def test_tamper_detected():
    i, r = pair()
    rec = i.seal(1, b"hello")
    import base64
    ct = bytearray(base64.b64decode(rec["c"])); ct[3] ^= 1
    rec["c"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(SessionError, match="Xác thực"):
        r.open(rec)


def test_replay_reorder_drop_detected():
    i, r = pair()
    a, b, c = i.seal(1, b"1"), i.seal(1, b"2"), i.seal(1, b"3")
    r.open(a)
    with pytest.raises(SessionError):
        r.open(a)          # replay
    with pytest.raises(SessionError):
        r.open(c)          # mất gói b


def test_reflection_detected():
    i, r = pair()
    rec = i.seal(1, b"x")
    with pytest.raises(SessionError):
        i.open(rec)        # phản xạ lại cho chính người gửi


def test_sanitize_filename():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\win.ini") == "win.ini"
    assert sanitize_filename("..") == "file.bin"
    assert "\x00" not in sanitize_filename("a\x00b.txt")


def test_file_transfer_ok_and_corrupt(tmp_path):
    src = tmp_path / "f.bin"; src.write_bytes(os.urandom(100_000))
    out = OutgoingFile(str(src))
    inc = IncomingFiles(str(tmp_path / "dl"))
    inc.on_offer("a", out.offer_body())
    for ch in out.chunks():
        inc.on_chunk("a", ch)
    info = inc.on_end("a", out.end_body())
    assert open(info["path"], "rb").read() == src.read_bytes()

    # tệp bị hỏng giữa đường -> hủy
    out2 = OutgoingFile(str(src))
    inc.on_offer("a", out2.offer_body())
    chunks = list(out2.chunks()); chunks[1] = chunks[1][:-1] + bytes([chunks[1][-1] ^ 1])
    for ch in chunks:
        inc.on_chunk("a", ch)
    with pytest.raises(TransferError):
        inc.on_end("a", out2.end_body())
    assert not any(n.endswith(".part") for n in os.listdir(tmp_path / "dl" / "a"))


def test_file_offer_path_traversal_and_oversize(tmp_path):
    inc = IncomingFiles(str(tmp_path / "dl"), max_size=10)
    import json
    body = json.dumps({"id": "00" * 16, "name": "../../evil.sh", "size": 5, "sha256": "0" * 64}).encode()
    info = inc.on_offer("a", body)
    assert info["name"] == "evil.sh"
    big = json.dumps({"id": "11" * 16, "name": "x", "size": 11, "sha256": "0" * 64}).encode()
    with pytest.raises(TransferError):
        inc.on_offer("a", big)
