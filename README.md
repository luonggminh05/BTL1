# BTL1 – 1.1: Chat & truyền tệp mã hóa đầu cuối (E2EE)

Môn **CO3069 – Mật mã và An ninh mạng** (ĐH Bách Khoa TP.HCM).
Ứng dụng Client–Server (Python 3.10+) kết hợp:

| Thành phần | Thuật toán | Vai trò |
|---|---|---|
| Trao đổi khóa phiên | **Diffie-Hellman** nhóm MODP-2048 (RFC 3526 #14), khóa tạm thời | Tạo bí mật chung Z, có *forward secrecy* |
| Xác thực danh tính | **RSA-3072 + PSS (SHA-256)** ký toàn bộ transcript | Chống Man-in-the-Middle |
| Dẫn xuất khóa | **HKDF-SHA256**, salt = **K0 = SHA256(MSSV₁ ‖ MSSV₂ ‖ …)** | Khóa AES theo từng hướng, khóa xác nhận |
| Xác nhận khóa | **HMAC-SHA256** (Finished) | Hai bên chứng minh cùng khóa/cùng nhóm MSSV |
| Mã hóa dữ liệu | **AES-256-GCM** + số thứ tự | Bí mật + toàn vẹn + chống replay |
| Truyền tệp | Chia khối 32 KiB, đều qua AES-GCM + SHA-256 toàn tệp | E2EE cho tệp |

Server chỉ là **relay không tin cậy**: không có khóa nào, chỉ thấy bản mã.

## Yêu cầu MSSV của đề bài đã được đáp ứng ở đâu

* `Hello, We are [MSSV_1], [MSSV_2]` → bắt buộc có trong HS1/HS2 (được ký) **và** là thông điệp mã hóa đầu tiên của mỗi phía; đối tác từ chối nếu chuỗi khác (`secure_chat/config.py`, `handshake.py`, `client.py`).
* `Key = SHA256(MSSV_1 || MSSV_2 ..)` → `GroupConfig.initial_key` (K0), dùng làm *salt* HKDF khi sinh khóa phiên. Hai client khai báo MSSV khác nhau sẽ **không bắt tay được**.

## Cài đặt & Chạy chương trình

> **Lưu ý quan trọng**: Mọi lệnh bên dưới đều chạy từ thư mục `srcs/`.  
> Nếu terminal của bạn đang ở `e2e_chat`, bạn chỉ cần gõ: **`cd srcs`** (không gõ `cd e2e_chat/srcs`).

```bash
cd srcs                                                # di chuyển vào thư mục chứa code
pip install -r requirements-dev.txt                    # cài đặt thư viện cần thiết
```

## Chạy nhanh (tự động hoàn toàn)

```bash
python -m tools.demo_local --mssv 2411508 2312075   # server + alice + bob, chat + gửi tệp 1 MiB
python -m tools.mitm_demo                           # các kịch bản tấn công & cách giao thức chống lại
python -m pytest -q                                 # 34 test
```

## Chạy thủ công (3 terminal)

```bash
# (một lần) tạo khóa RSA cho các user và ghim chéo vào data/trusted
python -m tools.setup_demo alice bob

# Terminal 1 – server (-v để thấy server chỉ có bản mã)
python -m secure_chat.server --host 0.0.0.0 --port 5000 -v

# Terminal 2
python -m secure_chat.client --user alice --mssv 2411508 2312075
# Terminal 3
python -m secure_chat.client --user bob   --mssv 2411508 2312075
```

Trong alice: `/connect bob` → gõ chữ để chat → `/send ./file.pdf`.
Tệp nhận được lưu ở `data/downloads/<user>/<người_gửi>/`.

Lệnh: `/users /connect /use /send /sessions /fingerprint /trust /help /quit`.

### Chạy trên 2 máy khác nhau
1. Máy server: `python -m secure_chat.server --host 0.0.0.0 --port 5000`.
2. Mỗi máy client chạy client 1 lần để sinh khóa (`data/identities/<user>.pub`), rồi **trao đổi file `.pub` và đối chiếu vân tay qua kênh khác** (gặp trực tiếp/điện thoại).
3. Đặt file `.pub` của đối tác vào `data/trusted/<đối_tác>.pub` (hoặc lệnh `/trust <user> <file.pub>`).
4. Chạy client với `--host <IP server>`.

Chính sách tin cậy: `--trust strict` (mặc định, chỉ chấp nhận khóa đã ghim) hoặc `--trust tofu` (lần đầu tự ghim + in vân tay – tiện nhưng yếu hơn ở lần gặp đầu).
Khóa riêng có thể mã hóa bằng mật khẩu: đặt biến môi trường `E2E_KEY_PASSPHRASE` trước khi chạy.

## Cấu trúc thư mục

```
e2e_chat/
├─ README.md             hướng dẫn (đóng gói thành README.doc)
├─ srcs/                 TOÀN BỘ MÃ NGUỒN
│  ├─ secure_chat/
│  │  ├─ config.py        MSSV → chuỗi Hello, K0
│  │  ├─ crypto.py        DH, RSA-PSS, HKDF, HMAC, AES-GCM (bọc thư viện cryptography)
│  │  ├─ identity.py      khóa RSA dài hạn, kho khóa tin cậy (pinning / TOFU)
│  │  ├─ handshake.py     giao thức bắt tay 3 thông điệp (Initiator / Responder)
│  │  ├─ session.py       record layer AES-GCM + số thứ tự
│  │  ├─ filetransfer.py  gửi/nhận tệp theo khối, kiểm SHA-256, chống path traversal
│  │  ├─ framing.py       khung TCP [độ dài][JSON]
│  │  ├─ server.py        relay server (asyncio)
│  │  └─ client.py        ChatClient + giao diện dòng lệnh
│  ├─ tools/              setup_demo, demo_local, mitm_demo, package_submission
│  ├─ tests/              34 test (crypto, handshake, session, file, tích hợp, tấn công)
│  ├─ mssv.txt / mssv.example.txt
│  └─ requirements*.txt
├─ refs/REFERENCES.md    tài liệu tham khảo
├─ docs/PROTOCOL.md      TÀI LIỆU THIẾT KẾ GIAO THỨC + PHÂN TÍCH AN TOÀN
└─ dist/                 (tự sinh) Assigment1.zip: python -m tools.package_submission
```

## Gợi ý kịch bản demo khi bảo vệ
1. Chạy server với `-v`, mở 2 client, `/connect` → chỉ ra vân tay, `session_id` hai bên **trùng nhau**.
2. Gửi tin + tệp; chỉ màn hình server: chỉ thấy bản mã base64.
3. (Tùy chọn) Wireshark trên loopback, cổng 5000: tìm chuỗi `Hello, We are` chỉ xuất hiện trong gói bắt tay, mọi nội dung chat/tệp không đọc được.
4. Chạy `python -m tools.mitm_demo`: giải thích từng kịch bản A–E.
5. Chạy client thứ 3 với MSSV khác → bắt tay thất bại (K0 khác).

## Lưu ý
* Đây là sản phẩm học tập, chưa qua kiểm toán độc lập; không dùng cho dữ liệu thực.
* Mỗi nhóm nhớ đổi `--mssv` sang MSSV thật của nhóm (ví dụ trong repo chỉ là giả định).
* Mục 1.2 (CA / X.509) có thể thay bước *pinning* bằng kiểm tra chứng thư: điểm nối là `TrustStore.verify_peer()` trong `identity.py`.
