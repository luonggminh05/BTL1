# Tài liệu thiết kế giao thức & phân tích an toàn

**BTL1 – 1.1 · Hệ thống Chat và truyền tệp mã hóa đầu cuối** · CO3069

---

## 1. Mục tiêu và mô hình đe dọa

**Mục tiêu an toàn**

| Mã  | Mục tiêu                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------- |
| G1  | **Bí mật** nội dung chat và tệp: chỉ hai đầu cuối đọc được (kể cả server).                              |
| G2  | **Xác thực hai chiều**: mỗi bên biết chắc đang nói chuyện với đúng đối tác (đã tin cậy khóa công khai). |
| G3  | **Toàn vẹn & chống giả mạo**: mọi sửa đổi bị phát hiện.                                                 |
| G4  | **Chống phát lại / đảo thứ tự / xóa gói** trong một phiên.                                              |
| G5  | **Forward secrecy**: lộ khóa dài hạn (RSA) về sau không làm lộ các phiên cũ.                            |
| G6  | **Ràng buộc nhóm MSSV**: chỉ client cùng danh sách MSSV mới hoàn tất bắt tay (theo đề bài).             |

**Kẻ tấn công (Darth)** – theo mô hình Dolev–Yao: kiểm soát hoàn toàn mạng _và cả server relay_: nghe, chặn, sửa, chèn, phát lại, xóa gói. Darth **không** có khóa riêng RSA của hai đầu cuối và **không** giải được bài toán logarit rời rạc / phân tích thừa số.

**Ngoài phạm vi**: máy đầu cuối bị nhiễm mã độc; che giấu siêu dữ liệu (ai nói với ai, kích thước); máy tính lượng tử (xem §8).

---

## 2. Kiến trúc

```
 Alice ──TCP──►  Relay Server  ◄──TCP── Bob
   │               (không tin cậy)         │
   └─────── kênh E2E: AES-256-GCM ─────────┘
```

- Server chỉ nhận khung `{"type":"relay","to","kind","body"}` và chuyển tiếp; server **tự điền** trường `from`.
- Toàn bộ bắt tay và dữ liệu là **end-to-end** giữa hai client; server không giữ khóa nào.
- Khung TCP: `[4 byte độ dài big-endian][JSON UTF-8]`, tối đa 1 MiB/khung.

---

## 3. Tham số và ký hiệu

| Ký hiệu           | Giá trị                                                                                   |
| ----------------- | ----------------------------------------------------------------------------------------- |
| Nhóm DH           | RFC 3526 #14: p 2048-bit **số nguyên tố an toàn** (p = 2q+1), g = 2 (sinh nhóm con bậc q) |
| Danh tính dài hạn | RSA-3072, e = 65537; ký **RSASSA-PSS**, SHA-256, MGF1-SHA256, salt 32 byte                |
| MSSV nhóm         | `MSSV₁, MSSV₂, …` (thứ tự khai báo)                                                       |
| `HELLO`           | `"Hello, We are " + ", ".join(MSSV)` → `Hello, We are 2411508, 2312075`                   |
| **K0**            | `SHA256(MSSV₁ ‖ MSSV₂ ‖ …)` (nối chuỗi ASCII, không phân cách)                            |
| `H(x)`            | SHA-256                                                                                   |
| `LB`              | nhãn `"E2E-CHAT-v1"` (tách miền – domain separation)                                      |
| `lp(a,b,…)`       | mã hóa có tiền tố độ dài 4 byte cho mỗi phần (tránh nhập nhằng khi nối)                   |

---

## 4. Giao thức bắt tay (3 thông điệp, kiểu SIGMA)

I = bên khởi tạo (Alice), R = bên đáp (Bob). `x_I, x_R` là số mũ DH tạm thời; `y = g^x mod p`.

```mermaid
sequenceDiagram
    participant I as Alice (Initiator)
    participant S as Server (không tin cậy)
    participant R as Bob (Responder)
    I->>S: HS1 {id_I, HELLO, pub_I, nonce_I, y_I}
    S->>R: HS1
    Note over R: kiểm HELLO == HELLO của mình<br/>kiểm pub_I với kho tin cậy<br/>sinh y_R; Z = y_I^x_R; dẫn xuất khóa<br/>sig_R = Sign(LB‖"R-sig"‖H1); mac_R = HMAC(k_conf, "R-finished"‖H1)
    R->>S: HS2 {id_R, HELLO, pub_R, nonce_R, y_R, sig_R, mac_R}
    S->>I: HS2
    Note over I: kiểm HELLO, pub_R (tin cậy), sig_R, Z = y_R^x_I, mac_R<br/>sig_I = Sign(LB‖"I-sig"‖H2); mac_I = HMAC(k_conf, "I-finished"‖H3)
    I->>S: HS3 {sig_I, mac_I}
    S->>R: HS3
    Note over R: kiểm sig_I, mac_I → phiên thiết lập
    I-->>R: [AES-GCM] GREETING = "Hello, We are 2411508, 2312075"
    R-->>I: [AES-GCM] GREETING
```

**Transcript** (mọi chuỗi mã hóa bằng `lp`, gồm cả danh tính, khóa công khai RSA, nonce, giá trị DH, phiên bản):

```
T1 = enc(HS1) ‖ enc(HS2 không có sig/mac)        H1 = H(T1)
T2 = T1 ‖ lp(sig_R, mac_R)                        H2 = H(T2)
T3 = T2 ‖ lp(sig_I)                               H3 = H(T3)
```

**Dẫn xuất khóa** (cả hai tính được sau khi có `y_I`, `y_R`):

```
Z    = DH(y_I, y_R)                         // 256 byte
OKM  = HKDF-SHA256( ikm = Z, salt = K0, info = LB ‖ " keys" ‖ H1, L = 120 )
k_I→R = OKM[0:32]   k_R→I = OKM[32:64]   k_conf = OKM[64:96]
iv_I→R = OKM[96:100] iv_R→I = OKM[100:104]  session_id = OKM[104:120]
```

**Vai trò của từng cơ chế**

| Cơ chế                                                 | Chống gì                                                                                         |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| DH tạm thời                                            | Bí mật chung không bao giờ đi qua mạng; forward secrecy                                          |
| Chữ ký RSA-PSS trên transcript                         | **MitM**: thay bất kỳ `y`, nonce, danh tính, khóa công khai nào đều làm `H1/H2` đổi → chữ ký sai |
| HMAC(k_conf) “Finished”                                | Xác nhận hai bên **cùng** khóa (key confirmation); phát hiện sửa đổi và khác nhóm MSSV           |
| K0 (từ MSSV) trong HKDF                                | Ràng buộc nhóm: khác danh sách MSSV ⇒ khóa khác ⇒ HMAC sai ⇒ bắt tay hỏng                        |
| Nonce 32 byte + DH mới mỗi lần                         | Chống phát lại bắt tay; mỗi phiên khóa độc lập                                                   |
| Danh tính + vai trò (`R-sig`/`I-sig`) trong dữ liệu ký | Chống _reflection_ và _unknown-key-share_                                                        |
| Kho tin cậy (pinning)                                  | Gắn _tên người dùng_ với _khóa RSA_ (xem §6)                                                     |

Kiểm tra khóa DH nhận được: `2 ≤ y ≤ p−2` và `y^q ≡ 1 (mod p)` (chặn small-subgroup / giá trị suy biến).

---

## 5. Lớp bản ghi (Record layer) & truyền tệp

```
nonce (12B) = iv_prefix(4B) ‖ seq(8B)
AAD         = session_id(16B) ‖ hướng(1B) ‖ seq(8B)
bản mã      = AES-256-GCM( key_hướng, nonce, loại(1B) ‖ nội dung, AAD )
```

- Mỗi hướng một khóa + bộ đếm riêng ⇒ không bao giờ lặp (key, nonce).
- Bên nhận **chỉ chấp nhận đúng `seq` kế tiếp**; sai ⇒ **đóng phiên** (fail-closed). Hướng nằm trong AAD ⇒ chống phản xạ gói về người gửi.
- Loại thông điệp: `TEXT`, `GREETING`, `FILE_OFFER`, `FILE_CHUNK`, `FILE_END`.
- **Tệp**: `OFFER{id, name, size, sha256}` → các `CHUNK{id, idx, data≤32 KiB}` → `END{id}`. Bên nhận: kiểm `idx` tuần tự, không vượt `size`, ghi vào `.part`, **kiểm SHA-256 toàn tệp** rồi mới đổi tên; lọc tên tệp (chống `../`), giới hạn 256 MiB và 4 tệp đồng thời.

---

## 6. Quản lý khóa tin cậy

Chữ ký chỉ chứng minh “người này giữ khóa riêng của khóa công khai X”. Việc **X thuộc về Bob** cần kênh tin cậy:

- `strict` (mặc định): chỉ chấp nhận khóa đã được ghim (`data/trusted/<tên>.pub`), đối chiếu **vân tay SHA-256** ngoài kênh.
- `tofu`: lần đầu tự ghim và in vân tay (SSH-style); lần sau khóa đổi ⇒ **luôn từ chối**.
- Điểm mở rộng cho **mục 1.2**: thay `TrustStore.verify_peer()` bằng kiểm tra chứng thư X.509 do CA nội bộ cấp (kèm CRL/OCSP) — khi đó không cần ghim thủ công.

---

## 7. Phân tích an toàn

### 7.1 Bảng đe dọa – biện pháp – kiểm chứng

| #   | Tấn công                                                                | Biện pháp                                                                                                                            | Kiểm chứng (test / demo)                                                                                                                         |
| --- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Nghe lén thụ động (kể cả server)                                        | AES-256-GCM, khóa từ DH                                                                                                              | `mitm_demo` A; server chỉ thấy bản mã                                                                                                            |
| 2   | **MitM lên DH** (Darth đóng giả hai đầu, như slide “Man-in-the-Middle”) | DH được **ký** cùng toàn transcript; kiểm khóa RSA đã ghim                                                                           | `mitm_demo` B (DH trần bị phá), C (giao thức này bị chặn: _“CHỮ KÝ … KHÔNG HỢP LỆ”_); `test_swapped_dh_detected`, `test_hs2_dh_swapped_detected` |
| 3   | Thay khóa công khai RSA bằng khóa của Darth                             | Khóa ≠ khóa đã ghim ⇒ từ chối                                                                                                        | `mitm_demo` D; `test_pinned_key_change_rejected_even_in_tofu`                                                                                    |
| 4   | Giả danh (không có khóa riêng)                                          | Cần `sig_I` / `sig_R` hợp lệ                                                                                                         | `test_forged_hs3_rejected`                                                                                                                       |
| 5   | Sửa bản mã                                                              | Thẻ GCM sai ⇒ đóng phiên                                                                                                             | `mitm_demo` E1; `test_tamper_detected`                                                                                                           |
| 6   | Phát lại / đảo thứ tự / xóa giữa chừng                                  | `seq` chặt + nonce theo `seq` + AAD                                                                                                  | `mitm_demo` E2; `test_replay_reorder_drop_detected`                                                                                              |
| 7   | Phản xạ gói về người gửi                                                | Khóa & AAD riêng từng hướng                                                                                                          | `test_reflection_detected`                                                                                                                       |
| 8   | Phát lại bắt tay cũ                                                     | Nonce + DH mới + chữ ký phủ transcript                                                                                               | Replay HS3 bị bác: `test_forged_hs3_rejected`                                                                                                    |
| 9   | Server khai sai `from`                                                  | `id` nằm trong phần được ký, phải khớp người gửi và khóa đã ghim                                                                     | `test_identity_mismatch_envelope`                                                                                                                |
| 10  | Client khác nhóm MSSV                                                   | Chuỗi Hello khác + K0 khác ⇒ HMAC sai                                                                                                | `test_wrong_group_mssv_rejected`, `test_different_mssv_cannot_handshake`                                                                         |
| 11  | Khóa DH độc (small subgroup)                                            | Kiểm `y^q = 1`, `2 ≤ y ≤ p−2`                                                                                                        | `test_dh_rejects_*`                                                                                                                              |
| 12  | Tệp bị hỏng/độc: path traversal, vượt kích thước, thiếu/đổi khối        | Lọc tên, giới hạn, kiểm `idx`, SHA-256                                                                                               | `test_file_*`, `test_sanitize_filename`                                                                                                          |
| 13  | Tấn công thời gian (Kocher)                                             | RSA của OpenSSL có _blinding_; so sánh MAC bằng `compare_digest`; AES-GCM hằng thời gian                                             | thiết kế (không có phép tự cài)                                                                                                                  |
| 14  | Hạ cấp thuật toán                                                       | Không thương lượng thuật toán, chỉ 1 bộ; `v` nằm trong transcript                                                                    | thiết kế                                                                                                                                         |
| 15  | Lộ khóa RSA dài hạn trong tương lai                                     | Khóa phiên chỉ phụ thuộc DH tạm thời đã xóa ⇒ **forward secrecy**; kẻ có khóa RSA của I vẫn _không_ giả được R với I (KCI-resistant) | thiết kế                                                                                                                                         |

### 7.2 Vì sao DH “trần” hỏng còn bản này thì không?

Trong DH thuần, Alice không có cách biết `y_B` nhận được là của Bob hay Darth (thiếu _authentication_). Ở đây `y_R` nằm trong dữ liệu mà Bob **ký**; Darth không thể tạo chữ ký của Bob cho giá trị `y_D` của hắn, và nếu hắn đổi `y_I` trên đường tới Bob thì Bob ký trên transcript khác với transcript Alice tính ⇒ Alice thấy chữ ký sai. Tức _phân phối khóa công khai có xác thực_ (Chương IV: chứng chỉ/CA, challenge–response bằng nonce) được hiện thực bằng chữ ký + khóa đã ghim.

### 7.3 Về “khóa khởi tạo từ MSSV”

`K0 = SHA256(MSSV…)` đúng yêu cầu đề bài và được dùng làm **salt/khóa khởi tạo của KDF**. Tuy nhiên MSSV có **entropy thấp** (vài chục bit, dễ đoán) nên K0 **không phải bí mật mạnh**: nó đóng vai trò _ràng buộc nhóm / tách miền_, còn độ an toàn thật sự đến từ DH 2048-bit + chữ ký RSA-3072. Đây là lựa chọn có chủ đích; không thiết kế để bảo mật phụ thuộc vào K0.

### 7.4 Hạn chế đã biết (nên nêu trong báo cáo)

1. **Siêu dữ liệu** (ai nhắn ai, thời điểm, độ dài gói) lộ cho server; chưa đệm độ dài.
2. **Cắt cụt luồng chat**: server có thể ngừng chuyển các gói _cuối_ mà bên nhận không biết (không có thông điệp kết thúc xác thực). Với tệp thì `END` + SHA-256 bảo vệ.
3. Chưa có _ratchet_ (đổi khóa liên tục); đổi khóa bằng cách bắt tay lại (`/connect`) hoặc khi `seq` chạm 2³².
4. Tin cậy khóa lần đầu: `strict` cần quy trình thủ công; `tofu` yếu hơn ở lần gặp đầu. Mục 1.2 (CA/X.509) sẽ khắc phục.
5. Không có giới hạn tốc độ (rate limit) ở server ⇒ DoS đơn giản; đã có giới hạn kích thước khung/tệp.
6. Mã không qua kiểm toán độc lập.

---

## 8. Thảo luận (liên hệ slide “pháo đài toán học nào sụp trước?”)

RSA dựa trên phân tích thừa số, DH/ECC dựa trên logarit rời rạc; **thuật toán Shor** trên máy tính lượng tử đủ lớn giải cả hai trong thời gian đa thức nên **cả RSA và DH (kể cả ECC) đều sụp**; ECC dùng khóa nhỏ hơn nên cần ít qubit hơn để phá. AES-256 và SHA-256 chỉ bị giảm một nửa độ mạnh (Grover). Hướng nâng cấp: thay DH bằng KEM hậu lượng tử (ML-KEM) và RSA-PSS bằng chữ ký hậu lượng tử (ML-DSA) hoặc chế độ lai.

---

## 9. Ánh xạ với nội dung môn học

| Nội dung                                                          | Nơi dùng                                              |
| ----------------------------------------------------------------- | ----------------------------------------------------- |
| Euclid mở rộng, nghịch đảo modulo (Ch. II)                        | RSA keygen (`d = e⁻¹ mod φ(n)`) do thư viện thực hiện |
| Lũy thừa modulo nhanh – Square & Multiply (Ch. II)                | `y = g^x mod p`, `pow(y, q, p)` kiểm khóa DH          |
| Định lý Euler / vì sao RSA đúng (Ch. IV)                          | Chữ ký/Xác minh RSA-PSS                               |
| Diffie-Hellman, logarit rời rạc, căn nguyên thủy (Ch. II, IV)     | Trao đổi khóa phiên (g = 2, p an toàn)                |
| Tấn công Man-in-the-Middle; challenge–response với nonce (Ch. IV) | Chữ ký transcript + nonce; `mitm_demo`                |
| Mật mã lai (public-key + AES) như TLS (Ch. IV)                    | Kiến trúc tổng thể                                    |
| Tấn công thời gian, OAEP/CCA (Ch. IV)                             | Mục 7.1 (#13); dùng PSS/GCM thay vì RSA thô           |
