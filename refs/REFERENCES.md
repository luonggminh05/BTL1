# Danh mục tài liệu tham khảo & nguồn mở (BTL1 - Đề 1.1)

Hệ thống Chat & Truyền tệp E2EE được thiết kế dựa trên các tiêu chuẩn mật mã học quốc tế và nội dung môn học CO3069 - Mật mã và An ninh mạng (ĐH Bách Khoa TP.HCM):

## 1. Tiêu chuẩn quốc tế (RFC / NIST)
1. **RFC 3526**: *More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)*.
   - Nhóm MODP 14 (2048-bit Safe Prime $p = 2q + 1$ với $g = 2$).
   - Sử dụng cho trao đổi khóa tạm thời Diffie-Hellman trong `secure_chat/crypto.py`.
2. **RFC 5869**: *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
   - Dùng để dẫn xuất các khóa phiên (khóa mã hóa 2 chiều, khóa xác nhận, IV prefix) từ bí mật $Z$ và $K_0$.
3. **RFC 8017**: *PKCS #1: RSA Cryptography Specifications Version 2.2*.
   - Chuẩn chữ ký số **RSASSA-PSS** với SHA-256 và MGF1-SHA256, salt 32 byte để xác thực danh tính hai đầu cuối.
4. **NIST SP 800-38D**: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
   - Chế độ mã hóa xác thực AEAD **AES-256-GCM** bảo vệ dữ liệu truyền và chống giả mạo, phát lại.

## 2. Các công trình mật mã học nền tảng
5. **Hugo Krawczyk (2003)**: *SIGMA: the ‘SIGn-and-MAc’ Approach to Authenticated Diffie-Hellman and its Use in the IKE-v2 Protocol*.
   - Giao thức bắt tay 3 bước kết hợp DH + RSA-PSS + HMAC xác nhận khóa để chống tấn công Man-in-the-Middle (MitM) và Identity Misbinding.
6. **RFC 8446**: *The Transport Layer Security (TLS) Protocol Version 1.3*.
   - Tham khảo kiến trúc tách biệt lớp bắt tay (Handshake) và lớp bản ghi (Record Layer).

## 3. Thư viện mã nguồn mở sử dụng
7. **Python Cryptography Library (pyca/cryptography)**:
   - Phiên bản: `>= 42.0`
   - Nhà phát triển: Python Cryptographic Authority
   - Giấy phép: Apache 2.0 / BSD 3-Clause
   - Địa chỉ: https://cryptography.io/en/latest/
   - Vai trò: Cung cấp cài đặt chuẩn OpenSSL cho các nguyên thủy mật mã lõi (RSA-PSS, FFDH, AES-GCM, HKDF, HMAC, SHA-256).

## 4. Giáo trình & Tài liệu môn học
8. **Bài giảng Mật mã và An ninh mạng (CO3069)** - Khoa Khoa học và Kỹ thuật Máy tính, Trường Đại học Bách Khoa – ĐHQG TP.HCM:
   - Chương II: Lý thuyết số và Mật mã cổ điển (Thuật toán Euclid mở rộng, Nghịch đảo Modulo, Lũy thừa modulo nhanh Square & Multiply, Căn nguyên thủy).
   - Chương III: Mã hóa khối và AES.
   - Chương IV: Mật mã khóa công khai, Trao đổi khóa Diffie-Hellman, Chữ ký số RSA, Tấn công Man-in-the-Middle (MitM) và Kênh phân phối khóa tin cậy.
