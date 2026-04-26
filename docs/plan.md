# Background

Đây là **Master Plan (Kế hoạch Tổng thể)** cuối cùng, được tối ưu hóa để thỏa mãn cả 3 mục tiêu:

1. **Nghiên cứu khoa học (Academic Research):** Thống kê bao quát, số liệu "khủng", chứng minh độ dày công nghiên cứu (Census).
2. **Yêu cầu của Thầy:** Trả lời chính xác về độ khó, khả năng build, khả năng exploit, và xếp hạng theo năm.
3. **Dự án AI Pentest:** Tạo ra dataset chất lượng cao (Ground Truth) để huấn luyện/test AI.

---

### PHẦN 1: KIẾN TRÚC HỆ THỐNG & CÔNG CỤ

- **Database:** **Neon (PostgreSQL Cloud)**. Đây là "Kho chứa sự thật" duy nhất. Cả 2 thành viên đều connect vào đây.
- **Client:** **WSL (Ubuntu) + VSCode**.
    - Extension: **Database Client** (để query/nhận task).
    - Docker: Để dựng môi trường kiểm thử (Sandbox).
- **Nguồn dữ liệu:**
    1. **GitHub Advisory (GHSA):** Nguồn chính, cung cấp metadata, mô tả, bản vá.
    2. **Exploit-DB (EDB):** Nguồn tham chiếu chéo. Với mỗi CVE từ GHSA, phải tìm xem có ID tương ứng bên Exploit-DB không.

---

### PHẦN 2: THIẾT KẾ DỮ LIỆU (MAPPING YÊU CẦU CỦA THẦY)

Đây là phần quan trọng nhất. Bạn cần thiết kế bảng trong DB sao cho mỗi cột đều trả lời một câu hỏi của thầy.

**Tên bảng:** `web_cve_census_master`

| **Yêu cầu của Thầy** | **Tên trường trong DB (Column)** | **Kiểu dữ liệu** | **Lưu ý khi điền dữ liệu** |
| --- | --- | --- | --- |
| **"Có bao nhiêu? Con số cụ thể?"** | `id` (Count tổng) | Integer | Đếm tổng số dòng -> Ra quy mô nghiên cứu (VD: 12,450 CVEs). |
| **"Ranking theo năm"** | `publish_year` | Integer | Dùng để `GROUP BY` và vẽ biểu đồ từ 2025 về 2015. |
| **"Độ khó tấn công?" (Lý thuyết)** | `cvss_attack_complexity` | Enum (Low/High) | Lấy từ CVSS Vector. |
| **"Độ khó tấn công?" (Thực tế)** | `research_build_effort` | ENUM | **(Người điền)
Mức độ tái hiện:** 

`TRIVIAL` (Dễ ợt: Có Docker sẵn, chạy 1 lệnh là lên).

`MODERATE` (Trung bình: Cần cài thêm lib, sửa config nhẹ).

`HARD` (Khó: Code cũ, lỗi dependency, cần môi trường OS đặc biệt).

`IMPOSSIBLE` (Bó tay: Cần phần mềm trả phí, cần hardware riêng, link chết sạch). |
| **"Có khả thi không?" (Feasibility)** | `epss_score` | Float (0.0 - 1.0) | Điểm xác suất bị hack thực tế. |
| **"Có code exploit không?"** | `exploit_availability` | Enum | `NONE` (Chỉ có tên), `PUBLIC_POC` (GitHub), `EXPLOIT_DB` (Có trên EDB). |
| **"Link Exploit-DB tương ứng"** | `exploit_db_id` | Varchar | Link/ID tới bài trên Exploit-DB (nếu có). |
| **"Có build được không?"** | `build_status` | Enum | `SKIPPED` (Chưa thử), `SUCCESS` (Dựng được), `FAILED_DEPENDENCY` (Thiếu lib), `FAILED_OBSOLETE` (Code quá cũ). |
| **"Source exploit chạy được không?"** | `exploit_verification` | Enum | `UNVERIFIED`, `CONFIRMED_SHELL` (Hack xong), `CONFIRMED_ERROR` (Code sai). |
| **"Chứng minh không phải chó táp phải ruồi"** | `research_depth_level` | Enum | `LEVEL_0` (Chỉ crawl tên), `LEVEL_1` (Đã review code), `LEVEL_2` (Đã dựng Docker & Hack). |

---

### PHẦN 3: QUY TRÌNH THU THẬP TỰ ĐỘNG (THE CENSUS)

**Mục tiêu:** Lấp đầy các trường "Lý thuyết" cho toàn bộ 10 năm (2015-2025).

1. **Bước 1: Quét GitHub Advisory (Bộ lọc Web chặt chẽ)**
    - Thời gian: `2015-01-01` đến `Nay`.
    - Ecosystem: `npm`, `maven`, `pip`, `composer`, `go`, `rubygems`.
    - **Bộ lọc CWE (Bắt buộc):** Chỉ lấy nếu CWE ID thuộc danh sách: Injection (`89`, `78`, `94`), XSS (`79`), Auth (`287`, `639`), Deserialization (`502`), SSRF (`918`), Path Traversal (`22`).
    - *Lưu ý:* Lưu cả những cái không có code (Level 0) để làm đẹp số liệu thống kê.
2. **Bước 2: Cross-Check với Exploit-DB**
    - Tải file `files_exploits.csv` từ Exploit-DB về.
    - Dùng script Python quét lại DB:
        - Lấy `CVE-ID` từ bảng `web_cve_census_master`.
        - Tra cứu trong file CSV của Exploit-DB.
        - Nếu tìm thấy -> Update cột `exploit_db_id` và set `exploit_availability = 'EXPLOIT_DB'`.
    - *Ý nghĩa:* Bước này tự động trả lời câu hỏi "Có khả thi hay không?" ở quy mô lớn mà chưa cần chạy thử.

---

### PHẦN 4: QUY TRÌNH PHÂN TÍCH & KIỂM THỬ (MANUAL VERIFY)

**Mục tiêu:** Lấp đầy các trường "Thực tế" (Build, Exploit) cho tập dữ liệu tinh hoa (Top 50-100 mẫu).

**Cách chia việc (Teamwork):**

- **Nguyên tắc:** "Cuốn chiếu ngược dòng" (2025 -> 2015).
- **Batching:** Mỗi người "Claim" (nhận) 5 task/lần trên Neon DB.
- **Tiêu chí chọn Task:** Chỉ nhận những CVE có `exploit_availability` là `EXPLOIT_DB` hoặc `PUBLIC_POC`. (Đừng tốn thời gian vào cái không có code).

**Quy trình 4 Bước cho mỗi Task:**

1. **Đánh giá Sơ bộ (Triage):**
    - Đọc CVE. Click link Exploit-DB/GitHub.
    - *Câu hỏi:* Có Dockerfile không? Code exploit là Python/Bash hay chỉ là văn bản hướng dẫn?
    - *Quyết định:* Nếu quá mù mờ -> Update `build_status = 'SKIPPED'` -> Next.
2. **Dựng Môi trường (Build):**
    - Tạo folder `CVE-XXXX-XXXX`. Viết `Dockerfile` hoặc `docker-compose.yml`.
    - Bấm giờ. Nếu tốn > 60 phút mà không lên -> Update `build_status = 'FAILED'`, `research_build_effort = 60` -> Next.
    - Nếu lên -> Update `build_status = 'SUCCESS'`.
3. **Thực nghiệm Tấn công (Exploit):**
    - Chạy script exploit vào container.
    - *Câu hỏi:* Có lấy được Shell / Token / File `/etc/passwd` không?
    - Nếu thành công -> Update `exploit_verification = 'CONFIRMED_SHELL'`. Lưu script exploit "chuẩn" lại vào folder.
    - Nếu thất bại -> Update `exploit_verification = 'CONFIRMED_ERROR'` và ghi chú lý do (VD: Phiên bản thư viện lệch).
4. **Đóng gói cho AI (Final):**
    - Zip folder lại (gồm Docker + Exploit Script). Đây chính là "Đề thi" cho con AI sau này.

---

### PHẦN 5: BÁO CÁO KẾT QUẢ (CHO THẦY & Báo)

Khi DB đã có dữ liệu, bạn sẽ xuất ra các báo cáo sau:

**Báo cáo 1: Tổng quan (The Census)**

> *"Chúng tôi đã khảo sát **12,450** CVE Web từ 2015-2025. Trong đó, **3,200** CVE (25%) đã được xác thực chéo là có mã khai thác trên Exploit-DB."* -> (Thể hiện sự nghiên cứu kỹ, số liệu cụ thể).
> 

**Báo cáo 2: Đánh giá độ khả thi (Feasibility)**

> *"Dựa trên chỉ số EPSS và đối chiếu Exploit-DB, năm 2024 có tỷ lệ lỗ hổng khả thi cao nhất (Exploitable) là **18%**, tập trung vào các nhóm lỗi Deserialization."*
> 

**Báo cáo 3: Kết quả thực nghiệm (Verification)**

> *"Tiến hành kiểm thử ngẫu nhiên **100** mẫu có PoC. Kết quả:
> 
> - **65%** dựng được môi trường thành công (Buildable).
> - **40%** khai thác thành công hoàn toàn bằng script tự động (Exploitable).
> - **Thời gian trung bình** để tái hiện một lỗi là **45 phút**.
> - Đây là bộ dữ liệu chuẩn (Ground Truth) được dùng để huấn luyện AI Pentest."*

### LƯU Ý CUỐI CÙNG (DO'S & DON'TS)

- **DO:** Lưu giữ mọi log khi chạy docker/exploit (thành công hay thất bại đều là số liệu quý giá).
- **DO:** Ưu tiên chất lượng hơn số lượng ở giai đoạn Verify. 50 cái chạy được giá trị hơn 500 cái dở dang.
- **DON'T:** Đừng xóa các dòng "chỉ có tên". Hãy giữ nó và đánh dấu là `LEVEL_0`. Nó là bằng chứng bạn đã "quét sạch" thị trường.
- **DON'T:** Đừng cố sửa code exploit của người khác quá 30 phút. Nếu code sai -> Đánh dấu là sai. Đó là thực trạng bảo mật (không phải cái nào trên mạng cũng chạy được), và đó là một kết luận khoa học.

# Implementation