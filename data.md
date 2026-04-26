  # BÁO CÁO KIẾN TRÚC THU THẬP VÀ PHÂN TÍCH DỮ LIỆU CVE (2020 - 2026)

## 1. Mục tiêu thu thập
Thu thập và phân tích các lỗ hổng bảo mật (CVE) tập trung hoàn toàn vào lớp **Ứng dụng Web (Web Applications và các Framework/Thư viện Backend/Frontend cấu thành)** trong giai đoạn từ năm 2020 đến nay. 

*Lưu ý: Mặc dù ứng dụng Web bao gồm cả tầng hạ tầng (OS, Web Server như Nginx, DB), hệ thống này dự kiến khoanh vùng rủi ro trực tiếp vào tầng mã nguồn và các thư viện liên đới để tối ưu hóa cho mục tiêu kiểm thử xâm nhập Web.*

## 2. Nguồn lấy dữ liệu và Kiến trúc tích hợp

Hệ thống đề xuất mô hình **Thu thập Kép (Dual-Source Collection Architecture)**, kết hợp ưu điểm của hai nền tảng cơ sở dữ liệu lớn nhất để tối ưu hóa tính chính xác và độ phủ của dữ liệu:

### 2.1. Nguồn Khai thác Lõi (Primary Source): GitHub Advisory Database
Hệ thống sử dụng GitHub GraphQL API làm nguồn khởi thủy (Bootstrapping) để xác định danh sách các lỗ hổng mục tiêu.
*   **Chức năng:** Truy xuất danh sách mã định danh `CVE-ID` ban đầu dựa trên hệ sinh thái thư viện (Ecosystem), điểm CVSS, năm công bố và thẻ điểm yếu (CWE).
*   **Lý do lựa chọn ưu tiên:**
    1.  **Tính phân mảnh Hệ sinh thái (Ecosystem-driven):** GitHub phân cấp rõ ràng dữ liệu theo các Hub ngôn ngữ và Framework (như `npm`, `pip`, `maven`). Điều này cho phép hệ thống lọc chính xác các lỗ hổng thuộc về lớp **Ứng dụng Web** ngay từ đầu vào, loại bỏ hoàn toàn độ nhiễu (noise) từ các lỗ hổng hạ tầng vật lý, hệ điều hành desktop hay thiết bị mạng (ví dụ: lỗi router Cisco) thường thấy trên NVD.
    2.  **Độ tin cậy từ DevSecOps:** Các báo cáo trên GitHub thường liên kết trực tiếp với commit vá lỗi (patch), giúp xác minh nhanh chóng tính chính xác của các thẻ phân loại như CWE.

### 2.2. Nguồn Tri Thức và Kiểm Chứng Tự Động (Knowledge & Automated Verification): NVD và Vertex AI
Khác với quy trình cào dữ liệu tự động từ GitHub, NVD được đóng vai trò là "Kho lưu trữ tham chiếu" (Reference Repository) kết hợp cùng Vertex AI (Gemini 2.5 Pro) để phục vụ cho **Quy trình Xác minh Tự động (Automated Verification Workflow)**.
*   **Chức năng:** Hệ thống tự động thiết lập cầu nối từ các `CVE-ID` sang NVD để lấy mô tả chi tiết. Dữ liệu này, cùng với mã nguồn PoC từ GitHub, được đẩy vào Vertex AI để tự động sinh ra môi trường Lab (Docker) và các bước khai thác chuẩn (Ground-truth steps).
*   **Giá trị mang lại:** Thay vì các nhà nghiên cứu phải đọc và dựng Lab thủ công, Agent AI sẽ đóng vai trò tái hiện lỗi (Level 2 - Exploit). Việc này tạo ra các bộ Benchmark có thể chạy được (runnable environments) với các bước rõ ràng (annotated steps) phục vụ trực tiếp cho việc tính toán các metric khắt khe (như ASSR, TSS) để đánh giá kiến trúc WebState-MCP-RAG.

### 2.3. Nguồn Đối Chiếu Mức Độ Khai Thác Đa Nguồn (Multi-source Exploit Intelligence)
Để đánh giá rủi ro thực tế ("Lỗ hổng nào thực sự đang bị tấn công hoặc đã có mã khai thác?"), hệ thống áp dụng cơ chế đối chiếu chéo (Cross-referencing) rẽ nhánh nhằm giải quyết bài toán mất cân bằng dữ liệu (Data Imbalance) của các hệ thống cũ:

1.  **Exploit-DB (Historical PoC):** Đối chiếu với cơ sở dữ liệu truyền thống cung cấp bởi Offensive Security để xác định các mã khai thác chuẩn mực đã được cộng đồng công nhận.
2.  **GitHub PoC Repositories (Modern Exploit Scraper):** Nhận thấy phần lớn các lỗi Web hiện đại (như RCE trên Spring Framework hay Deserialization) thường được giới nghiên cứu chia sẻ trực tiếp dưới dạng mã nguồn mở (PoC) trên GitHub mà không cập nhật lên Exploit-DB, hệ thống tích hợp thêm quét và trích xuất dữ liệu từ các dự án tổng hợp mã khai thác trên GitHub (Ví dụ: `nomi-sec/PoC-in-GitHub`). Việc sử dụng kiến trúc "Đa nguồn" (Multi-PoC) này giúp đưa tỷ lệ nhận diện lỗ hổng có mã khai thác lên mức tiệm cận thực tế nhất.
    *   **Cơ chế xác thực độ tin cậy của PoC độc lập:** Để lọc bỏ các mã khai thác giả mạo (Fake Exploit/Troll) hoặc độc hại trên GitHub, hệ thống áp dụng hai vòng kiểm duyệt:
        - **Bộ lọc Định lượng (Quantitative Filter):** Chỉ chấp nhận các repository PoC có số lượng tương tác cộng đồng tối thiểu (Ví dụ: `Stars >= 5` hoặc `Forks >= 2`) để loại bỏ các repo rác.
        - **Kiểm chứng Thực nghiệm Tự động (Automated Empirical Verification - Level 2 Workflow):** Hệ thống không tin tưởng mù quáng vào dòng code. Trạng thái khai thác cuối cùng (`VERIFIED_SUCCESS`) được cấp khi hệ thống AI Verifier (Agent_Verifier qua Vertex AI) tự động dựng thành công môi trường Sandbox cô lập bằng Docker, biên dịch PoC, và bắn payload thành công (EXPLOIT_SUCCESS) mà không cần con người can thiệp.

---

## 3. Trình tự Thu thập và Phân loại

Hệ thống hoạt động theo nguyên lý **"Thu thập có định hướng - Phân loại đa tầng" (Targeted Collection - Multi-layer Classification)** qua 5 bước:

1. **Giai đoạn 1 (Khoanh vùng Hệ sinh thái phần mềm Web):** Lựa chọn truy vấn dữ liệu từ 9 hệ sinh thái backend và frontend phổ biến nhất: `npm` (JS/TS), `maven` (Java/Spring Boot), `nuget` (.NET/C#), `pip` (Python/FastAPI), `composer` (PHP/Laravel), `go` (Microservices), `rubygems` (Ruby on Rails), `rust` (Rust Web API), và `erlang` (Erlang/Elixir).
2. **Giai đoạn 2 (Phân tách Dòng thời gian - Chống rò rỉ dữ liệu / Data Contamination):** Nhằm đáp ứng tiêu chuẩn khắt khe của hội đồng phản biện, dữ liệu thu thập được chia làm 2 vách ngăn độc lập:
    - **Tập Tri Thức RAG (2020 - 2025):** Các CVE cũ (đã nằm trong dữ liệu huấn luyện của LLM) sẽ được đưa vào *Evidence-Centric RAG Layer* để cung cấp kiến thức nền, mẫu payload và kịch bản (playbook).
    - **Tập Benchmark Đánh Giá (2026):** Các CVE hoàn toàn mới (sau khi LLM đã cutoff training) sẽ được dùng để test năng lực Suy luận Zero-day (Reasoning) thực sự của Agent.
3. **Giai đoạn 3 (Chuẩn hoá CWE và Phân loại ưu tiên):** Để giải quyết triệt để lỗi bất đồng nhất dữ liệu, hệ thống tách bạch rõ ràng `primary_cwe_id` (lưu mã gốc O(1), VD: CWE-79) và `owasp_category` (Tên danh mục chuẩn, VD: INJECTION_FLAWS). Hệ thống áp dụng kiến trúc **"Thu thập tất cả, Gán nhãn sau" (Collect-all-then-label)** dựa trên hai trục Phân loại:
    - **Thu thập Toàn diện:** Hệ thống lưu trữ 100% CVE thuộc các hệ sinh thái Web, không lọc bỏ bất kỳ lỗ hổng nào để đảm bảo không có điểm mù dữ liệu (Zero Data Loss).
    - **Ánh xạ Cấu trúc Phân cấp (Hierarchical CWE Tree Traversal):** Thay vì sử dụng danh sách tĩnh một chiều, hệ thống tích hợp sẵn một bộ từ điển hạt nhân chứa cơ sở dữ liệu nút gốc (Pillar/Class) của OWASP Top 25. Khi thư viện API NVD/GitHub trả về các mã lỗi CWE ngách (Ví dụ: `CWE-1336` - Cú pháp Mẫu, hay `CWE-564` - Hibernate SQLi), thuật toán độ đệ quy $O(1)$ sẽ quét ngược lên các thẻ cha (Parent-ID) trong cây phân cấp CWE. Từ đó, mọi biến thể phức tạp đều tự động được quy tụ về đúng danh mục Phân loại rủi ro gốc (Ví dụ: nhóm `INJECTION_FLAWS` hay `BROKEN_ACCESS_CONTROL`).

*(Mô hình tham chiếu Từ điển Nhóm Gốc - Cốt lõi của Thuật toán Đệ quy CWE)*
```json
{
  "BROKEN_ACCESS_CONTROL": [
    "CWE-22",   // Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
    "CWE-285",  // Improper Authorization
    "CWE-639",  // Authorization Bypass Through User-Controlled Key (IDOR/BOLA)
    "CWE-862",  // Missing Authorization
    "CWE-863"   // Incorrect Authorization
  ],
  "INJECTION_FLAWS": [
    "CWE-78",   // Improper Neutralization of Special Elements used in an OS Command
    "CWE-79",   // Improper Neutralization of Input During Web Page Generation (XSS)
    "CWE-89",   // Improper Neutralization of Special Elements used in an SQL Command
    "CWE-94",   // Improper Control of Generation of Code (Code Injection)
    "CWE-91",   // XML Injection (aka Blind XPath Injection)
    "CWE-564"   // SQL Injection: Hibernate
  ],
  "CRYPTOGRAPHIC_FAILURES": [
    "CWE-259",  // Use of Hard-coded Password
    "CWE-295",  // Improper Certificate Validation
    "CWE-327",  // Use of a Broken or Risky Cryptographic Algorithm
    "CWE-330"   // Use of Insufficiently Random Values
  ],
  "INSECURE_DESIGN_AND_ARCH": [
    "CWE-434",  // Unrestricted Upload of File with Dangerous Type
    "CWE-502",  // Deserialization of Untrusted Data
    "CWE-918"   // Server-Side Request Forgery (SSRF)
  ],
  "SECURITY_MISCONFIGURATION": [
    "CWE-16",   // Configuration
    "CWE-611",  // Improper Restriction of XML External Entity Reference (XXE)
    "CWE-1004"  // Sensitive Cookie Without 'HttpOnly' Flag
  ],
  "AUTHENTICATION_FAILURES": [
    "CWE-287",  // Improper Authentication
    "CWE-306",  // Missing Authentication for Critical Function
    "CWE-798"   // Use of Hard-coded Credentials
  ],
  "SOFTWARE_AND_DATA_INTEGRITY": [
    "CWE-494",  // Download of Code Without Integrity Check
    "CWE-829",  // Inclusion of Functionality from Untrusted Control Sphere
    "CWE-1104"  // Use of Unmaintained Third Party Components
  ]
}
```

- **Quy trình Con người (Human-in-the-loop Fallback):** Sau khi các bộ lọc Đệ quy Tree Traversal và AI Inference hoàn thành, những lỗ hổng có mô tả quá kỳ lạ sẽ được đưa vào danh sách chờ Duyệt tay. Các nhà nghiên cứu dùng giao diện đồ án để rà quét lại lần cuối. *Nếu lỗ hổng rơi trúng các kịch bản nhạy cảm này, công cụ sẽ gắn cờ theo dõi khẩn cấp (`is_priority_cwe = True`).*
4. **Giai đoạn 4 (Phân tích chỉ số Khai thác):** Quét qua CSDL của Exploit-DB và các kho lưu trữ PoC trên GitHub (Ví dụ: `nomi-sec/PoC-in-GitHub`) để phát giác CVE đã có công cụ tấn công công khai.
5. **Giai đoạn 5 (Lưu trữ Database):** Dữ liệu vượt qua khâu làm sạch sẽ được đẩy vào hạ tầng Database PostgreSQL để đáp ứng các lệnh Data Analytics.

---

## 4. Kết quả Thống kê Mẫu (Trước CISA KEV)

