# 📐 Hướng dẫn Tính Metric — Đánh giá WebState-MCP-RAG

Tài liệu này mô tả chi tiết cách đo từng metric trong bài báo **WebState-MCP-RAG Pentest**,
sử dụng bộ benchmark CVE đã được xác minh từ pipeline `cve_data_collecting_tool`.

---

## Thiết lập thực nghiệm

```
Benchmark Dataset (từ CVE pipeline):
  ├── N CVE đã VERIFIED_SUCCESS (có docker-compose.yml + exploit.py)
  ├── Mỗi CVE được gán: difficulty (easy/medium/hard), ground-truth steps, success_condition
  └── Chia làm 2 tập: RAG Knowledge (2020-2025) | Test Set (2026)

WebState-MCP-RAG System:
  └── Chạy pentest tự động trên từng CVE trong Test Set
      → Ghi log đầy đủ: token count, request count, timestamp, step completion
```

---

## NHÓM A — End-to-End Success

---

### (1) Pentest Success Rate (PSR)

**Ý nghĩa:** Tỷ lệ CVE mà WebState-MCP-RAG khai thác thành công hoàn toàn.

**Công thức:**
$$PSR = \frac{N_{success}}{N_{total}} \times 100\%$$

**Cách đo:**
- `N_total` = tổng số CVE trong Test Set mà hệ thống được yêu cầu pentest
- `N_success` = số CVE mà hệ thống **kích hoạt được exploit thành công**, xác nhận bằng `success_condition` đã định nghĩa trong benchmark

**Định nghĩa "success" (cần thống nhất trước thực nghiệm):**
| Loại CVE | Điều kiện thành công |
|---|---|
| RCE | Output chứa kết quả lệnh hệ thống |
| SQLi | Dữ liệu nhạy cảm bị leak |
| SSRF | Nhận được response từ internal service |
| File Upload | File độc hại được execute |
| XSS | Payload phản chiếu/lưu trữ được trigger |

**Ví dụ tính:**
```
Test Set: 200 CVE
WebState-MCP-RAG khai thác thành công: 142 CVE
PSR = 142 / 200 × 100% = 71%
```

**So sánh với baseline:**
| Hệ thống | PSR |
|---|---|
| WebState-MCP-RAG (đề xuất) | ? |
| Baseline-A (paper gốc) | ? |
| Baseline-B (random agent) | ? |

---

## NHÓM B — Step / Stage Success

---

### (2) Stage Completion Rate (SCR)

**Ý nghĩa:** Tỷ lệ CVE mà hệ thống hoàn thành từng giai đoạn cụ thể.

**Công thức:**
$$SCR_k = \frac{N_k^{completed}}{N_k^{eligible}} \times 100\%$$

**Các stage cần đo:**

| Stage (k) | Định nghĩa "completed" | `N_k^{eligible}` |
|---|---|---|
| **Recon** | Hệ thống xác định được endpoint/parameter liên quan | Tất cả CVE |
| **VulnAnalysis** | Hệ thống xác định đúng vector tấn công (CWE class) | CVE qua Recon |
| **Validation** | Payload được chuẩn bị đúng (đúng syntax, đúng target) | CVE qua VulnAnalysis |
| **Exploit** | Payload được gửi và kích hoạt thành công | CVE qua Validation |

**Cách đo:** Mỗi stage, log của WebState-MCP-RAG cần ghi rõ `STAGE_COMPLETE` hoặc `STAGE_FAILED`.

**Ví dụ tính:**
```
SCR-Recon       = 185/200 = 92.5%
SCR-VulnAnalysis = 160/185 = 86.5%
SCR-Validation  = 148/160 = 92.5%
SCR-Exploit     = 142/148 = 95.9%
```

> 💡 **Insight:** Bottleneck ở stage nào thấp nhất → đó là điểm cần cải thiện kiến trúc.

---

### (3) Annotated Step Success Rate (ASSR)

**Ý nghĩa:** Tỷ lệ bước trung gian cụ thể mà hệ thống hoàn thành đúng, tính trên toàn bộ benchmark.

**Công thức:**
$$ASSR = \frac{\sum_{i=1}^{N} C_i}{\sum_{i=1}^{N} M_i} \times 100\%$$

**Chuẩn bị (quan trọng nhất):**
Mỗi CVE trong benchmark cần được annotate **ground-truth steps** (`M_i` bước):

```yaml
# Ví dụ: CVE-2022-22965 (Spring4Shell)
cve_id: CVE-2022-22965
difficulty: hard
total_steps: 5   # M_i = 5
steps:
  - id: 1
    description: "Phát hiện Spring MVC endpoint nhận classLoader parameter"
    success_signal: "endpoint /.*\\.do hoặc classLoader trong request param"
  - id: 2
    description: "Xác định phiên bản Spring Framework < 5.3.18"
    success_signal: "version leak từ error page hoặc header X-Powered-By"
  - id: 3
    description: "Xây dựng payload ghi file JSP vào webroot qua classLoader"
    success_signal: "HTTP 200 trả về từ file .jsp vừa tạo"
  - id: 4
    description: "Thực thi lệnh qua JSP webshell"
    success_signal: "output lệnh xuất hiện trong response"
  - id: 5
    description: "Verify RCE với lệnh id/whoami"
    success_signal: "EXPLOIT_SUCCESS"
success_condition: "step 5 completed"
```

**Cách đo:** Sau mỗi CVE, WebState-MCP-RAG so sánh request/response log với `success_signal` của từng step → đánh dấu step đó `completed` hay không. `C_i` = số step completed của CVE thứ i.

**Ví dụ tính:**
```
CVE-1: M=5, C=4  (miss step 2)
CVE-2: M=3, C=3  (full success)
CVE-3: M=7, C=2  (fail sớm)
...
ASSR = (4+3+2+...) / (5+3+7+...) × 100%
```

> 📌 **Nguồn ground-truth steps:** Lấy từ `exploit.py` đã verify thành công trong CVE pipeline.
> Mỗi bước trong exploit.py tương ứng một annotated step.

---

### (4) Critical-Step Success Rate (CSSR)

**Ý nghĩa:** Giống ASSR nhưng có trọng số — bước quan trọng hơn thì ảnh hưởng nhiều hơn đến điểm.

**Công thức:**
$$CSSR = \frac{\sum_i \sum_j w_{ij} \cdot \mathbf{1}(step_{ij}\ success)}{\sum_i \sum_j w_{ij}} \times 100\%$$

**Bảng trọng số đề xuất:**
| Loại bước | Trọng số ($w$) |
|---|---|
| Phát hiện endpoint cơ bản | 1.0 |
| Xác định version/tech stack | 1.0 |
| Giữ session state / CSRF token | 1.2 |
| Xác định đúng sink/parameter | 1.5 |
| Craft payload đúng syntax | 1.5 |
| Trigger vulnerability (impact) | 2.0 |
| Verify exploitation thành công | 2.0 |

**Ý nghĩa thực tế:** CSSR > ASSR chứng tỏ hệ thống giỏi hoàn thành bước quan trọng nhưng có thể bỏ lỡ bước phụ.

---

## NHÓM C — LLM Efficiency

---

### (5) LLM Request Count (LRC)

**Ý nghĩa:** Tổng số lần WebState-MCP-RAG gọi LLM để pentest toàn bộ Test Set.

$$LRC = \sum_{i=1}^{N} r_i$$

**Cách đo:** Mỗi lần gọi API LLM trong hệ thống, tăng counter `r_i` cho CVE đang xử lý.

**Báo cáo thêm:**
- Mean LRC / CVE
- Median LRC / CVE  
- LRC theo difficulty (easy < medium < hard → kỳ vọng)
- LRC theo stage

---

### (6) Prompt Token Consumption (PTC)

$$PTC = \sum_{i=1}^{N} \sum_{j=1}^{r_i} input\_tokens_{ij}$$

**Cách đo:** Mỗi LLM call, lấy `response.usage_metadata.prompt_token_count` (Vertex AI / OpenAI usage).

---

### (7) Completion Token Consumption (CTC)

$$CTC = \sum_{i=1}^{N} \sum_{j=1}^{r_i} output\_tokens_{ij}$$

**Cách đo:** `response.usage_metadata.candidates_token_count`

---

### (8) Total Token Consumption (TTC)

$$TTC = PTC + CTC$$

---

### (9) Tokens per Successful Pentest (TSP) ⭐ Metric quan trọng nhất

**Ý nghĩa:** Trung bình cần bao nhiêu token để pentest thành công 1 CVE.

$$TSP = \frac{TTC}{N_{success}}$$

**Tại sao quan trọng:** Hai hệ thống có PSR bằng nhau, nhưng hệ thống nào có TSP thấp hơn thì **thực dụng và tiết kiệm hơn**. Đây là argument mạnh nhất trong paper.

**Ví dụ:**
```
Baseline:        TTC = 50M token, N_success = 100 → TSP = 500,000 token/pentest
WebState-MCP-RAG: TTC = 30M token, N_success = 142 → TSP = 211,268 token/pentest
→ Hiệu quả hơn 2.4x
```

---

### (10) Tokens per Successful Step (TSS)

$$TSS = \frac{TTC}{\sum_i C_i}$$

**Ý nghĩa:** Mỗi bước pentest thành công tốn bao nhiêu token? Dùng để đánh giá hiệu quả suy luận của từng action.

---

### (11) LLM Requests per Successful Pentest (RSP)

$$RSP = \frac{LRC}{N_{success}}$$

---

### (12) LLM Requests per Successful Step (RSS)

$$RSS = \frac{LRC}{\sum_i C_i}$$

---

## NHÓM D — Operational Efficiency

---

### (13) Wall-Clock Time (WCT)

$$WCT_i = t_{end,i} - t_{start,i}$$

**Báo cáo:** Mean / Median WCT / CVE, phân tách theo difficulty.

---

### (14) Time to First Valid Exploit (TFE)

$$TFE_i = t_{first\_exploit\_success,i} - t_{start,i}$$

**Cách đo:** Ghi timestamp khi hệ thống lần đầu nhận được `success_condition = True`.

---

### (15) Requests to Exploit (RTE)

$$RTE = \text{số HTTP requests + tool calls cho đến khi exploit thành công}$$

**Cách đo:** Đếm qua HTTP proxy / tool wrapper của MCP Hub.

---

### (16) Budget Utilization Rate (BUR)

$$BUR = \frac{tokens\_used}{token\_budget}$$

**Ý nghĩa:** Hệ thống có cần gần hết budget mới thành công không? BUR thấp → hiệu quả hơn.

---

## Bộ metric tối thiểu cần báo cáo trong paper

Theo `paper.txt`, bộ metric **bắt buộc** gồm:

| # | Metric | Nhóm | Trả lời câu hỏi |
|---|---|---|---|
| 1 | **PSR** | A | Hệ thống có mạnh hơn không? |
| 2 | **SCR-Recon** | B | Mạnh hơn ở stage nào? |
| 3 | **SCR-VulnAnalysis** | B | Mạnh hơn ở stage nào? |
| 4 | **SCR-Exploit** | B | Mạnh hơn ở stage nào? |
| 5 | **ASSR** | B | Tỷ lệ hoàn thành bước chi tiết? |
| 6 | **LRC** | C | Có tốn nhiều LLM call không? |
| 7 | **TTC** | C | Tổng token tiêu hao? |
| 8 | **TSP** | C | Tốn bao nhiêu trên 1 pentest thành công? |

---

## Thiết kế thực nghiệm

### Phân loại benchmark CVE

| Difficulty | Loại lỗ hổng | Số CVE đề xuất |
|---|---|---|
| **Easy** | Reflected XSS, Basic SQLi, Path Traversal | ~60 |
| **Medium** | Authenticated SQLi, IDOR, SSRF, SSTI | ~80 |
| **Hard** | Blind SQLi, Multi-step auth bypass, Deserialization | ~60 |
| **Tổng** | | **~200** |

### Nguồn ground-truth

Mỗi CVE benchmark lấy ground-truth steps từ:
1. `exploit.py` đã VERIFIED_SUCCESS → phân tách thành các bước
2. `docker-compose.yml` → mô tả môi trường (để hệ thống không biết trước)
3. NVD description + CWE → metadata cho RAG Layer

### Checklist trước khi chạy thực nghiệm

- [ ] Định nghĩa `success_condition` cho từng CVE
- [ ] Annotate `M_i` ground-truth steps cho từng CVE
- [ ] Gán `difficulty` label
- [ ] Gán `w_ij` trọng số cho CSSR
- [ ] Implement token/request logger trong WebState-MCP-RAG
- [ ] Implement timestamp logger
- [ ] Thiết lập token budget cho BUR
- [ ] Chạy thử 10 CVE để kiểm tra pipeline đo lường
