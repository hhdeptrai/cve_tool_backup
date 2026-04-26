import os
import re
import time
import shutil
import subprocess
import vertexai
from vertexai.generative_models import GenerativeModel

# ==========================================
# CẤU HÌNH
# ==========================================
PROJECT_ID = "project-49966148-9e92-4a21-949" 
CVE_ID_TO_TEST = "CVE-2024-21626" # Sửa thành CVE bạn muốn test (ví dụ: RunC container breakout)
PACKAGE_NAME = "runc"
DESCRIPTION = "runc allows a malicious container to overwrite the host runc binary."
CVE_CWE = "CWE-416"

SYSTEM_PROMPT = f"""
Bạn là một chuyên gia bảo mật Web. Hãy đọc thông tin CVE sau và tạo ra một môi trường Lab bằng Docker để kiểm chứng.

[THÔNG TIN CVE]
- ID: {CVE_ID_TO_TEST}
- Package: {PACKAGE_NAME}
- CWE: {CVE_CWE}
- Mô tả: {DESCRIPTION}

[YÊU CẦU BẮT BUỘC]
Bạn PHẢI trả về mã nguồn của các file cần thiết (như docker-compose.yml, app.js, init.sql, exploit.py) bọc trong định dạng sau:
===FILE: tên_file.mở_rộng===
nội dung file
===END_FILE===

Trong đó exploit.py phải chứa dòng 'print("EXPLOIT_SUCCESS")' nếu khai thác thành công.
"""

def extract_files(text):
    files = {}
    pattern = re.compile(r'===FILE:\s*(.+?)\s*===\n(.*?)(?:===END_FILE===)', re.DOTALL)
    matches = pattern.findall(text)
    for filepath, content in matches:
        block = content.strip()
        if block.startswith("```"):
            block = block.split("\n", 1)[-1]
        if block.endswith("```"):
            block = block.rsplit("\n", 1)[0]
        files[filepath.strip()] = block.strip()
    return files

def run_test():
    print(f"[*] Đang khởi tạo Vertex AI (Gemini 2.5 Pro) cho {CVE_ID_TO_TEST}...")
    vertexai.init(project=PROJECT_ID, location="us-central1")
    model = GenerativeModel("gemini-2.5-pro")
    
    print("[*] Đang gửi yêu cầu sinh môi trường Docker tới AI... (Chờ khoảng 15-30s)")
    response = model.generate_content(SYSTEM_PROMPT)
    text_response = response.text
    
    files = extract_files(text_response)
    if not files:
        print("[-] Lỗi: AI không sinh ra file đúng định dạng ===FILE:...===")
        print("Kết quả gốc:\n", text_response)
        return
        
    print(f"[+] AI đã sinh ra {len(files)} files: {list(files.keys())}")
    
    # Setup tmp dir
    tmp_dir = os.path.join("tmp_test", CVE_ID_TO_TEST)
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir)
    
    for filepath, content in files.items():
        full_path = os.path.join(tmp_dir, filepath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding='utf-8') as f:
            f.write(content)
            
    print(f"[*] Đã lưu files vào folder '{tmp_dir}'")
    
    # Run Docker
    if 'docker-compose.yml' in files and 'exploit.py' in files:
        print("[*] Đang chạy Docker Compose Up...")
        subprocess.run(["docker", "compose", "up", "-d", "--build", "-V"], cwd=tmp_dir)
        
        print("[*] Chờ 5 giây cho services khởi động...")
        time.sleep(5)
        
        print("[*] Firing exploit.py...")
        exploit_res = subprocess.run(["python3", "exploit.py"], cwd=tmp_dir, capture_output=True, text=True)
        print("\n--- OUTPUT TỪ EXPLOIT ---")
        print(exploit_res.stdout)
        if exploit_res.stderr:
            print("[LỖI]:", exploit_res.stderr)
            
        print("\n[*] Dọn dẹp Docker...")
        subprocess.run(["docker", "compose", "down", "-v"], cwd=tmp_dir)
        
        if "EXPLOIT_SUCCESS" in exploit_res.stdout:
            print("\n✅ KẾT LUẬN: KHAI THÁC THÀNH CÔNG (VERIFIED!)")
        else:
            print("\n❌ KẾT LUẬN: KHAI THÁC THẤT BẠI")
    else:
        print("[-] Lỗi: AI không sinh đủ docker-compose.yml hoặc exploit.py")

if __name__ == "__main__":
    run_test()
