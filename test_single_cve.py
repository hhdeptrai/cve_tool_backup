#!/usr/bin/env python3
"""
DEBUG SCRIPT: Test AgentVerifier on a single CVE without needing DB.

Usage:
    # Chạy local, không proxy (dùng khi proxy LAN chưa setup hoặc chết):
    python3 test_single_cve.py

    # Chạy với proxy (dùng khi chạy song song trên mạng LAN):
    python3 test_single_cve.py --proxy http://user:pass@host:port

    # Chỉ test prompt + Gemini API (không chạy Docker):
    python3 test_single_cve.py --step 3

    # Chạy toàn bộ kể cả Docker:
    python3 test_single_cve.py --step 4
"""
import os
import sys
import json
import re
import logging
import argparse
import time
import shutil
import subprocess
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Verbose logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("test_single_cve")


# ──────────────────────────────────────────────────
#  CVE mặc định để test
# ──────────────────────────────────────────────────
DEFAULT_CVE = {
    "cve_id":      "CVE-2021-41773",
    "package":     "httpd (Apache HTTP Server 2.4.49)",
    "cvss":        7.5,
    "cwe":         "CWE-22 (Path Traversal / Improper Limitation of a Pathname)",
    "description": (
        "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. "
        "An attacker could use a path traversal attack to map URLs to files outside the directories "
        "configured by Alias-like directives. If files outside of these directories are not protected "
        "by the usual default configuration 'require all denied', these requests can succeed. "
        "Additionally, this flaw could leak the source of interpreted files like CGI scripts. "
        "This issue is known to be exploited in the wild. CVSSv3: 7.5 (High)."
    ),
}

POC_REPO_PATH = os.getenv("GITHUB_POC_REPO_PATH", "./data/PoC-in-GitHub")


# ──────────────────────────────────────────────────
#  Step 1: Kiểm tra & Fill Prompt Template
# ──────────────────────────────────────────────────
def step1_prompt(cve_id, package, cvss, cwe, description, poc_section):
    print("\n" + "="*60)
    print("STEP 1: Kiểm tra Prompt Template")
    print("="*60)

    prompt_path = os.path.join("reports", "templates", "cve_report_prompt.txt")
    if not os.path.exists(prompt_path):
        print(f"❌ Không tìm thấy: {prompt_path}")
        return None

    with open(prompt_path, "r", encoding="utf-8") as f:
        tmpl = f.read()

    try:
        filled = tmpl.format(
            cve_id=cve_id,
            package=package,
            cvss=str(cvss),
            cwe=cwe,
            description=description,
            poc_code=poc_section,
            date=time.strftime("%Y-%m-%d"),
        )
        print(f"✅ Prompt OK ({len(filled)} ký tự)")
        print("\n--- PREVIEW (400 ký tự đầu) ---")
        print(filled[:400] + "\n...")
        return filled
    except KeyError as e:
        print(f"❌ KeyError: {e} — Prompt template có ký tự {{}} chưa escape hoặc thiếu placeholder")
        return None


# ──────────────────────────────────────────────────
#  Step 0 (helper): Đọc PoC intel từ local JSON
# ──────────────────────────────────────────────────
def load_poc_intel(cve_id: str) -> str:
    parts = cve_id.split("-")
    if len(parts) < 2:
        return "N/A"
    year = parts[1]
    json_path = Path(POC_REPO_PATH) / year / f"{cve_id}.json"

    if not json_path.exists():
        print(f"   ℹ️  Không có PoC JSON tại {json_path}")
        return "N/A"

    with open(json_path, "r", encoding="utf-8") as f:
        repos = json.load(f)

    if not repos:
        return "N/A"

    repos_sorted = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
    top = repos_sorted[:5]

    lines = [f"Found {len(repos)} public PoC repositories for {cve_id}. Top references:"]
    for i, repo in enumerate(top, 1):
        name = repo.get("full_name", repo.get("name", "?"))
        desc = repo.get("description") or "(no description)"
        stars = repo.get("stargazers_count", 0)
        url = repo.get("html_url", "")
        lines.append(f"  {i}. [{name}]({url}) — ⭐{stars} — {desc}")

    print(f"   ✅ Đọc được {len(repos)} PoC repos từ local JSON, inject top {len(top)} vào prompt")
    return "\n".join(lines)


# ──────────────────────────────────────────────────
#  Step 2: Gửi Prompt lên Gemini
# ──────────────────────────────────────────────────
def step2_gemini(filled_prompt: str, proxy_override: str = None):
    print("\n" + "="*60)
    print("STEP 2: Gửi Prompt lên Gemini")
    print("="*60)

    api_keys = os.getenv("GEMINI_API_KEYS", "").strip()
    if not api_keys:
        print("❌ GEMINI_API_KEYS chưa được set trong .env")
        return None

    # Proxy logic: --proxy arg overrides .env; empty string = no proxy
    if proxy_override is not None:
        proxy = proxy_override  # Could be "" to disable proxy
    else:
        proxy = os.getenv("GEMINI_PROXIES", "").strip()

    if proxy:
        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy
        print(f"   → Sử dụng proxy: {proxy}")
    else:
        os.environ.pop("HTTP_PROXY", None)
        os.environ.pop("HTTPS_PROXY", None)
        os.environ.pop("http_proxy", None)
        os.environ.pop("https_proxy", None)
        print("   → Kết nối trực tiếp (không proxy)")

    from src.ai_reporter import APIKeyRotator

    try:
        rotator = APIKeyRotator(api_keys, proxy)
        print(f"   ✅ {len(rotator.keys)} API keys, {len(rotator.proxies)} proxies")
    except Exception as e:
        print(f"❌ Lỗi khởi tạo Rotator: {e}")
        return None

    # Retry loop với key rotation
    max_attempts = len(rotator.keys) * 2
    for attempt in range(1, max_attempts + 1):
        try:
            print(f"   → Attempt {attempt}/{max_attempts} (key ...{rotator.keys[rotator.current_idx][-4:]})")
            chat = rotator.client.chats.create(model="gemini-2.5-pro")
            response = chat.send_message(filled_prompt)
            text = response.text
            print(f"   ✅ Response nhận được ({len(text)} ký tự)")
            print("\n--- RESPONSE THÔ (1200 ký tự đầu) ---")
            print(text[:1200])
            print("...")
            return text, chat
        except Exception as e:
            err = str(e)
            if "429" in err or "quota" in err or "RESOURCE_EXHAUSTED" in err.upper():
                print(f"   ⚠️  Rate limit — rotating key...")
                rotator.rotate()
                time.sleep(3)
            elif "503" in err or "UNAVAILABLE" in err.upper():
                print(f"   ⚠️  Gemini 503 high demand — chờ 10s rồi thử lại...")
                time.sleep(10)
            else:
                print(f"   ❌ Lỗi không xử lý được: {err}")
                return None

    print("❌ Hết key / hết lần thử")
    return None


# ──────────────────────────────────────────────────
#  Step 3: Parse files từ response
# ──────────────────────────────────────────────────
def step3_parse(response_text: str):
    print("\n" + "="*60)
    print("STEP 3: Parse Files từ Response")
    print("="*60)

    pattern = re.compile(r'===FILE:\s*(.+?)\s*===\n(.*?)(?:===END_FILE===)', re.DOTALL)
    matches = pattern.findall(response_text)

    if not matches:
        print("❌ Không tìm thấy block ===FILE:===END_FILE=== trong response!")
        print(f"   '===FILE' present: {'===FILE' in response_text}")
        print(f"   '===END_FILE' present: {'===END_FILE' in response_text}")
        print("\n   💡 Gemini không tuân output format — thêm feedback và thử lại:")
        return None

    files = {}
    for filepath, content in matches:
        filepath = filepath.strip()
        block = content.strip()
        if block.startswith("```"):
            block = block.split("\n", 1)[-1]
        if block.endswith("```"):
            block = block.rsplit("\n", 1)[0]
        files[filepath] = block.strip()
        print(f"   ✅ {filepath} ({len(block)} bytes)")

    required = ["docker-compose.yml", "exploit.py"]
    missing = [f for f in required if f not in files]
    if missing:
        print(f"\n   ⚠️  Thiếu files bắt buộc: {missing}")
        print("   → Gemini sinh file nhưng thiếu. Cần thêm vòng lặp retry với feedback.")
        return files  # Return partial so user can inspect

    print(f"\n   ✅ Đủ files bắt buộc. Files: {list(files.keys())}")
    return files


# ──────────────────────────────────────────────────
#  Step 4: Chạy Docker
# ──────────────────────────────────────────────────
def step4_docker(cve_id: str, files: dict):
    print("\n" + "="*60)
    print("STEP 4: Docker Compose + Exploit")
    print("="*60)

    tmp_dir = os.path.join("tmp", cve_id + "_test")
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir)

    for filepath, content in files.items():
        full_path = os.path.join(tmp_dir, filepath)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"   Ghi: {full_path}")

    print("\n--- docker-compose.yml ---")
    print(files.get("docker-compose.yml", "(không có)")[:600])
    print("\n--- exploit.py (50 dòng đầu) ---")
    print("\n".join(files.get("exploit.py", "(không có)").splitlines()[:50]))

    answer = input("\n⚡ Chạy Docker Compose thật? [y/N] ").strip().lower()
    if answer != "y":
        print(f"   ℹ️  Dry-run OK — files lưu tại: {tmp_dir}")
        print(f"   Để chạy thủ công: cd {tmp_dir} && docker-compose up --build -d")
        return

    print("\n[*] docker-compose up -d --build -V ...")
    res = subprocess.run(
        ["docker-compose", "up", "-d", "--build", "-V"],
        cwd=tmp_dir, capture_output=True, text=True, timeout=600
    )
    if res.returncode != 0:
        print(f"❌ Docker fail:\n{res.stderr[-2000:]}")
        return

    print("✅ Docker UP. Chờ 8s...")
    time.sleep(8)

    print("[*] Chạy exploit.py ...")
    exp = subprocess.run(
        ["python3", "exploit.py"],
        cwd=tmp_dir, capture_output=True, text=True, timeout=120
    )
    output = exp.stdout + "\n" + exp.stderr
    print(f"\n--- EXPLOIT OUTPUT ---\n{output}")

    if "EXPLOIT_SUCCESS" in output:
        print("🎉 EXPLOIT_SUCCESS!")
    else:
        print(f"❌ Exploit thất bại (exit code: {exp.returncode})")

    subprocess.run(["docker-compose", "down", "-v", "--remove-orphans"],
                   cwd=tmp_dir, capture_output=True)


# ──────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Test AgentVerifier trên 1 CVE đơn lẻ")
    parser.add_argument("--cve", default=DEFAULT_CVE["cve_id"])
    parser.add_argument("--step", type=int, default=4,
                        help="Chạy đến step nào: 1=prompt, 2=gemini, 3=parse, 4=docker (default: 4)")
    parser.add_argument("--proxy", default=None,
                        help="Override proxy URL. Dùng '' để tắt proxy, bỏ qua để đọc từ .env")
    args = parser.parse_args()

    cve_id = args.cve
    cve_data = DEFAULT_CVE if cve_id == DEFAULT_CVE["cve_id"] else {
        "cve_id": cve_id, "package": "Unknown", "cvss": 0.0,
        "cwe": "Unknown", "description": f"CVE data for {cve_id}"
    }

    print(f"\n🔍 CVE: {cve_id}")

    # Load PoC intel từ local JSON
    print("\n[PoC Intel]")
    poc_section = load_poc_intel(cve_id)
    print(f"   poc_section preview: {poc_section[:200]}...")

    # Step 1
    filled = step1_prompt(
        cve_data["cve_id"], cve_data["package"], cve_data["cvss"],
        cve_data["cwe"], cve_data["description"], poc_section
    )
    if not filled or args.step < 2:
        sys.exit(0 if filled else 1)

    # Step 2
    result = step2_gemini(filled, proxy_override=args.proxy)
    if not result or args.step < 3:
        sys.exit(0 if result else 1)
    response_text, chat = result

    # Step 3
    files = step3_parse(response_text)
    if not files or args.step < 4:
        sys.exit(0)

    # Step 4
    step4_docker(cve_id, files)


if __name__ == "__main__":
    main()
