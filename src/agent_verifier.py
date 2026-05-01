"""
Agentic Exploit Verifier (Self-Healing AI Loop)
Automatically builds Docker environments, runs exploits on HOST, and feeds errors back to AI.
"""

import os
import re
import json
import time
import logging
import subprocess
import shutil
from pathlib import Path

import vertexai
from vertexai.generative_models import GenerativeModel, ChatSession, GenerationConfig

from .ai_reporter import APIKeyRotator
from .database import DatabaseManager, CVERepository

logger = logging.getLogger(__name__)

# Data source paths
POC_REPO_PATH     = os.getenv("GITHUB_POC_REPO_PATH", "./data/PoC-in-GitHub")
VULHUB_PATH       = os.getenv("VULHUB_PATH",          "./data/vulhub")
EXPLOITDB_PATH    = os.getenv("EXPLOITDB_PATH",       "./data/exploitdb_full")
EXPLOITDB_CSV     = os.getenv("EXPLOITDB_CSV",        "./data/exploitdb/files_exploits.csv")
METASPLOIT_PATH   = os.getenv("METASPLOIT_PATH",      "./data/metasploit")

class AgentVerifier:
    def __init__(self, db_manager: DatabaseManager, rotator: APIKeyRotator, output_dir: str):
        self.db_manager = db_manager
        self.rotator = rotator # kept for compatibility
        self.output_dir = output_dir
        self.max_retries = 5 # Changed to 5 for Try-Hard Mode
        
        # Init vertex AI
        PROJECT_ID = os.getenv("VERTEX_PROJECT_ID", "")
        LOCATION   = os.getenv("VERTEX_LOCATION", "us-central1")
        if not PROJECT_ID:
            raise ValueError("VERTEX_PROJECT_ID is not set. Add it to your .env file.")
        vertexai.init(project=PROJECT_ID, location=LOCATION)
        
        # ✅ BƯỚC 1: Giới hạn output token để tiết kiệm chi phí
        # max_output_tokens=8192: Đủ cho docker-compose + exploit.py + report, không dư thừa
        # temperature=0.2: Ít sáng tạo hơn → ít ảo giác hơn, code chắc chắn hơn
        self.model = GenerativeModel(
            "gemini-2.5-pro",
            generation_config=GenerationConfig(
                max_output_tokens=8192,
                temperature=0.2,
            )
        )
        
        prompt_path = os.path.join("reports", "templates", "cve_report_prompt.md")
        with open(prompt_path, 'r', encoding='utf-8') as f:
            self.system_prompt = f.read()

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    # =========================================================
    # MULTI-SOURCE PoC INTELLIGENCE GATHERING
    # Priority: Vulhub → Exploit-DB → Metasploit → GitHub PoC
    # =========================================================

    def _fetch_vulhub(self, cve_id: str) -> tuple[str | None, str | None]:
        """
        Source 1 (BEST): Search Vulhub for pre-built Docker environment.
        Returns (docker_compose_content, vulhub_dir_path) or (None, None).
        """
        vulhub_base = Path(VULHUB_PATH)
        if not vulhub_base.exists():
            return None, None

        # Vulhub structure: vulhub/<software>/<CVE-ID>/docker-compose.yml
        for compose_file in vulhub_base.rglob(f"{cve_id}/docker-compose.yml"):
            try:
                content = compose_file.read_text(encoding="utf-8")
                logger.info(f"[{cve_id}] ✅ [Source 1/Vulhub] Found pre-built environment at {compose_file.parent}")
                return content, str(compose_file.parent)
            except Exception:
                continue
        return None, None

    def _fetch_exploitdb(self, cve_id: str) -> str | None:
        """
        Source 2: Search Exploit-DB CSV for CVE match, then read actual exploit code.
        Returns exploit code as string or None.
        """
        csv_path = Path(EXPLOITDB_CSV)
        exploitdb_full = Path(EXPLOITDB_PATH)
        if not csv_path.exists() or not exploitdb_full.exists():
            return None

        try:
            import csv
            with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    codes = row.get("codes", "")
                    if cve_id in codes:
                        # Found a match — read the actual exploit file
                        exploit_rel_path = row.get("file", "").strip()
                        if not exploit_rel_path:
                            continue
                        # Try exploitdb_full root first, then strip leading 'exploits/'
                        for base in [exploitdb_full, exploitdb_full.parent]:
                            exploit_file = base / exploit_rel_path
                            if exploit_file.exists():
                                code = exploit_file.read_text(encoding="utf-8", errors="ignore")
                                logger.info(f"[{cve_id}] ✅ [Source 2/Exploit-DB] Found: {exploit_rel_path}")
                                return f"# Exploit-DB: {row.get('description', '')}\n" + code[:8000]
        except Exception as e:
            logger.warning(f"[{cve_id}] Exploit-DB lookup failed: {e}")
        return None

    def _fetch_metasploit(self, cve_id: str) -> str | None:
        """
        Source 3: Search Metasploit modules for CVE reference.
        Returns Ruby module content or None.
        """
        msf_base = Path(METASPLOIT_PATH) / "modules" / "exploits"
        if not msf_base.exists():
            return None

        try:
            # Use grep for fast search across all Ruby files
            result = subprocess.run(
                ["grep", "-rl", cve_id, str(msf_base)],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                first_match = result.stdout.strip().split("\n")[0]
                code = Path(first_match).read_text(encoding="utf-8", errors="ignore")
                logger.info(f"[{cve_id}] ✅ [Source 3/Metasploit] Found module: {first_match}")
                return f"# Metasploit Module (Ruby) — read to understand attack vector:\n" + code[:6000]
        except Exception as e:
            logger.warning(f"[{cve_id}] Metasploit lookup failed: {e}")
        return None

    def _fetch_github_poc_links(self, cve_id: str) -> str | None:
        """
        Source 4: Read nomi-sec PoC-in-GitHub JSON for repo links.
        Returns formatted string of top repo links or None.
        """
        parts = cve_id.split("-")
        if len(parts) < 2:
            return None
        year = parts[1]
        json_path = Path(POC_REPO_PATH) / year / f"{cve_id}.json"
        if not json_path.exists():
            return None
        try:
            repos = json.load(open(json_path, "r", encoding="utf-8"))
        except Exception:
            return None
        if not repos:
            return None

        repos_sorted = sorted(repos, key=lambda r: r.get("stargazers_count", 0), reverse=True)
        top = repos_sorted[:5]
        lines = [f"Found {len(repos)} public PoC repos for {cve_id}. Top references:"]
        for i, repo in enumerate(top, 1):
            name = repo.get("full_name", "unknown")
            stars = repo.get("stargazers_count", 0)
            url = repo.get("html_url", "")
            lines.append(f"  {i}. {name} ({url}) ⭐{stars}")
        logger.info(f"[{cve_id}] ✅ [Source 4/GitHub] {len(repos)} PoC repos found")
        return "\n".join(lines)

    def _gather_all_intel(self, cve_id: str) -> dict:
        """
        Master function: Search all 4 sources by priority.
        Returns a dict with intel from each available source.
        """
        intel = {"vulhub_compose": None, "vulhub_dir": None,
                 "exploitdb_code": None, "metasploit_code": None,
                 "github_links": None, "source_label": "Zero-shot"}

        intel["vulhub_compose"], intel["vulhub_dir"] = self._fetch_vulhub(cve_id)
        intel["exploitdb_code"] = self._fetch_exploitdb(cve_id)
        intel["metasploit_code"] = self._fetch_metasploit(cve_id)
        intel["github_links"] = self._fetch_github_poc_links(cve_id)

        # Determine highest-quality source for logging
        if intel["vulhub_compose"]:
            intel["source_label"] = "Vulhub"
        elif intel["exploitdb_code"]:
            intel["source_label"] = "Exploit-DB"
        elif intel["metasploit_code"]:
            intel["source_label"] = "Metasploit"
        elif intel["github_links"]:
            intel["source_label"] = "GitHub-PoC"

        logger.info(f"[{cve_id}] Intel source: {intel['source_label']}")
        self._last_intel_source = intel["source_label"]  # save for DB write later
        return intel

    def _build_poc_section(self, intel: dict) -> str:
        """
        Build the PoC context string to inject into the AI prompt.
        Combines all available intel from all sources.
        """
        parts = []

        if intel["vulhub_compose"]:
            parts.append(
                "## ✅ Pre-built Docker Environment (Vulhub)\n"
                "A ready-made vulnerable environment already exists. "
                "USE this docker-compose.yml AS-IS — do NOT create a new one from scratch:\n"
                f"```yaml\n{intel['vulhub_compose'][:3000]}\n```"
            )

        if intel["exploitdb_code"]:
            parts.append(
                f"## ✅ Exploit-DB Reference Code\n"
                f"```python\n{intel['exploitdb_code'][:4000]}\n```"
            )

        if intel["metasploit_code"]:
            parts.append(
                f"## ✅ Metasploit Module Reference\n"
                f"Study this Ruby module to understand the attack vector, "
                f"then implement the same logic in Python:\n"
                f"```ruby\n{intel['metasploit_code'][:3000]}\n```"
            )

        if intel["github_links"]:
            parts.append(
                f"## ℹ️ Public PoC Repositories\n{intel['github_links']}"
            )

        if not parts:
            return "No public PoC found. Reason from CVE description and CWE to build the exploit."

        return "\n\n".join(parts)

    def _extract_all_files(self, text: str) -> dict:
        """Parses ===FILE: filename.ext=== blocks into a dictionary of {filepath: content}"""
        files = {}
        # Regex to find all file blocks: ===FILE: filepath=== \n content \n ===END_FILE===
        pattern = re.compile(r'===FILE:\s*(.+?)\s*===\n(.*?)(?:===END_FILE===)', re.DOTALL)
        matches = pattern.findall(text)
        
        for filepath, content in matches:
            filepath = filepath.strip()
            block = content.strip()
            # Strip triple backticks if AI accidentally includes them
            if block.startswith("```"):
                block = block.split("\n", 1)[-1]
            if block.endswith("```"):
                block = block.rsplit("\n", 1)[0]
            files[filepath] = block.strip()
            
        return files

    def _setup_tmp_dir(self, cve_id: str, files: dict) -> str:
        tmp_dir = os.path.join("tmp", cve_id)
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)
        
        for filepath, content in files.items():
            # Support AI generating files in subdirectories (e.g. src/config.php)
            full_path = os.path.join(tmp_dir, filepath)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding='utf-8') as f:
                f.write(content)
            
        return tmp_dir

    def _run_docker_verification(self, cve_id: str, tmp_dir: str) -> tuple[bool, str]:
        """Runs docker-compose up, executes exploit.py locally, cleans up."""
        
        def _cleanup():
            """Luôn chạy dù thành công hay thất bại."""
            subprocess.run(
                ["docker", "compose", "down", "-v", "--remove-orphans", "--rmi", "local"],
                cwd=tmp_dir, capture_output=True, timeout=60
            )
            # Xóa dangling images (image rác từ build) để giải phóng disk
            subprocess.run(
                ["docker", "image", "prune", "-f"],
                capture_output=True, timeout=30
            )
        
        try:
            # 1. Compose Build & Up
            logger.info(f"[{cve_id}] Using Docker Compose Up...")
            build_res = subprocess.run(
                ["docker", "compose", "up", "-d", "--build", "-V"],
                cwd=tmp_dir, capture_output=True, text=True, timeout=600
            )
            if build_res.returncode != 0:
                log_res = subprocess.run(
                    ["docker", "compose", "logs"],
                    cwd=tmp_dir, capture_output=True, text=True
                )
                stderr = build_res.stderr
                if len(stderr) > 1500:
                    err_detail = stderr[:800] + "\n...(truncated)...\n" + stderr[-400:]
                else:
                    err_detail = stderr
                err_msg = f"DOCKER COMPOSE BUILD FAILED:\n{err_detail}\n\nCONTAINER LOGS:\n{log_res.stdout[-1000:]}"
                return False, err_msg

            # Wait for services to fully boot
            time.sleep(5)

            # 2. Exploit on Host
            logger.info(f"[{cve_id}] Firing exploit.py from Host...")
            exploit_res = subprocess.run(
                ["python3", "exploit.py"],
                cwd=tmp_dir, capture_output=True, text=True, timeout=120
            )

            output_log = exploit_res.stdout + "\\n" + exploit_res.stderr
            log_res = subprocess.run(["docker", "compose", "logs"], cwd=tmp_dir, capture_output=True, text=True)
            container_logs = log_res.stdout[-2000:]

            if exploit_res.returncode == 0 or "EXPLOIT_SUCCESS" in output_log:
                return True, "EXPLOIT SUCCESSFUL"
            else:
                return False, f"EXPLOIT FAILED (Exit Code {exploit_res.returncode}):\\n{output_log[-1000:]}\\n\\nCONTAINER LOGS:\\n{container_logs}"

        finally:
            # ✅ LUÔN LUÔN dọn dẹp, dù thành công, thất bại, hay exception/timeout
            logger.info(f"[{cve_id}] Cleaning up Compose...")
            _cleanup()


    def verify_and_report(self, cve_id: str, package: str, cvss: float, cwe: str, description: str, poc_code: str = "") -> tuple[bool, str, str, str]:
        """
        Returns: (is_verified, report_md, final_build_status, final_exploit_status)
        build_status:  NOT_ATTEMPTED | IN_PROGRESS | SUCCESS | FAILED
        exploit_status: NONE | POC_PUBLIC | EXPLOIT_DB | VERIFIED_SUCCESS | UNEXPLOITABLE
        """
        import random
        cvss_str = str(cvss) if cvss is not None else "Unknown"
        today_date = time.strftime("%Y-%m-%d")
        assigned_port = random.randint(10000, 60000)

        # Gather intel from ALL 4 sources by priority
        intel = self._gather_all_intel(cve_id)
        poc_section = self._build_poc_section(intel)

        # Determine initial exploit_status based on available intel
        if intel["vulhub_compose"] or intel["exploitdb_code"]:
            init_exploit_status = "EXPLOIT_DB" if intel["exploitdb_code"] else "POC_PUBLIC"
        elif intel["github_links"] or intel["metasploit_code"]:
            init_exploit_status = "POC_PUBLIC"
        else:
            init_exploit_status = "NONE"

        # Track failure stage
        build_status   = "NOT_ATTEMPTED"
        exploit_status = init_exploit_status

        # If Vulhub has the docker-compose, inject it as a pre-built asset
        # The prompt will tell AI to reuse it instead of building from scratch
        vulhub_hint = ""
        if intel["vulhub_compose"]:
            vulhub_hint = (
                "\n\n⚠️ IMPORTANT: A pre-built Vulhub docker-compose.yml is provided above. "
                "You MUST use it exactly as-is in your ===FILE: docker-compose.yml=== block. "
                "Only write exploit.py from scratch."
            )

        first_prompt = self.system_prompt.format(
            cve_id=cve_id, package=package, cvss=cvss_str, cwe=cwe,
            description=description, poc_code=poc_section + vulhub_hint,
            date=today_date, port=assigned_port
        )

        chat = self.model.start_chat()
        current_prompt = first_prompt
        
        response_text = ""
        text_response = ""
        files_dict = {}
        feedback_log = "No execution attempted."
        for iteration in range(1, self.max_retries + 1):
            logger.info(f"[{cve_id}] Agent Iteration {iteration}/{self.max_retries}...")
            
            try:
                response = chat.send_message(current_prompt)
            except Exception as e:
                logger.error(f"[{cve_id}] Vertex AI Error: {e}")
                time.sleep(10)
                continue
                
            if not response or not response.text:
                logger.error(f"[{cve_id}] Failed to get response.")
                return False, "Failed to get AI response."
                
            text_response = response.text
            response_text = text_response
            
            # Extract Files
            files_dict = self._extract_all_files(text_response)
            
            if 'docker-compose.yml' not in files_dict or 'exploit.py' not in files_dict:
                # ✅ BƯỚC 2: Retry prompt ngắn gọn - không gửi lại toàn bộ context
                current_prompt = (
                    "FORMAT ERROR: Missing required files.\n"
                    "MUST use: ===FILE: filename=== content ===END_FILE===\n"
                    "MUST include both docker-compose.yml AND exploit.py. Resend all files now."
                )
                continue
                
            tmp_dir = self._setup_tmp_dir(cve_id, files_dict)
            
            # Run
            build_status = "IN_PROGRESS"
            is_success, feedback_log = self._run_docker_verification(cve_id, tmp_dir)
            
            if is_success:
                build_status   = "SUCCESS"
                exploit_status = "VERIFIED_SUCCESS"
                logger.info(f"🚀 [{cve_id}] VERIFIED SUCCESSFUL on iteration {iteration}!")
                # Return the final approved markdown
                markdown = re.sub(r'===FILE:.*?===END_FILE===', '', text_response, flags=re.DOTALL)
                markdown = markdown.replace("✅ VERIFIED_SUCCESS", "✅ VERIFIED_SUCCESS")
                markdown += f"\n\n### Auto-Generated Multi-File Infrastructure\n"
                for fname, content in files_dict.items():
                    ext = fname.split('.')[-1] if '.' in fname else 'text'
                    markdown += f"\n**`{fname}`**\n```{ext}\n{content}\n```\n"
                return True, markdown, build_status, exploit_status
            else:
                logger.warning(f"[{cve_id}] Iteration {iteration} Failed! Error:")
                logger.warning(f"[{cve_id}] {feedback_log[:300]}...")
                # ✅ FIX: Gửi phần ĐẦU của error (nơi lỗi thực sự xảy ra)
                # Không gửi phần cuối vì đó chỉ là Docker daemon config vô nghĩa
                error_for_ai = feedback_log[:600] if len(feedback_log) > 600 else feedback_log
                current_prompt = (
                    f"FAILED. Fix this error:\n{error_for_ai}\n"
                    "Return ALL files using ===FILE: name=== content ===END_FILE=== format."
                )
                
        logger.error(f"❌ [{cve_id}] Failed to verify after {self.max_retries} attempts.")

        # Determine final statuses
        if "BUILD FAILED" in feedback_log or "COMPOSE" in feedback_log:
            build_status   = "FAILED"
            exploit_status = init_exploit_status  # exploit never ran
            fail_stage     = "BUILD"
            fail_reason    = "Docker environment failed to start after all retries."
        else:
            build_status   = "SUCCESS"   # build worked but exploit failed
            exploit_status = "UNEXPLOITABLE"
            fail_stage     = "EXPLOIT"
            fail_reason    = "Docker started successfully but exploit.py could not trigger the vulnerability."

        # Ask AI for failure analysis
        try:
            analysis_prompt = (
                f"All {self.max_retries} attempts failed at the {fail_stage} stage.\n"
                f"Last error:\n```\n{feedback_log[:800]}\n```\n"
                "Explain briefly in English: What caused this failure? "
                "Was it a network/package issue, wrong base image, wrong exploit logic, or something else?"
            )
            failure_analysis = self.model.generate_content(analysis_prompt).text
        except Exception:
            failure_analysis = "Could not generate failure analysis."

        # Build structured failure markdown
        markdown = re.sub(r'===FILE:.*?===END_FILE===', '', text_response, flags=re.DOTALL).strip()
        markdown = markdown.replace("✅ VERIFIED_SUCCESS", "❌ EXPLOIT_FAILED_AFTER_5_RETRIES")
        markdown += f"\n\n---\n\n### ❌ Verification Failed — Stage: `{fail_stage}`\n"
        markdown += f"**Reason:** {fail_reason}\n\n"
        markdown += f"**AI Failure Analysis:**\n{failure_analysis}\n\n"
        markdown += f"**Last Error Log:**\n```text\n{feedback_log[:1500]}\n```\n"
        if files_dict:
            markdown += f"\n\n### Last Generated Files\n"
            for fname, content in files_dict.items():
                ext = fname.split('.')[-1] if '.' in fname else 'text'
                markdown += f"\n**`{fname}`**\n```{ext}\n{content}\n```\n"

        return False, markdown, build_status, exploit_status


    def run_worker_loop(self):
        logger.info("Starting AGENTIC AI Verifier Worker...")
        repo = CVERepository(self.db_manager)
        
        while True:
            conn = None
            try:
                conn = self.db_manager.get_connection()
                conn.autocommit = False
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT cve_id, description, cvss_base_score, owasp_category, affected_package 
                    FROM web_cve_census_master 
                    WHERE is_priority_cwe = TRUE 
                      AND research_depth = 'LEVEL_0' 
                    FOR UPDATE SKIP LOCKED 
                    LIMIT 1;
                """)
                
                row = cursor.fetchone()
                
                if not row:
                    logger.info("No more LEVEL_0 priority CVEs available. Sleeping for 30s...")
                    conn.rollback()
                    self.db_manager.return_connection(conn)
                    time.sleep(30)
                    continue
                    
                cve_id, description, cvss, cwe, package = row
                
                # Claim it immediately so we can drop the DB connection during the long AI process
                cursor.execute("UPDATE web_cve_census_master SET research_depth = 'LEVEL_1' WHERE cve_id = %s", (cve_id,))
                conn.commit()
                self.db_manager.return_connection(conn)
                logger.info(f"==> Agent Claimed {cve_id} (Marked LEVEL_1 to release DB Lock). Initializing Hack Process...")
                
                # -------------------------------
                # Start Long AI and Docker Process
                # -------------------------------
                is_verified, report_md, build_status, exploit_status = self.verify_and_report(
                    cve_id, package, cvss, cwe, description, ""
                )
                
                filepath = os.path.join(self.output_dir, f"{cve_id}.md")
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(report_md)
                    
                # -------------------------------
                # Upload results back to DB
                # -------------------------------
                # Due to long running AI task, database idle connections in pool may be dropped by server. Reset pool first.
                self.db_manager.close_pool()
                self.db_manager.initialize_pool()
                
                if is_verified:
                    conn2 = self.db_manager.get_connection()
                    cursor2 = conn2.cursor()
                    cursor2.execute("""
                        UPDATE web_cve_census_master
                        SET research_depth  = 'LEVEL_2',
                            build_status    = %s,
                            exploit_status  = 'VERIFIED_SUCCESS',
                            intel_source    = %s,
                            updated_at      = CURRENT_TIMESTAMP
                        WHERE cve_id = %s;
                    """, (build_status, getattr(self, '_last_intel_source', 'Zero-shot'), cve_id))
                    conn2.commit()
                    self.db_manager.return_connection(conn2)
                    logger.info(f"[{cve_id}] ✅ Saved to {filepath} | DB: LEVEL_2 / VERIFIED_SUCCESS / src={getattr(self, '_last_intel_source', '?')}")
                else:
                    conn2 = self.db_manager.get_connection()
                    cursor2 = conn2.cursor()
                    cursor2.execute("""
                        UPDATE web_cve_census_master
                        SET research_depth  = 'LEVEL_0',
                            build_status    = %s,
                            exploit_status  = %s,
                            intel_source    = %s,
                            updated_at      = CURRENT_TIMESTAMP
                        WHERE cve_id = %s;
                    """, (build_status, exploit_status, getattr(self, '_last_intel_source', 'Zero-shot'), cve_id))
                    conn2.commit()
                    self.db_manager.return_connection(conn2)
                    logger.info(f"[{cve_id}] ❌ Failed | DB: LEVEL_0 / build={build_status} / exploit={exploit_status} / src={getattr(self, '_last_intel_source', '?')}")

                # Small pause between CVEs to avoid hitting API rate limits
                time.sleep(3)
                    
            except Exception as e:
                logger.error(f"Agent Worker Error: {e}")
                if conn:
                    # In case it failed before commit
                    try:
                        conn.rollback()
                        self.db_manager.return_connection(conn)
                    except:
                        pass
                time.sleep(10)

