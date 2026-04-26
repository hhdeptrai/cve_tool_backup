"""
AI Reporter Module using Gemini 2.5 Pro and Flash to automate CVE analysis reports.
Features:
- API Key Rotation for handling Rate Limits
- Fallback Model Selection
- Row-Level Locking via PostgreSQL (`FOR UPDATE SKIP LOCKED`) for Distributed Parallel Execution
"""

import os
import time
import logging
from typing import Optional

import psycopg2
from psycopg2.extensions import connection as Connection
from google import genai
from google.genai import types

from .database import DatabaseManager, CVERepository
from .config import Config

logger = logging.getLogger(__name__)


class APIKeyRotator:
    """Manages cycle-rotation of Gemini API Keys to bypass individual quotas."""
    
    def __init__(self, key_string: str, proxy_string: str = ""):
        if not key_string:
            raise ValueError("No Gemini API keys provided in GEMINI_API_KEYS environment variable.")
            
        self.keys = [k.strip() for k in key_string.split(',') if k.strip()]
        self.proxies = [p.strip() for p in proxy_string.split(',') if p.strip()] if proxy_string else []
        if not self.keys:
            raise ValueError("No valid Gemini API keys parsed.")
            
        self.current_idx = 0
        logger.debug(f"APIKeyRotator initialized with {len(self.keys)} keys and {len(self.proxies)} proxies.")
        self.client = self._create_client()
        
    def _create_client(self):
        """Reconfigure the genai module with the currently selected key and proxy."""
        # Tự động map Key với Proxy tương ứng (Round-Robin nếu ít Proxy hơn Key)
        if self.proxies:
            proxy = self.proxies[self.current_idx % len(self.proxies)]
            os.environ['HTTPS_PROXY'] = proxy
            os.environ['HTTP_PROXY'] = proxy
            logger.debug(f"Assigned Proxy: {proxy}")
        else:
            os.environ.pop('HTTPS_PROXY', None)
            os.environ.pop('HTTP_PROXY', None)
            
        logger.debug(f"Switched to API Key ending in ...{self.keys[self.current_idx][-4:]}")
        return genai.Client(api_key=self.keys[self.current_idx])
        
    def rotate(self) -> bool:
        """
        Advance to the next API key. 
        Returns True if rotated successfully. 
        Returns False if all keys are exhausted and we just wrapped around.
        """
        self.current_idx += 1
        wrapped_around = False
        
        if self.current_idx >= len(self.keys):
            logger.warning("All API keys have been exhausted! Wrapping around to Key 0.")
            self.current_idx = 0
            wrapped_around = True
            
        self.client = self._create_client()
        return not wrapped_around


class CVEAnalystAgent:
    """Agent that wraps Gemini calls and constructs Prompts."""
    
    def __init__(self, rotator: APIKeyRotator, prompt_template_path: str):
        self.rotator = rotator
        
        # Primary is Pro (Best reasoning). Fallback is Flash (Fast/Cheap)
        self.primary_model_name = "gemini-2.0-pro-exp-02-05"
        self.fallback_model_name = "gemini-2.5-flash"
        
        with open(prompt_template_path, 'r', encoding='utf-8') as f:
            self.prompt_template = f.read()

    def generate_report(self, cve_id: str, package: str, cvss: float, cwe: str, description: str, poc_code: str = "") -> Optional[str]:
        """
        Attempt to generate a report using the primary model.
        Handles rate limits by rotating keys, and falls back to flash if necessary.
        """
        if poc_code:
            poc_section = f"```\n{poc_code[:20000]}\n```" # Truncate to prevent token explosion
        else:
            poc_section = "N/A"
            
        cvss_str = str(cvss) if cvss is not None else "Unknown"
        package_str = package if package else "Unknown"
        cwe_str = cwe if cwe else "Unknown"
        today_date = time.strftime("%Y-%m-%d")
            
        prompt = self.prompt_template.format(
            cve_id=cve_id,
            package=package_str,
            cvss=cvss_str,
            cwe=cwe_str,
            description=description,
            poc_code=poc_section,
            date=today_date
        )

        max_retries = len(self.rotator.keys) * 2
        retry_count = 0
        
        models_to_try = [self.primary_model_name, self.fallback_model_name]
        
        for model_name in models_to_try:
            
            while retry_count < max_retries:
                try:
                    logger.info(f"[{cve_id}] Generating report using {model_name}...")
                    response = self.rotator.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                    )
                    return self._clean_markdown(response.text)
                    
                except Exception as e:
                    error_str = str(e).lower()
                    if "429" in error_str or "quota" in error_str or "resource" in error_str:
                        logger.warning(f"[{cve_id}] Rate limit hit on Model: {model_name}.")
                        if not self.rotator.rotate():
                            logger.error(f"[{cve_id}] All keys exhausted. Sleeping for 60s...")
                            time.sleep(60)
                        retry_count += 1
                    else:
                        logger.error(f"[{cve_id}] Unexpected error from Gemini: {e}")
                        break # Try fallback model
            
            logger.warning(f"[{cve_id}] Model {model_name} failed after retries. Trying fallback...")
            
        logger.error(f"[{cve_id}] Failed to generate report using all models.")
        return None

    def _clean_markdown(self, text: str) -> str:
        """Remove markdown codeblocks wrapping the whole response if present."""
        text = text.strip()
        if text.startswith("```markdown"):
            text = text[11:]
        elif text.startswith("```"):
            text = text[3:]
            
        if text.endswith("```"):
            text = text[:-3]
            
        return text.strip()


class AIReporter:
    """Orchestrates DB locking, PoC fetching, and AI generation."""
    
    def __init__(self, db_manager: DatabaseManager, repo: CVERepository, agent: CVEAnalystAgent, output_dir: str):
        self.db_manager = db_manager
        self.repo = repo
        self.agent = agent
        self.output_dir = output_dir
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def _fetch_poc_code(self, cve_id: str) -> str:
        """Attempt to locate a python/sh poc file for this cve in the tmp directory tree."""
        # Look in ./tmp/<cve_id> for exploit scripts.
        poc_dir = os.path.join("tmp", cve_id)
        if not os.path.exists(poc_dir):
            return ""
            
        best_poc_code = ""
        for root, dirs, files in os.walk(poc_dir):
            for file in files:
                if file.endswith((".py", ".sh", ".rb", ".js", ".php")) and ("exploit" in file.lower() or "poc" in file.lower() or "server" in file.lower()):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            best_poc_code += f"--- {file} ---\n{f.read()}\n\n"
                    except:
                        pass
        return best_poc_code

    def run_worker_loop(self):
        """Continuous worker loop using FOR UPDATE SKIP LOCKED."""
        logger.info("Starting AI Reporter Parallel Worker...")
        
        while True:
            conn = None
            try:
                # Need a fresh connection explicitly managing transactions
                conn = self.db_manager.get_connection()
                conn.autocommit = False
                cursor = conn.cursor()
                
                # 1. Claim a CVE exclusively
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
                logger.info(f"==> Claimed {cve_id}. Generating AI Report...")
                
                # 2. Fetch context
                poc_code = self._fetch_poc_code(cve_id)
                
                # 3. Request AI
                report_md = self.agent.generate_report(cve_id, package, cvss, cwe, description, poc_code)
                
                if report_md:
                    # 4. Save to disk
                    filepath = os.path.join(self.output_dir, f"{cve_id}.md")
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(report_md)
                        
                    # 5. Commit state change to Database
                    cursor.execute("""
                        UPDATE web_cve_census_master
                        SET research_depth = 'LEVEL_1', updated_at = CURRENT_TIMESTAMP
                        WHERE cve_id = %s;
                    """, (cve_id,))
                    
                    conn.commit()
                    logger.info(f"✅ [{cve_id}] Report saved to {filepath}. DB Commited.")
                else:
                    logger.error(f"❌ [{cve_id}] Failed to generate report. Rolling back claim.")
                    conn.rollback()
                    
            except Exception as e:
                logger.error(f"Worker Loop Error: {e}")
                if conn:
                    conn.rollback()
                time.sleep(10) # Backoff on DB error
            finally:
                if conn:
                    self.db_manager.return_connection(conn)
