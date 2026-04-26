import time
with open("reports/templates/cve_report_prompt.md", "r") as f:
    prompt = f.read()
    
try:
    first_prompt = prompt.format(
        cve_id="CVE-123", package="pkg", cvss="9.8", cwe="CWE",
        description="desc", poc_code="poc", date="date"
    )
    print("Length of first_prompt:", len(first_prompt))
except Exception as e:
    print(f"Format error: {e}")
