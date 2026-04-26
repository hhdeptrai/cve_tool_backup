# Verification Criteria Guide

This guide defines the specific criteria researchers must use when verifying CVEs. Consistency is critical for the integrity of the census data.

## 1. Build Status Criteria

The `build_status` field indicates whether a researcher could successfully set up a **running, vulnerable environment**.

### ✅ SUCCESS
**Criteria:**
*   The vulnerable application or library can be installed.
*   The application **starts successfully** and is reachable (e.g., HTTP 200 OK).
*   The specific vulnerable function or endpoint is accessible.

**Example Notes:**
> "Successfully built using Docker. App allows login at localhost:8080."
> "Library installed via pip. Verify script runs without import errors."

### ❌ FAILED
**Criteria:**
*   **Dependency Hell:** Required dependencies are no longer available (e.g., npm 404, deprecated Python libraries).
*   **Compilation Error:** Source code fails to compile and cannot be easily fixed.
*   **Runtime Crash:** Application starts but crashes immediately upon access.

**Example Notes:**
> "Build failed: 'node-sass' version 4.1.0 is incompatible with current Node environment."
> "Failed: Source code link is dead (404)."

### ⏳ IN_PROGRESS
**Criteria:**
*   You are currently working on the dockerfile or environment setup.

---

## 2. Exploit Status Criteria

The `exploit_status` field indicates the **proven** exploitability of the CVE in the built environment.

### 🏆 VERIFIED_SUCCESS (Gold Standard)
**Criteria:**
*   You have **personally executed** an exploit against your built environment.
*   You have **observed the impact** (e.g., popped a shell, read /etc/passwd, effectively DoS'd the app).
*   **Proof is required** in the notes.

**Example Notes:**
> "Successfully exploited. Payload `?id=1' OR '1'='1` returned all user records."
> "RCE confirmed. Generated reverse shell to localhost:4444."

### 🛡️ UNEXPLOITABLE
**Criteria:**
*   You have built the environment successfully.
*   You have attempted the known exploits/PoCs.
*   The exploit **fails** due to:
    *   Default configuration options that mitigate the issue.
    *   Missing required hardware/OS features.
    *   The vulnerability requires unachievable prerequisites (e.g., "attacker must already be root").

**Example Notes:**
> "Unexploitable in default config. Vulnerable function is behind an authentication flag that is disabled by default."
> "Exploit requires Windows, but this library is Linux-only."

### 📝 POC_PUBLIC
**Criteria:**
*   You found a Proof of Concept (PoC) on GitHub, Exploit-DB, or a blog.
*   You have **NOT** yet verified it yourself (or you haven't finished building the environment).
*   This is a "lead" for future verification.

**Example Notes:**
> "Found PoC on GitHub (link). Haven't run it yet."

### 🚫 NONE
**Criteria:**
*   No public exploit code or detailed reproduction steps could be found after searching.

---

## 3. Research Depth Criteria

### LEVEL_0 (Triage)
*   Read the CVE description.
*   Read the GitHub Advisory.
*   Identify the affected package and version.

### LEVEL_1 (Code Review)
*   Located the vulnerable code in the source repository.
*   Understood *why* the code is vulnerable.
*   Attempted to build the environment (Build Status may be SUCCESS or FAILED).

### LEVEL_2 (Deep Analysis)
*   **Full Replication:** Successfully built the environment.
*   **Exploitation Attempted:** Ran an exploit (Result is VERIFIED_SUCCESS or UNEXPLOITABLE).
*   **Root Cause Analysis:** Can explain exactly how the input flows to the vulnerability.
