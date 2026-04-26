"""CWE Hierarchical Tree Traversal Engine."""

import os
import json
import zipfile
import urllib.request
from typing import Optional, Dict, List
import xml.etree.ElementTree as ET
from src.models import CWECategory


class CWETreeEngine:
    """
    Engine to parse MITRE CWE dependencies and perform O(1) recursive lookups 
    to map subset CWE IDs to root OWASP Category Pillars.
    """
    
    CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    JSON_CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cwe_tree.json")
    
    # The 'Terminal Anchors' from data.md
    OWASP_ROOT_MAPPING = {
        # BROKEN_ACCESS_CONTROL
        "CWE-22": CWECategory.BROKEN_ACCESS_CONTROL.value,
        "CWE-285": CWECategory.BROKEN_ACCESS_CONTROL.value,
        "CWE-639": CWECategory.BROKEN_ACCESS_CONTROL.value,
        "CWE-862": CWECategory.BROKEN_ACCESS_CONTROL.value,
        "CWE-863": CWECategory.BROKEN_ACCESS_CONTROL.value,
        
        # INJECTION_FLAWS
        "CWE-78": CWECategory.INJECTION_FLAWS.value,
        "CWE-79": CWECategory.INJECTION_FLAWS.value,
        "CWE-89": CWECategory.INJECTION_FLAWS.value,
        "CWE-94": CWECategory.INJECTION_FLAWS.value,
        "CWE-91": CWECategory.INJECTION_FLAWS.value,
        "CWE-564": CWECategory.INJECTION_FLAWS.value,
        
        # CRYPTOGRAPHIC_FAILURES
        "CWE-259": CWECategory.CRYPTOGRAPHIC_FAILURES.value,
        "CWE-295": CWECategory.CRYPTOGRAPHIC_FAILURES.value,
        "CWE-327": CWECategory.CRYPTOGRAPHIC_FAILURES.value,
        "CWE-330": CWECategory.CRYPTOGRAPHIC_FAILURES.value,
        
        # INSECURE_DESIGN_AND_ARCH
        "CWE-434": CWECategory.INSECURE_DESIGN_AND_ARCH.value,
        "CWE-502": CWECategory.INSECURE_DESIGN_AND_ARCH.value,
        "CWE-918": CWECategory.INSECURE_DESIGN_AND_ARCH.value,
        
        # SECURITY_MISCONFIGURATION
        "CWE-16": CWECategory.SECURITY_MISCONFIGURATION.value,
        "CWE-611": CWECategory.SECURITY_MISCONFIGURATION.value,
        "CWE-1004": CWECategory.SECURITY_MISCONFIGURATION.value,
        
        # AUTHENTICATION_FAILURES
        "CWE-287": CWECategory.AUTHENTICATION_FAILURES.value,
        "CWE-306": CWECategory.AUTHENTICATION_FAILURES.value,
        "CWE-798": CWECategory.AUTHENTICATION_FAILURES.value,
        
        # SOFTWARE_AND_DATA_INTEGRITY
        "CWE-494": CWECategory.SOFTWARE_AND_DATA_INTEGRITY.value,
        "CWE-829": CWECategory.SOFTWARE_AND_DATA_INTEGRITY.value,
        "CWE-1104": CWECategory.SOFTWARE_AND_DATA_INTEGRITY.value,
    }
    
    def __init__(self, force_update: bool = False):
        """
        Initialize the Engine. Downloads and parses MITRE CWEs if the cache doesn't exist.
        """
        self.child_to_parents: Dict[str, List[str]] = {}
        
        if force_update or not os.path.exists(self.JSON_CACHE_PATH):
            self._fetch_and_build_cache()
            
        self._load_cache()

    def _fetch_and_build_cache(self) -> None:
        """Download cwec_latest.xml.zip, parse ChildOf relationships, save to JSON."""
        print(f"[*] CWE cache not found. Downloading latest MITRE CWE Dict from {self.CWE_URL}...")
        
        data_dir = os.path.dirname(self.JSON_CACHE_PATH)
        os.makedirs(data_dir, exist_ok=True)
        
        zip_path = os.path.join(data_dir, "cwe_latest.zip")
        
        # 1. Download
        urllib.request.urlretrieve(self.CWE_URL, zip_path)
        
        # 2. Unzip and parse
        child_parent_map = {}
        
        print("[*] Parsing MITRE CWE XML...")
        with zipfile.ZipFile(zip_path, 'r') as z:
            # Usually there is only 1 xml file inside
            xml_filename = [name for name in z.namelist() if name.endswith('.xml')][0]
            with z.open(xml_filename) as xf:
                tree = ET.parse(xf)
                root = tree.getroot()
                
                # Mitre uses namespaces sometimes, but searching gracefully:
                # We look for <Weakness> elements.
                for el in root.iter():
                    # Strip namespace for tag comparison
                    tag_name = el.tag.split('}')[-1] if '}' in el.tag else el.tag
                    
                    if tag_name in ['Weakness', 'Category']:
                        node_id = f"CWE-{el.attrib.get('ID', '')}"
                        if node_id == "CWE-":
                            continue
                            
                        parents = []
                        # Look for Related_Weaknesses -> Related_Weakness Nature="ChildOf"
                        for related_weaknesses in el:
                            rw_tag = related_weaknesses.tag.split('}')[-1] if '}' in related_weaknesses.tag else related_weaknesses.tag
                            if rw_tag == 'Related_Weaknesses':
                                for rw in related_weaknesses:
                                    r_tag = rw.tag.split('}')[-1] if '}' in rw.tag else rw.tag
                                    if r_tag == 'Related_Weakness':
                                        nature = rw.attrib.get('Nature', '')
                                        parent_cwe_id = rw.attrib.get('CWE_ID', '')
                                        if nature == 'ChildOf' and parent_cwe_id:
                                            parents.append(f"CWE-{parent_cwe_id}")
                        
                        if parents:
                            child_parent_map[node_id] = parents
        
        # 3. Save to JSON
        with open(self.JSON_CACHE_PATH, 'w') as f:
            json.dump(child_parent_map, f)
            
        # 4. Cleanup
        os.remove(zip_path)
        print("[*] Built CWE Hierarchical cache successfully.")

    def _load_cache(self):
        """Load JSON into memory."""
        with open(self.JSON_CACHE_PATH, 'r') as f:
            self.child_to_parents = json.load(f)

    def get_parents(self, cwe_id: str) -> List[str]:
        """Get direct parents of a CWE."""
        # Format normalization
        if isinstance(cwe_id, int) or cwe_id.isdigit():
            cwe_id = f"CWE-{cwe_id}"
        return self.child_to_parents.get(cwe_id.upper(), [])

    def find_owasp_root_category(self, cwe_id: str, max_depth=10) -> Optional[str]:
        """
        Recursively traverse parents until hitting an OWASP Pillar.
        Returns the mapped Category String (e.g. "INJECTION_FLAWS"), or None if unmapped.
        """
        if not cwe_id:
            return None
            
        cwe_id = str(cwe_id).upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
            
        # Visited set for cycle prevention
        visited = set()
        
        # BFS traversal
        queue = [(cwe_id, 0)]
        
        while queue:
            current_id, depth = queue.pop(0)
            
            if current_id in visited or depth > max_depth:
                continue
            visited.add(current_id)
            
            # Check if this node is exactly the Anchor we need
            if current_id in self.OWASP_ROOT_MAPPING:
                return self.OWASP_ROOT_MAPPING[current_id]
                
            # Otherwise, enqueue parents
            parents = self.get_parents(current_id)
            for p in parents:
                queue.append((p, depth + 1))
                
        # Climbed the whole tree but hit nothing in the OWASP map
        return None

if __name__ == "__main__":
    # Test
    engine = CWETreeEngine()
    print("Testing CWE-564 (Hibernate SQLi)...")
    res = engine.find_owasp_root_category("CWE-564")
    print(f"Result: {res}")
    assert res == CWECategory.INJECTION_FLAWS.value
