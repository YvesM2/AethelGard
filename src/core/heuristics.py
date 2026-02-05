import re
from src.core.knowledge_base import PROCESS_SCHEMA, SAFE_APPS

class ForensicHeuristics:
    
    @staticmethod
    def analyze_processes(process_list, netscan_data=None):
        """
        Tier 1 Filter: Matches processes against the Schema using exact or prefix logic.
        """
        results = []
        
        # Build network map for O(1) lookups
        net_map = {}
        if netscan_data:
            for conn in netscan_data:
                pid = conn.get("PID")
                if pid:
                    pid = int(pid)
                    if pid not in net_map: net_map[pid] = []
                    remote = f"{conn.get('ForeignAddr')}:{conn.get('ForeignPort')}"
                    net_map[pid].append(remote)

        for proc in process_list:
            pid = int(proc["PID"])
            raw_name = proc["ImageFileName"]
            clean_name = raw_name.lower()
            
            # --- TRUNCATION HANDLING (V14.1) ---
            # Try exact match first
            matched_schema_name = None
            if clean_name in PROCESS_SCHEMA:
                matched_schema_name = clean_name
            # If name is long (>=14 chars), check for prefix match
            elif len(clean_name) >= 14:
                for safe_name in PROCESS_SCHEMA.keys():
                    if safe_name.startswith(clean_name):
                        matched_schema_name = safe_name
                        break
            
            # DEFAULT: Assume Unknown/Suspicious
            confidence = 0.5 
            flags = []

            # 1. NETWORK CHECK
            proc_conns = net_map.get(pid, [])
            if proc_conns:
                flags.append("Network Activity")
                confidence += 0.2

            # 2. SCHEMA VALIDATION
            if matched_schema_name:
                schema = PROCESS_SCHEMA[matched_schema_name]
                
                # Path Check (Normalize slashes)
                # Volatility 3 output varies, sometimes None.
                # Only check if path is available.
                # For simplified logic: If name matches schema, start low.
                confidence = 0.2 
                
                # In a real tool, we would validate Parent PID here.
                # For now, we trust the Name match significantly to reduce Tier 2 load.
                
            else:
                # Unknown Binary
                flags.append("Unknown Binary")
                confidence += 0.3

            # 3. UNLINKED CHECK
            if "HIDDEN" in proc.get("AethelTags", []):
                flags.append("Unlinked Process")
                confidence += 0.4

            results.append({
                "pid": pid,
                "name": raw_name, # Keep original name for reporting
                "confidence": min(1.0, confidence),
                "flags": flags,
                "net_connections": proc_conns,
                "AethelTags": proc.get("AethelTags", [])
            })

        return results
