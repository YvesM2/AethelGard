import re
from src.core.knowledge_base import PROCESS_SCHEMA, SAFE_APPS

class ForensicHeuristics:
    
    @staticmethod
    def analyze_processes(process_list, netscan_data=None):
        """
        Tier 1 Filter: Matches processes against the Schema using exact or prefix logic.
        """
        results = []
        
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
            

            matched_schema_name = None
            if clean_name in PROCESS_SCHEMA:
                matched_schema_name = clean_name
            elif len(clean_name) >= 14:
                for safe_name in PROCESS_SCHEMA.keys():
                    if safe_name.startswith(clean_name):
                        matched_schema_name = safe_name
                        break
            
            confidence = 0.5 
            flags = []

            proc_conns = net_map.get(pid, [])
            if proc_conns:
                flags.append("Network Activity")
                confidence += 0.2

            if matched_schema_name:
                schema = PROCESS_SCHEMA[matched_schema_name]

                confidence = 0.2 
                
                
            else:
                flags.append("Unknown Binary")
                confidence += 0.3

            if "HIDDEN" in proc.get("AethelTags", []):
                flags.append("Unlinked Process")
                confidence += 0.4

            results.append({
                "pid": pid,
                "name": raw_name, 
                "confidence": min(1.0, confidence),
                "flags": flags,
                "net_connections": proc_conns,
                "AethelTags": proc.get("AethelTags", [])
            })

        return results
