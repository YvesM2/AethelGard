import json
import os
import time
import datetime
import re
import sys
from src.config import (
    AI_MODEL_NAME, VOL_PATH, MAX_TARGETS_TO_ANALYZE, MAX_STEPS_PER_TARGET
)
from src.core.wrapper import VolatilityWrapper
from src.core.heuristics import ForensicHeuristics
from src.core.knowledge_base import PROCESS_SCHEMA, HIGH_ACTIVITY_APPS, YARA_SIGNATURES
from src.agents.investigator import AIInvestigator

# --- CONFIGURATION HANDLING ---
DEFAULT_DUMP = "dumps/AsyncRAT_Win10.mem"

if len(sys.argv) > 1:
    DUMP_FILE = sys.argv[1]
else:
    DUMP_FILE = DEFAULT_DUMP

print(f"[*] Target Dump: {DUMP_FILE}")

# --- TOOL CLASSIFICATION ---
ANOMALY_TOOLS = ["windows.malfind.Malfind", "windows.ldrmodules.LdrModules"]
CONTEXT_TOOLS = ["windows.cmdline.CmdLine", "windows.consoles.Consoles", "windows.dlllist.DllList", "windows.netscan.NetScan"]
ALL_TOOLS = ANOMALY_TOOLS + CONTEXT_TOOLS

# --- HELPER FUNCTIONS ---
def clean_for_json(data):
    if isinstance(data, dict): return {k: clean_for_json(v) for k, v in data.items()}
    elif isinstance(data, list): return [clean_for_json(v) for v in data]
    elif hasattr(data, '__dict__'): return clean_for_json(data.__dict__)
    else: return data

class CaseLogger:
    def __init__(self, dump_path):
        dump_name = os.path.basename(dump_path).split('.')[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.case_dir = os.path.join("cases", f"{dump_name}_{timestamp}")
        
        # New Directory Structure
        self.global_log_dir = os.path.join(self.case_dir, "logs", "global")
        self.pid_log_dir = os.path.join(self.case_dir, "logs", "pids")
        
        os.makedirs(self.global_log_dir, exist_ok=True)
        os.makedirs(self.pid_log_dir, exist_ok=True)
        
        self.audit_file = os.path.join(self.case_dir, "pipeline_audit.md")
        self.raw_file = os.path.join(self.case_dir, "raw_scans.txt") # Keeping strict text backup
        print(f"[+] Case Folder Created: {self.case_dir}")

    def save_raw(self, title, data):
        # Legacy monolithic backup
        with open(self.raw_file, "a") as f:
            f.write(f"\n{'='*40}\n[RAW DATA] {title}\n{'='*40}\n")
            f.write(json.dumps(clean_for_json(data), indent=2))
            f.write("\n")

    def save_scan(self, tool_name, data, pid=None):
        """
        Saves scan results to the granular file structure.
        """
        clean_data = clean_for_json(data)
        safe_tool_name = tool_name.replace("windows.", "").replace(".", "_")
        
        if pid:
            # Per-PID Log: logs/pids/1234/ToolName.json
            pid_dir = os.path.join(self.pid_log_dir, str(pid))
            os.makedirs(pid_dir, exist_ok=True)
            file_path = os.path.join(pid_dir, f"{safe_tool_name}.json")
        else:
            # Global Log: logs/global/ToolName.json
            file_path = os.path.join(self.global_log_dir, f"{safe_tool_name}.json")
            
        with open(file_path, "w") as f:
            json.dump(clean_data, f, indent=2)

    def log_table(self, title, headers, rows):
        with open(self.audit_file, "a") as f:
            f.write(f"\n## {title}\n\n")
            f.write("| " + " | ".join(headers) + " |\n")
            f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")
            for row in rows:
                clean_row = [str(r).replace("|", "/") for r in row]
                f.write("| " + " | ".join(clean_row) + " |\n")
            f.write("\n")

def extract_artifacts(command, result, filter_pid=None):
    if not result.get("data"): return None
    artifacts = []
    
    def is_match(row):
        if not filter_pid: return True
        try:
            r_pid = row.get("PID") or row.get("Pid") or row.get("ProcessId")
            if r_pid is not None and int(r_pid) == int(filter_pid): return True
        except: pass
        return False

    if "cmdline" in command.lower():
        for row in result["data"]:
            if is_match(row):
                vals = [str(v) for k,v in row.items() if v]
                if vals: artifacts.append(" ".join(vals))
    elif "consoles" in command.lower():
        for row in result["data"]:
            if is_match(row): 
                vals = [str(v) for k,v in row.items() if v and str(v) not in ["-", "None"]]
                if vals: artifacts.append(f"History: {' '.join(vals)}")
    elif "netscan" in command.lower():
        for row in result["data"]:
            if is_match(row): 
                addr = row.get("ForeignAddr") or row.get("RemoteAddress")
                port = row.get("ForeignPort") or row.get("RemotePort")
                state = row.get("State") or ""
                if addr and port: artifacts.append(f"Connection: {addr}:{port} ({state})")
    elif "dlllist" in command.lower():
        for row in result["data"]:
            path = row.get("Path") or row.get("Name")
            base = row.get("Base") or row.get("BaseAddr")
            if path: artifacts.append(f"DLL: {path} @ {base}")
    elif "ldrmodules" in command.lower():
        for row in result["data"]:
            if is_match(row):
                in_load = row.get("InLoad")
                in_mem = row.get("InMem")
                path = row.get("Path") or row.get("Name")
                if in_mem is True and in_load is False:
                    artifacts.append(f"Unlinked DLL: {path} (InMem: True, InLoad: False)")
    else:
        for row in result["data"]:
             vals = [str(v) for k,v in row.items() if v]
             if vals: artifacts.append(" ".join(vals))
    return artifacts if artifacts else None

# --- V14.0 POLICY ENGINE ---

class ForensicPolicy:
    @staticmethod
    def calculate_risk_floor(item):
        floor = 0.10
        if item.get("net_connections"): 
            floor = max(floor, 0.40)
        flags = item.get("flags", [])
        if any("Masquerading" in f for f in flags): floor = max(floor, 0.50)
        if "HIDDEN" in item.get("AethelTags", []): floor = max(floor, 0.35)
        
        name = item.get("name", "").lower()
        is_high_activity = False
        if name in HIGH_ACTIVITY_APPS:
            is_high_activity = True
        elif len(name) >= 14:
             for safe_name in HIGH_ACTIVITY_APPS:
                 if safe_name.startswith(name):
                     is_high_activity = True
                     break
        
        if is_high_activity:
            floor = min(floor, 0.25)
            
        return floor

    @staticmethod
    def check_yara_match(item):
        name = item.get("name", "").lower()
        for sig, family in YARA_SIGNATURES.items():
            if sig in name:
                return family
        return None

    @staticmethod
    def calculate_score_update(current_score, tool_name, has_artifacts, domains_hit):
        if not has_artifacts:
            return max(0.0, current_score - 0.15)
        if tool_name in ANOMALY_TOOLS:
            base_bump = 0.40
            if domains_hit >= 1:
                print(f"    [!] Multi-Domain Correlation. Boosting Score (x1.5).")
                base_bump *= 1.5
            return min(1.0, current_score + base_bump)
        else:
            return current_score

def run_investigation_on_target(target_item, wrapper, investigator, logger):
    target_pid = target_item["pid"]
    current_score = target_item.get("confidence", 0.5)
    risk_floor = ForensicPolicy.calculate_risk_floor(target_item)
    domains_hit = 0
    
    print(f"\n" + "="*60)
    print(f"[*] FORENSIC LOOP: PID {target_pid} ({target_item['name']})")
    print(f"[*] Initial Score: {current_score:.2f} | Risk Floor: {risk_floor:.2f}")
    print("="*60)
    
    yara_hit = ForensicPolicy.check_yara_match(target_item)
    if yara_hit:
        print(f"[!] YARA MATCH: {yara_hit}. KILL SWITCH ACTIVATED.")
        return {
            "target": target_item,
            "locked_verdict": "MALICIOUS",
            "locked_score": 1.0,
            "investigation_log": [{"step": 0, "command": "YaraScan", "artifacts": [f"Signature: {yara_hit}"]}],
            "findings_summary": [f"YARA Detection: {yara_hit}"]
        }

    observations = []
    used_tools = set()

    net_conns = target_item.get("net_connections", [])
    if net_conns:
        name = target_item["name"].lower()
        is_high_activity = False
        if name in HIGH_ACTIVITY_APPS: is_high_activity = True
        elif len(name) >= 14:
             for safe_name in HIGH_ACTIVITY_APPS:
                 if safe_name.startswith(name): is_high_activity = True; break

        if is_high_activity:
            print(f"    [i] High Activity Profile ({target_item['name']}). Ignoring Network Volume.")
        else:
            print(f"    [+] Pre-Loaded {len(net_conns)} Network Connections.")
            domains_hit += 1 
        
        observations.append({"step": 0, "command": "NetScan", "artifacts": [f"Connection: {c}" for c in net_conns]})
        used_tools.add("windows.netscan.NetScan")

    locked_verdict = "INCONCLUSIVE" 
    
    for step in range(MAX_STEPS_PER_TARGET):
        print(f"\n--- Analysis Step {step + 1} ---")
        
        available_tools = [t for t in ALL_TOOLS if t not in used_tools]
        if not available_tools:
            print("[!] Exhausted tools. Stopping.")
            break

        history_summary = []
        for o in observations:
            res = "Found Artifacts" if o.get("artifacts") else "Clean"
            history_summary.append(f"{o['command']} -> {res}")
        
        context = {
            "pid": target_pid,
            "current_score": current_score,
            "history_summary": "; ".join(history_summary) if history_summary else "None (Start)",
            "available_tools": available_tools
        }
        
        analysis = investigator.analyze_evidence(context)
        chosen_action = analysis.get("next_action", available_tools[0])
        if chosen_action not in available_tools: chosen_action = available_tools[0]

        print(f"[*] Executing: {chosen_action}")
        try:
            args = {"pid": target_pid}
            if "Consoles" in chosen_action: args = {}
            tool_result = wrapper.run_plugin(chosen_action, args=args)
            
            # --- GRANULAR LOGGING (Updated V14.4) ---
            logger.save_scan(chosen_action, tool_result, pid=target_pid)
            
            artifacts = extract_artifacts(chosen_action, tool_result, filter_pid=target_pid)
        except Exception:
            artifacts = None
            
        old_score = current_score
        has_artifacts = bool(artifacts)
        
        if has_artifacts:
            print(f"    [>] Found {len(artifacts)} data points.")
            if chosen_action in ANOMALY_TOOLS:
                print(f"    [!] Anomaly Detected.")
                current_score = ForensicPolicy.calculate_score_update(current_score, chosen_action, True, domains_hit)
                domains_hit += 1
            else:
                 print(f"    [i] Context Data. Score Neutral.")
        else:
            print("    [>] Clean.")
            potential = current_score - 0.15
            if potential < risk_floor:
                current_score = risk_floor
                print(f"    [-] Decay Hit Floor ({risk_floor:.2f}). Holding.")
            else:
                current_score = potential
                print(f"    [-] Clean. Decaying.")

        current_score = max(0.0, min(current_score, 1.0))
        print(f"Score Update: {old_score:.2f} -> {current_score:.2f}")

        if current_score <= 0.20 and current_score == risk_floor: 
             print("[*] Score minimized at Floor. Stopping.")
             break
        
        if current_score >= 0.95:
             if domains_hit >= 2:
                 print("[!] CRITICAL: Multi-Domain Correlation. Forcing STOP_MALICIOUS.")
                 locked_verdict = "MALICIOUS"
                 break
             else:
                 print("[!] High Score but Single Domain. Continuing to verify.")

        observations.append({"step": step+1, "command": chosen_action, "artifacts": artifacts})
        used_tools.add(chosen_action)
        time.sleep(1)

    if locked_verdict == "INCONCLUSIVE":
        if current_score <= 0.25: locked_verdict = "PROBABLY_BENIGN"
        elif current_score > 0.75: locked_verdict = "HIGH_RISK"
        else: locked_verdict = "REQUIRES_FOLLOWUP"

    findings_summary = []
    if yara_hit: findings_summary.append(f"YARA: {yara_hit}")
    if "HIDDEN" in target_item.get("AethelTags", []): 
        findings_summary.append("Anomaly: Unlinked Process")
    for o in observations:
        if o.get("artifacts") and o["command"] in ANOMALY_TOOLS: 
            findings_summary.append(f"Forensic Alert: {o['command']} found anomalies.")
    
    conclusion_payload = {
        "target": target_item, 
        "locked_verdict": locked_verdict,
        "locked_score": current_score,
        "investigation_log": observations, 
        "findings_summary": findings_summary
    }
    return investigator.generate_conclusion(conclusion_payload)

def main():
    print(f"--- AethelGard: Autonomous Incident Response (V14.4 Granular Logging) ---")
    logger = CaseLogger(DUMP_FILE)
    wrapper = VolatilityWrapper(vol_path=VOL_PATH, dump_path=DUMP_FILE)
    investigator = AIInvestigator(model_name=AI_MODEL_NAME)
    
    print("\n[Phase 1] Process Collection & Integrity...")
    pslist = wrapper.run_plugin("windows.pslist.PsList")
    psscan = wrapper.run_plugin("windows.psscan.PsScan")
    
    # --- GRANULAR LOGGING (Global) ---
    logger.save_scan("PsList", pslist)
    logger.save_scan("PsScan", psscan)
    
    pslist_pids = {int(p["PID"]) for p in pslist.get("data", [])}
    psscan_data = psscan.get("data", [])
    psscan_pids = {int(p["PID"]) for p in psscan_data}
    hidden_pids = psscan_pids - pslist_pids
    if hidden_pids: print(f"[!] ANOMALY: {len(hidden_pids)} Unlinked Processes.")

    master_list = []
    for proc in psscan_data:
        proc_pid = int(proc["PID"])
        proc["AethelTags"] = ["HIDDEN"] if proc_pid in hidden_pids else []
        master_list.append(proc)
    if not master_list: return

    print("\n[Phase 2] NetScan Overlay...")
    netscan = wrapper.run_plugin("windows.netscan.NetScan")
    logger.save_scan("NetScan", netscan) # Granular Log
    netscan_data = netscan.get("data", [])
    print(f"[+] NetScan found {len(netscan_data)} connections.")
    
    print("\n[Phase 3] Heuristics & Tier 1 Filter...")
    heuristics_items = ForensicHeuristics.analyze_processes(master_list, netscan_data=netscan_data)
    
    tier2_candidates = []
    final_investigation_list = []
    
    print("\n[Phase 4] Tiered Trust Gate...")
    for item in heuristics_items:
        name = item["name"]
        pid = item["pid"]
        if pid == 4: continue 
        is_masquerading = any("Masquerading" in f for f in item.get("flags", []))
        
        clean_name = name.lower()
        should_drop = False
        if clean_name in PROCESS_SCHEMA:
            if item["confidence"] < 0.4: should_drop = True
        elif len(clean_name) >= 14:
            for safe_name in PROCESS_SCHEMA:
                if safe_name.startswith(clean_name):
                    if item["confidence"] < 0.4: should_drop = True
                    break
        elif clean_name in HIGH_ACTIVITY_APPS:
             if item["confidence"] < 0.6: should_drop = True

        if not should_drop and not is_masquerading:
            tier2_candidates.append(item)

    table1_rows = [[str(i["pid"]), i["name"], f"{i['confidence']:.2f}", str(i.get("flags", []))] for i in tier2_candidates]
    logger.log_table("Table 1: Tier 1 -> Tier 2 Handoff", ["PID", "Name", "Score", "Flags"], table1_rows)

    if tier2_candidates:
        print(f"    [*] TIER 2: AI Analyzing {len(tier2_candidates)} candidates...")
        ai_trust_results = investigator.classify_trust(tier2_candidates)
        for item in tier2_candidates:
            pid_str = str(item["pid"])
            trust_data = ai_trust_results.get(pid_str, {"class": "UNKNOWN"})
            trust_class = trust_data.get("class", "UNKNOWN")
            flags = item.get("flags", [])
            
            clean_name = item["name"].lower()
            is_high_activity = False
            if clean_name in HIGH_ACTIVITY_APPS:
                is_high_activity = True
            elif len(clean_name) >= 14:
                 for safe_name in HIGH_ACTIVITY_APPS:
                     if safe_name.startswith(clean_name):
                         is_high_activity = True
                         break
            
            guardrail_triggers = ["Unknown Binary", "Network Activity"]
            if is_high_activity:
                if "Network Activity" in guardrail_triggers:
                    guardrail_triggers.remove("Network Activity")

            has_blocking_risk = any(x in flags for x in guardrail_triggers) or "HIDDEN" in item.get("AethelTags", [])
            
            if has_blocking_risk and trust_class == "KNOWN_GOOD":
                print(f"        [!] GUARDRAIL: {item['name']} has Risk. Ignoring AI 'KNOWN_GOOD'.")
                trust_class = "UNKNOWN"

            if trust_class == "KNOWN_BAD":
                print(f"        [!] TIER 2 ESCALATE: {item['name']}")
                item["confidence"] = 1.0 
                item["tier2_escalation"] = True
                item["trust_verdict"] = "KNOWN_BAD"
                final_investigation_list.append(item)
            elif trust_class == "KNOWN_GOOD":
                print(f"        [-] TIER 2 SOFT DROP: {item['name']}")
                item["confidence"] -= 0.3
                item["trust_verdict"] = "KNOWN_GOOD"
                if item["confidence"] > 0.05:
                    final_investigation_list.append(item)
            else:
                print(f"        [?] TIER 2 UNKNOWN: {item['name']}")
                item["trust_verdict"] = "UNKNOWN"
                final_investigation_list.append(item)

    def calculate_priority(item):
        score = item.get("confidence", 0.0)
        if item.get("tier2_escalation"): score += 1.0
        if item.get("net_connections"): score += 0.3
        if any("Masquerading" in f for f in item.get("flags", [])): score += 0.5
        return score

    final_investigation_list.sort(key=calculate_priority, reverse=True)
    table2_rows = [[str(i["pid"]), i["name"], i.get("trust_verdict", "N/A"), f"{calculate_priority(i):.2f}"] for i in final_investigation_list]
    logger.log_table("Table 2: Phase 4 Risk Sorting", ["PID", "Name", "Trust Class", "Priority Score"], table2_rows)

    print(f"[+] Final Investigation Queue: {len(final_investigation_list)} targets.")
    
    final_reports = []
    for case_num in range(min(5, len(final_investigation_list))):
        target_item = final_investigation_list[case_num]
        
        # --- PASS LOGGER INSTANCE ---
        report = run_investigation_on_target(target_item, wrapper, investigator, logger)
        
        if report:
            report["pid"] = target_item["pid"]
            report["process_name"] = target_item["name"]
            final_reports.append(report)
        
        with open(os.path.join(logger.case_dir, "final_reports.json"), "w") as f:
            json.dump(clean_for_json(final_reports), f, indent=2)

    table3_rows = [[str(r["pid"]), r["process_name"], r["final_verdict"], str(r["confidence_score"])] for r in final_reports]
    logger.log_table("Table 3: Locked Verdicts", ["PID", "Name", "Verdict", "Final Score"], table3_rows)

    print("\n" + "="*60); print("FORENSIC MISSION SUMMARY"); print("="*60)
    for rep in final_reports:
        print(f"PID {rep.get('pid')} ({rep.get('process_name')})")
        print(f"Verdict: {rep.get('final_verdict')} (Score: {rep.get('confidence_score'):.2f})")
        print("-" * 60)

if __name__ == "__main__":
    main()
