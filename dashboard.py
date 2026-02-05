import streamlit as st
import json
import os
import glob
import subprocess
import time
import pandas as pd

# --- CONFIG ---
CASES_DIR = "cases"
DUMPS_DIR = "dumps"
SUPPORTED_EXTENSIONS = ['*.vmem', '*.raw', '*.mem', '*.dmp', '*.dd']

st.set_page_config(page_title="AethelGard Command", layout="wide", page_icon="🛡️")

# --- CUSTOM CSS FOR PROFESSIONAL UI ---
st.markdown("""
<style>
    .evidence-box {
        border-left: 5px solid #ff4b4b;
        background-color: #262730;
        padding: 15px;
        margin-bottom: 10px;
        border-radius: 5px;
    }
    .safe-box {
        border-left: 5px solid #00c0f2;
        background-color: #262730;
        padding: 10px;
        margin-bottom: 10px;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR: MISSION CONTROL ---
st.sidebar.header("🚀 Mission Control")

# 1. FILE SELECTOR
dump_files = []
for ext in SUPPORTED_EXTENSIONS:
    dump_files.extend(glob.glob(os.path.join(DUMPS_DIR, ext)))
dump_files.sort(key=os.path.getmtime, reverse=True)

selected_dump = st.sidebar.selectbox("Select Target Dump:", dump_files)

# 2. DEPLOY BUTTON
if st.sidebar.button("Deploy Hunter Agent"):
    if selected_dump:
        with st.spinner(f"AethelGard is hunting in {os.path.basename(selected_dump)}..."):
            try:
                # EXECUTE BACKEND
                result = subprocess.run(
                    ["python", "main.py", selected_dump],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    st.sidebar.success("Investigation Complete!")
                else:
                    st.sidebar.error("Agent Failed!")
                    st.sidebar.code(result.stderr)
            except Exception as e:
                st.sidebar.error(f"Execution Error: {e}")
            
            time.sleep(1)
            st.rerun()

st.sidebar.divider()

# 3. CASE BROWSER
st.sidebar.header("🗂️ Case Archives")
if not os.path.exists(CASES_DIR): os.makedirs(CASES_DIR)

case_folders = sorted(glob.glob(os.path.join(CASES_DIR, "*")), reverse=True)
selected_folder = st.sidebar.selectbox("Select Investigation Report:", case_folders)

if not selected_folder:
    st.title("AethelGard: Ready for deployment.")
    st.info("Select a dump and click 'Deploy Hunter Agent' to begin.")
    st.stop()

# --- MAIN DASHBOARD CONTENT ---
st.title(f"🛡️ Operation: {os.path.basename(selected_folder)}")

# LOAD DATA
json_path = os.path.join(selected_folder, "final_reports.json")
audit_path = os.path.join(selected_folder, "pipeline_audit.md")
pid_logs_base = os.path.join(selected_folder, "logs", "pids")
global_logs_base = os.path.join(selected_folder, "logs", "global")

if os.path.exists(json_path):
    with open(json_path, "r") as f:
        try:
            report_data = json.load(f)
        except json.JSONDecodeError:
            st.error("Error reading report JSON.")
            st.stop()
    
    # METRICS
    col1, col2, col3, col4 = st.columns(4)
    total = len(report_data)
    malicious = len([x for x in report_data if "MALICIOUS" in x['final_verdict'] or "HIGH_RISK" in x['final_verdict']])
    followup = len([x for x in report_data if "REQUIRES_FOLLOWUP" in x['final_verdict']])
    
    col1.metric("Targets Scanned", total)
    col2.metric("Threats Detected", malicious, delta_color="inverse")
    col3.metric("Pending Review", followup, delta_color="off")
    
    st.divider()
    
    # 4. THREAT QUEUE
    st.subheader("🔥 Threat Queue")
    df = pd.DataFrame(report_data)
    if not df.empty:
        def get_risk_color(verdict):
            v = str(verdict)
            if "MALICIOUS" in v or "HIGH" in v: return "🔴"
            if "FOLLOWUP" in v: return "🟠"
            return "🟢"

        df['Risk'] = df['final_verdict'].apply(get_risk_color)
        display_df = df[['Risk', 'confidence_score', 'process_name', 'pid', 'final_verdict']].sort_values(by="confidence_score", ascending=False)
        
        st.dataframe(
            display_df,
            column_config={
                "confidence_score": st.column_config.ProgressColumn("Score", format="%.2f", min_value=0, max_value=1)
            },
            use_container_width=True,
            hide_index=True
        )

    # 5. ANALYST WORKBENCH (UPDATED)
    st.divider()
    st.subheader("🕵️ Analyst Workbench")
    
    pid_options = [r['pid'] for r in report_data]
    if pid_options:
        target_pid = st.selectbox("Select Target PID:", options=pid_options, format_func=lambda x: f"PID {x} - {[r['process_name'] for r in report_data if r['pid']==x][0]}")
        target = next((r for r in report_data if r['pid'] == target_pid), None)
        
        if target:
            c1, c2 = st.columns([2, 1])
            
            with c1:
                # --- NARRATIVE ---
                st.markdown("#### **Operational Narrative**")
                st.info(target.get("incident_narrative", "No narrative."))
                
                # --- CRITICAL EVIDENCE (NEW) ---
                # Filter for High Fidelity Artifacts (Malfind, Ldr, Yara)
                evidence = [step for step in target.get("investigation_log", []) 
                            if step.get("artifacts") and 
                            any(tool in step["command"] for tool in ["Malfind", "LdrModules", "YaraScan"])]
                
                if evidence:
                    st.markdown("#### **🚨 Verified Forensic Artifacts**")
                    for step in evidence:
                        with st.container():
                            st.markdown(f"""
                            <div class="evidence-box">
                                <strong>{step['command']}</strong> detected anomalies:<br>
                                <pre>{json.dumps(step['artifacts'], indent=2)}</pre>
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.markdown("#### **✅ Forensic Status**")
                    st.markdown("""<div class="safe-box">No high-fidelity anomalies detected in memory or linking structures.</div>""", unsafe_allow_html=True)

                # --- TIMELINE (RENAMED) ---
                with st.expander("📂 Full Forensic Execution Log"):
                    st.table(pd.DataFrame(target.get("investigation_log", [])))

            with c2:
                # --- METADATA ---
                st.markdown("#### **Target Metadata**")
                st.text(f"Process: {target.get('process_name')}")
                st.text(f"PID: {target.get('pid')}")
                st.markdown(f"**Verdict:** `{target.get('final_verdict')}`")
                st.metric("Risk Score", f"{target.get('confidence_score'):.2f}")
                
                # --- GRANULAR LOG VIEWER (NEW) ---
                st.divider()
                st.markdown("#### **🔬 Granular Tool Output**")
                
                # Look for logs in cases/<case>/logs/pids/<pid>/
                pid_dir = os.path.join(pid_logs_base, str(target_pid))
                
                if os.path.exists(pid_dir):
                    log_files = glob.glob(os.path.join(pid_dir, "*.json"))
                    if log_files:
                        selected_log = st.selectbox("Select Tool Log:", [os.path.basename(f) for f in log_files])
                        if selected_log:
                            with open(os.path.join(pid_dir, selected_log), "r") as log_f:
                                st.json(json.load(log_f))
                    else:
                        st.caption("No granular logs found for this PID.")
                else:
                    st.caption(f"No log directory found for PID {target_pid}")

    # 6. SYSTEM AUDIT (UPDATED)
    st.divider()
    st.subheader("📜 System Audit Trails")
    
    tab1, tab2, tab3 = st.tabs(["Pipeline Audit (Tables)", "Global Scan Logs", "Raw Text Backup"])
    
    with tab1:
        if os.path.exists(audit_path):
            with open(audit_path, "r") as f:
                st.markdown(f.read())
        else:
            st.warning("Audit log not found.")
            
    with tab2:
        # GLOBAL LOG VIEWER
        if os.path.exists(global_logs_base):
            global_files = glob.glob(os.path.join(global_logs_base, "*.json"))
            if global_files:
                selected_global = st.selectbox("View Global Scan:", [os.path.basename(f) for f in global_files])
                if selected_global:
                    with open(os.path.join(global_logs_base, selected_global), "r") as gf:
                        st.json(json.load(gf))
            else:
                st.info("No global logs found.")
        else:
            st.warning("Global logs directory missing.")

    with tab3:
        # Legacy Raw Text
        if os.path.exists(os.path.join(selected_folder, "raw_scans.txt")):
             with open(os.path.join(selected_folder, "raw_scans.txt"), "r") as f:
                 st.text_area("Raw Output", f.read(100000), height=400)

else:
    st.warning("Report generation in progress or failed. Check logs.")
