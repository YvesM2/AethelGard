
#  AethelGard V1.0

**Sovereign Autonomous Incident Response & Memory Forensics Engine**

AethelGard is a fully offline, air-gapped AI agent designed to triage Windows memory dumps. It combines the deterministic power of **Volatility 3** with the reasoning capabilities of **Local LLMs (Ollama/Llama3)** to automate forensic analysis without data ever leaving your machine.

Designed for high-security environments, AethelGard uses a **Tiered Trust Gate** architecture to filter noise and prevent AI hallucinations, strictly validating verdicts against hard forensic artifacts (Network, Injection, Masquerading).

---

##  Prerequisites

Before installing AethelGard, ensure your host machine meets the following requirements:

1.  **Python 3.10+**: Required for the core engine and Streamlit dashboard.
2.  **[Ollama](https://ollama.com/)**: Must be installed and running locally to provide the AI logic.
    * *Required Model:* You must pull the model specified in your config (default is `llama3`).
    * Command: `ollama pull llama3`
3.  **[Volatility 3](https://github.com/volatilityfoundation/volatility3)**: The forensic engine used to parse memory dumps.
    * AethelGard wraps the `vol.py` script. You must have Volatility 3 cloned and working on your machine.

---

##  Installation Guide

### 1. Clone the Repository
```bash
git clone [https://github.com/YvesM2/AethelGard.git](https://github.com/YvesM2/AethelGard.git)
cd AethelGard

```

### 2. Create a Virtual Environment (Recommended)

Isolate dependencies to prevent conflicts with your system Python.

**Mac/Linux:**

```bash
python3 -m venv venv
source venv/bin/activate

```

**Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1

```

### 3. Install Dependencies

Install the required Python packages (Streamlit, Pandas, etc.) into your virtual environment.

```bash
pip install -r requirements.txt

```

### 4. Configuration Setup

AethelGard uses environment variables to locate your local tools.

1. Copy the example configuration file:
```bash
cp .env.example .env

```


2. Open `.env` in a text editor and set the paths:
```ini
# The AI model you pulled in Ollama (e.g., llama3, mistral)
AI_MODEL_NAME=llama3

# IMPORTANT: The absolute path to your local Volatility 3 "vol.py" file
# Example: /Users/username/tools/volatility3/vol.py
VOLATILITY_PATH=../volatility3/vol.py

```


---

##  Usage

### Option 1: The Hunter Agent (CLI)

Run the automated triage engine directly from the terminal. This will perform the full 4-phase analysis and generate a report in the `cases/` folder.

**Syntax:**

```bash
python main.py <path_to_memory_dump>

```

**Example:**

```bash
python main.py dumps/TargetDump.vmem

```

### Option 2: Mission Control (Dashboard)

Launch the GUI to visualize threats, explore the forensic timeline, and view granular logs.

```bash
streamlit run dashboard.py

```

*The dashboard will open automatically in your default web browser.*

---

##  Core Architecture

AethelGard operates in 4 Distinct Phases:

1. **Tier 1 (Static Filter):** Instantly drops known-good Windows binaries (Trust Gate) using a strict whitelist.
2. **Tier 2 (Heuristic Triage):** Analyzes process behavior using a "High Activity Profile" to filter noise (e.g., ignoring high network volume for legitimate browsers like Edge/Slack).
3. **Tier 3 (Local AI Investigator):** Orchestrates forensic tools (`Malfind`, `Netscan`, `DllList`) via Ollama to hunt for anomalies in the remaining suspects.
4. **Guardrails:** A Python-based safety layer that overrides AI verdicts if critical artifacts (e.g., Code Injection, Unlinked Processes) are detected.

##  Project Structure

* `main.py`: The autonomous agent core.
* `dashboard.py`: Streamlit-based visualization deck.
* `src/core/knowledge_base.py`: The "Brain" containing known-good schemas and behavioral profiles.
* `cases/`: Auto-generated forensic reports and audit logs.
* `logs/`: Granular, per-process JSON logs for deep-dive analysis.

##  License

MIT License

```

```

