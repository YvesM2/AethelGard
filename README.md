# 🛡️ AethelGard V1.0

**Sovereign Autonomous Incident Response & Memory Forensics Engine**

AethelGard is a fully offline, air-gapped AI agent designed to triage Windows memory dumps. It combines the deterministic power of **Volatility 3** with the reasoning capabilities of **Local LLMs (Ollama/Llama3)** to automate forensic analysis without data ever leaving your machine.

Designed for high-security environments, AethelGard uses a **Tiered Trust Gate** architecture to filter noise and prevent AI hallucinations, strictly validating verdicts against hard forensic artifacts (Network, Injection, Masquerading).

## 🧠 Core Architecture (V1.0)

1.  **Tier 1 (Static Filter):** Instantly drops known-good Windows binaries (Trust Gate).
2.  **Tier 2 (Heuristic Triage):** Analyzes process behavior using a "High Activity Profile" to filter noise (e.g., ignoring network volume for Edge/Slack).
3.  **Tier 3 (Local AI Investigator):** Orchestrates forensic tools (`Malfind`, `Netscan`, `DllList`) via Ollama to hunt for anomalies.
4.  **Guardrails:** A Python-based safety layer that overrides AI verdicts if critical artifacts (e.g., Code Injection) are detected.

## 🚀 Getting Started

### Prerequisites
* Python 3.10+
* [Volatility 3](https://github.com/volatilityfoundation/volatility3)
* [Ollama](https://ollama.com/) running locally
* `ollama pull llama3` (or your preferred model)

### Installation

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/AethelGard.git](https://github.com/YOUR_USERNAME/AethelGard.git)
    cd AethelGard
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Setup Configuration**
    Create a `.env` file in the root directory:
    ```ini
    AI_MODEL_NAME=llama3
    VOLATILITY_PATH=../path/to/vol.py
    ```

##  Usage

**1. The Hunter Agent (CLI)**
Run the automated triage engine on a memory dump:
```bash
python main.py dumps/Target.vmem
