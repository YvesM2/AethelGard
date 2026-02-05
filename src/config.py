# src/config.py

# --- HARDWARE & AI CONFIGURATION ---

AI_MODEL_NAME = "llama3" 

# --- PATH CONFIGURATION ---
# Path to the volatility3 folder you cloned
VOL_PATH = "vol3/vol.py"

# --- INVESTIGATION PARAMETERS ---
# How many separate suspicious processes to hunt down in one run
MAX_TARGETS_TO_ANALYZE = 3 

# How many steps (tools) to use on a SINGLE target before giving up
MAX_STEPS_PER_TARGET = 5

# --- PERFORMANCE TUNING ---
# Only show the AI the last N actions. 
MAX_HISTORY_ITEMS = 10
