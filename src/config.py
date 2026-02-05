# src/config.py

# --- HARDWARE & AI CONFIGURATION ---
# "llama3" is best for M1/M2/M3 chips (8GB+ RAM).
# If you have an older Mac or PC, try "phi3" or "gemma:2b" (faster, less smart).
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
# Prevents "Context Window Exceeded" errors on long runs.
MAX_HISTORY_ITEMS = 10
