# src/agents/action_policy.py

def validate_args(command, args, history=None):
    """
    Sanitizes arguments before execution and prevents logical loops.
    
    Args:
        command (str): The Volatility plugin to run.
        args (dict): The arguments provided by the AI.
        history (list): The list of previous observations (for loop detection).
        
    Returns:
        dict: Safe arguments.
        
    Raises:
        ValueError: If the command violates policy or is redundant.
    """
    clean_args = {}
    
    # 0. LOOP PREVENTION
    # If the AI tries to run the exact same command twice in a row, block it.
    # Exception: NetScan and Consoles (content might change dynamically/we want to re-verify).
    if history and len(history) > 0:
        last_entry = history[-1]
        last_cmd = last_entry.get("command")
        if command == last_cmd and command not in ["windows.netscan.NetScan", "windows.consoles.Consoles"]:
            # Check if args are also identical (if args exist)
            # For simplicity, we block consecutive calls of the same plugin for static analysis.
            raise ValueError(f"Redundant command. {command} was just executed in the previous step.")

    # 1. SPECIAL RULES: PLUGINS THAT CRASH WITH PID
    # Volatility 3's NetScan and Consoles do NOT support filtering by --pid at the CLI level.
    # We must strip the PID here and filter the results in Python later.
    if command in ["windows.netscan.NetScan", "windows.consoles.Consoles"]:
        return {} 

    # 2. STANDARD PID SANITIZATION
    # Allowed commands: CmdLine, Malfind, DllList, Handles, etc.
    if "pid" in args:
        try:
            val = int(args["pid"])
            if val < 0 or val > 100000: 
                raise ValueError("PID out of range.")
            clean_args["pid"] = val
        except (ValueError, TypeError):
            pass # Drop invalid PID, run without it if necessary

    # 3. OFFSET/ADDRESS SANITIZATION
    if "offset" in args:
        try:
            # Handle hex strings (0x...) or integers
            clean_args["offset"] = int(str(args["offset"]), 16)
        except (ValueError, TypeError):
            pass
        
    # 4. REGISTRY KEY SANITIZATION
    if "key" in args:
        # Prevent command injection via semicolons or weird chars
        clean_val = str(args["key"]).replace(";", "").strip()
        if clean_val:
            clean_args["key"] = clean_val

    return clean_args
