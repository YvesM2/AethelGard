
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

    if history and len(history) > 0:
        last_entry = history[-1]
        last_cmd = last_entry.get("command")
        if command == last_cmd and command not in ["windows.netscan.NetScan", "windows.consoles.Consoles"]:

            raise ValueError(f"Redundant command. {command} was just executed in the previous step.")

    if command in ["windows.netscan.NetScan", "windows.consoles.Consoles"]:
        return {} 

    if "pid" in args:
        try:
            val = int(args["pid"])
            if val < 0 or val > 100000: 
                raise ValueError("PID out of range.")
            clean_args["pid"] = val
        except (ValueError, TypeError):
            pass 

        if "offset" in args:
        try:
            clean_args["offset"] = int(str(args["offset"]), 16)
        except (ValueError, TypeError):
            pass
        
    if "key" in args:
        clean_val = str(args["key"]).replace(";", "").strip()
        if clean_val:
            clean_args["key"] = clean_val

    return clean_args
