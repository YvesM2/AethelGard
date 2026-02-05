import subprocess
import json
import sys

class VolatilityWrapper:
    def __init__(self, vol_path, dump_path):
        self.vol_path = vol_path
        self.dump_path = dump_path

    def run_plugin(self, plugin_name, args=None):
        """
        Executes a Volatility 3 plugin and returns parsed JSON.
        Handles argument parsing from Dict -> List format.
        """
        if args is None:
            args = {}

        # 1. Build the base command
        # Syntax: python3 vol.py -f <dump> -r json <plugin>
        cmd = [sys.executable, self.vol_path, "-f", self.dump_path, "-r", "json", plugin_name]

        # 2. Add Arguments (THE FIX)
        # We iterate the dictionary and append strings to the command list.
        for key, value in args.items():
            if value is not None:
                # Handle boolean flags (e.g., {'verbose': True} -> --verbose)
                if isinstance(value, bool):
                    if value: cmd.append(f"--{key}")
                # Handle standard key-value (e.g., {'pid': 708} -> --pid 708)
                else:
                    cmd.append(f"--{key}")
                    cmd.append(str(value))

        # 3. Execute
        try:
            # Capture output (both stdout and stderr)
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300 # 5 minute timeout for slow plugins
            )

            # 4. Error Handling (Non-JSON output)
            if result.returncode != 0:
                return {
                    "status": "ERROR",
                    "error": result.stderr.strip() or "Unknown CLI Error",
                    "data": [],
                    "raw": result.stdout  # Return raw for debugging
                }

            # 5. Parse JSON
            try:
                output = result.stdout.strip()
                if not output:
                    return {"status": "EMPTY", "data": []}
                
                # Find the start of the JSON structure (skip any deprecation warnings)
                json_start = output.find('[')
                if json_start == -1: json_start = output.find('{')
                
                if json_start != -1:
                    clean_json = output[json_start:]
                    parsed = json.loads(clean_json)
                    return {
                        "status": "SUCCESS",
                        "row_count": len(parsed),
                        "data": parsed
                    }
                else:
                    return {"status": "PARSE_ERROR", "error": "No JSON found", "raw": output[:200]}

            except json.JSONDecodeError as e:
                return {
                    "status": "JSON_ERROR", 
                    "error": f"Failed to parse JSON: {str(e)}", 
                    "raw": result.stdout[:200]
                }

        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "error": "Plugin timed out", "data": []}
        except Exception as e:
            return {"status": "CRASH", "error": str(e), "data": []}
