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

        cmd = [sys.executable, self.vol_path, "-f", self.dump_path, "-r", "json", plugin_name]

        for key, value in args.items():
            if value is not None:
                if isinstance(value, bool):
                    if value: cmd.append(f"--{key}")
                else:
                    cmd.append(f"--{key}")
                    cmd.append(str(value))

        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300 
            )

            if result.returncode != 0:
                return {
                    "status": "ERROR",
                    "error": result.stderr.strip() or "Unknown CLI Error",
                    "data": [],
                    "raw": result.stdout  
                }

            try:
                output = result.stdout.strip()
                if not output:
                    return {"status": "EMPTY", "data": []}
                
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
