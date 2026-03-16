#!/usr/bin/env python3
"""
TESTERPy2 Agent - T1059.006 EDR/AV Testing Agent
Cross-platform Python agent for testing EDR/AV detection capabilities.

MITRE ATT&CK: T1059.006 - Command and Scripting Interpreter: Python
https://attack.mitre.org/techniques/T1059/006/

The agent receives test code from the server and executes it in a 
separate Python subprocess for isolation.

For authorized security testing only.

Usage:
    python agent.py --server http://192.168.1.100:5000
    python agent.py --server http://localhost:5000 --interval 5
"""

import os
import sys
import time
import json
import socket
import platform
import argparse
import subprocess
import tempfile
import base64
from datetime import datetime
from typing import Optional, Dict

try:
    import requests
except ImportError:
    print("[!] 'requests' library not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


def log(message: str, level: str = "INFO"):
    """Log a message with timestamp and color."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    colors = {
        "INFO": "\033[94m",
        "SUCCESS": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "DEBUG": "\033[90m",
        "EXEC": "\033[95m"
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    print(f"{color}[{timestamp}] [{level}] {message}{reset}")


def get_system_info() -> Dict[str, str]:
    """Gather system information for registration."""
    return {
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "python_version": platform.python_version(),
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "architecture": platform.machine(),
        "ip_address": socket.gethostbyname(socket.gethostname())
    }


class TestExecutor:
    """Handles execution of test code in isolated subprocess."""
    
    def __init__(self, temp_dir: Optional[str] = None):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.python_exe = sys.executable
    
    def execute_code(self, test_code: str, test_name: str, timeout: int = 60) -> Dict:
        """
        Execute test code in a separate Python subprocess.
        
        Args:
            test_code: The Python code to execute
            test_name: Name of the test (for temp file naming)
            timeout: Maximum execution time in seconds
            
        Returns:
            Dict with status, details, and detection_info
        """
        result = {
            "status": "failed",
            "details": "",
            "detection_info": ""
        }
        
        # Create temporary file for the test code
        temp_file = os.path.join(
            self.temp_dir, 
            f"testerpy2_{test_name}_{int(time.time())}.py"
        )
        
        try:
            # Write code to temp file
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(test_code)
            
            log(f"Executing test in subprocess: {test_name}", "EXEC")
            log(f"Temp file: {temp_file}", "DEBUG")
            
            # Execute in subprocess
            proc = subprocess.run(
                [self.python_exe, temp_file],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.temp_dir
            )
            
            # Parse JSON output from test
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
            
            if stderr:
                log(f"Test stderr: {stderr}", "DEBUG")
            
            if stdout:
                try:
                    # Test should output JSON result
                    result = json.loads(stdout)
                    log(f"Test result: {result.get('status', 'unknown')}", "INFO")
                except json.JSONDecodeError:
                    # If not JSON, treat stdout as details
                    result["status"] = "success" if proc.returncode == 0 else "failed"
                    result["details"] = stdout
            else:
                result["status"] = "failed" if proc.returncode != 0 else "success"
                result["details"] = f"Exit code: {proc.returncode}"
                if stderr:
                    result["details"] += f"\nError: {stderr}"
                    
        except subprocess.TimeoutExpired:
            result["status"] = "detected"
            result["details"] = f"Test execution timed out after {timeout}s"
            result["detection_info"] = "EDR may have blocked or delayed execution"
            log(f"Test timed out: {test_name}", "WARNING")
            
        except PermissionError as e:
            result["status"] = "detected"
            result["details"] = f"Permission denied: {e}"
            result["detection_info"] = "EDR blocked file creation or execution"
            log(f"Permission denied: {e}", "WARNING")
            
        except Exception as e:
            result["status"] = "failed"
            result["details"] = f"Execution error: {e}"
            log(f"Execution error: {e}", "ERROR")
            
        finally:
            # Cleanup temp file
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    log(f"Cleaned up temp file", "DEBUG")
            except Exception as e:
                log(f"Failed to cleanup temp file: {e}", "DEBUG")
        
        return result
    
    def execute_code_base64(self, code_b64: str, test_name: str, timeout: int = 60) -> Dict:
        """Execute base64-encoded test code."""
        try:
            test_code = base64.b64decode(code_b64).decode('utf-8')
            return self.execute_code(test_code, test_name, timeout)
        except Exception as e:
            return {
                "status": "failed",
                "details": f"Failed to decode test code: {e}",
                "detection_info": ""
            }


class Agent:
    """TESTERPy2 Agent - communicates with server and executes tests."""
    
    def __init__(self, server_url: str, beacon_interval: int = 10):
        self.server_url = server_url.rstrip("/")
        self.beacon_interval = beacon_interval
        self.agent_id = None
        self.running = True
        self.executor = TestExecutor()
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "TESTERPy2-Agent/2.0",
            "Content-Type": "application/json"
        })
    
    def register(self) -> bool:
        """Register agent with the server."""
        try:
            sys_info = get_system_info()
            log(f"Registering with server: {self.server_url}", "INFO")
            
            r = self.session.post(
                f"{self.server_url}/api/agent/register",
                json=sys_info,
                timeout=10
            )
            
            if r.status_code == 200:
                self.agent_id = r.json().get("agent_id")
                log(f"Registered successfully. Agent ID: {self.agent_id}", "SUCCESS")
                return True
            else:
                log(f"Registration failed: {r.status_code}", "ERROR")
                return False
                
        except requests.exceptions.ConnectionError:
            log(f"Cannot connect to server: {self.server_url}", "ERROR")
            return False
        except Exception as e:
            log(f"Registration error: {e}", "ERROR")
            return False
    
    def beacon(self) -> list:
        """Send beacon to server and receive pending commands."""
        try:
            r = self.session.post(
                f"{self.server_url}/api/agent/beacon",
                json={"agent_id": self.agent_id},
                timeout=10
            )
            
            if r.status_code == 200:
                commands = r.json().get("commands", [])
                if commands:
                    log(f"Received {len(commands)} command(s)", "INFO")
                return commands
            return []
            
        except Exception as e:
            log(f"Beacon error: {e}", "DEBUG")
            return []
    
    def submit_result(self, test_id: str, status: str, details: str, detection_info: str):
        """Submit test result to server."""
        try:
            self.session.post(
                f"{self.server_url}/api/agent/result",
                json={
                    "test_id": test_id,
                    "status": status,
                    "details": details,
                    "detection_info": detection_info
                },
                timeout=10
            )
            log(f"Result submitted: {test_id} -> {status}", "INFO")
        except Exception as e:
            log(f"Failed to submit result: {e}", "ERROR")
    
    def execute_test(self, command: dict):
        """Execute a test command received from server."""
        test_id = command.get("test_id")
        test_name = command.get("test_name")
        test_code = command.get("test_code")
        test_code_b64 = command.get("test_code_b64")
        timeout = command.get("timeout", 60)
        
        log(f"Executing test: {test_name} (ID: {test_id})", "EXEC")
        
        if test_code_b64:
            # Execute base64-encoded code
            result = self.executor.execute_code_base64(test_code_b64, test_name, timeout)
        elif test_code:
            # Execute plain text code
            result = self.executor.execute_code(test_code, test_name, timeout)
        else:
            result = {
                "status": "failed",
                "details": "No test code provided in command",
                "detection_info": ""
            }
        
        # Submit result
        self.submit_result(
            test_id,
            result["status"],
            result["details"],
            result["detection_info"]
        )
        
        # Log result
        status_colors = {
            "success": "SUCCESS",
            "detected": "WARNING",
            "failed": "ERROR",
            "skipped": "DEBUG"
        }
        log(f"Test complete: {result['status']}", status_colors.get(result["status"], "INFO"))
    
    def run(self):
        """Main agent loop."""
        # Keep trying to register
        while not self.register():
            log("Retrying registration in 5 seconds...", "WARNING")
            time.sleep(5)
        
        log(f"Agent running. Beacon interval: {self.beacon_interval}s", "INFO")
        log("Waiting for commands...", "INFO")
        
        while self.running:
            try:
                # Get commands from server
                commands = self.beacon()
                
                # Process each command
                for cmd in commands:
                    cmd_type = cmd.get("type")
                    
                    if cmd_type == "execute_test":
                        self.execute_test(cmd)
                    elif cmd_type == "shutdown":
                        log("Shutdown command received", "WARNING")
                        self.running = False
                    else:
                        log(f"Unknown command type: {cmd_type}", "WARNING")
                
                # Wait for next beacon
                time.sleep(self.beacon_interval)
                
            except KeyboardInterrupt:
                log("Interrupted by user", "WARNING")
                self.running = False
            except Exception as e:
                log(f"Error in main loop: {e}", "ERROR")
                time.sleep(self.beacon_interval)
        
        log("Agent stopped", "INFO")


def main():
    """Entry point."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║  ████████╗███████╗███████╗████████╗███████╗██████╗               ║
    ║  ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗              ║
    ║     ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝              ║
    ║     ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗              ║
    ║     ██║   ███████╗███████║   ██║   ███████╗██║  ██║              ║
    ║     ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝              ║
    ║                                                                   ║
    ║  ██████╗ ██╗   ██╗██████╗     AGENT v2.0                         ║
    ║  ██╔══██╗╚██╗ ██╔╝╚════██╗    T1059.006 Security Testing         ║
    ║  ██████╔╝ ╚████╔╝  █████╔╝    Subprocess Test Execution          ║
    ║  ██╔═══╝   ╚██╔╝  ██╔═══╝                                        ║
    ║  ██║        ██║   ███████╗    For authorized testing only        ║
    ║  ╚═╝        ╚═╝   ╚══════╝                                       ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    parser = argparse.ArgumentParser(
        description="TESTERPy2 Agent - EDR/AV Testing Agent"
    )
    parser.add_argument(
        "--server", "-s",
        default="http://localhost:5000",
        help="Server URL (default: http://localhost:5000)"
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=10,
        help="Beacon interval in seconds (default: 10)"
    )
    
    args = parser.parse_args()
    
    print(f"  Server:   {args.server}")
    print(f"  Interval: {args.interval}s")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Python:   {platform.python_version()}")
    print(f"  Hostname: {socket.gethostname()}")
    print()
    
    try:
        agent = Agent(args.server, args.interval)
        agent.run()
    except KeyboardInterrupt:
        log("Agent terminated", "INFO")


if __name__ == "__main__":
    main()
