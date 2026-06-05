#!/usr/bin/env python3
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
import threading
from concurrent.futures import ThreadPoolExecutor
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

_MAX_BACKOFF = 120


def log(message: str, level: str = "INFO"):
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


def _resolve_local_ip() -> str:
    # gethostbyname fails on Linux hosts where the short hostname doesn't
    # resolve; fall back to a UDP connect that needs no actual packets sent.
    try:
        return socket.gethostbyname(socket.gethostname())
    except (socket.gaierror, OSError):
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_system_info() -> Dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "python_version": platform.python_version(),
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "architecture": platform.machine(),
        "ip_address": _resolve_local_ip(),
    }


class TestExecutor:
    def __init__(self, temp_dir: Optional[str] = None):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.python_exe = sys.executable

    def execute_code(self, test_code: str, test_name: str, timeout: int = 60,
                     proc_hook=None) -> Dict:
        result = {"status": "failed", "details": "", "detection_info": ""}

        tmp_fd, temp_file = tempfile.mkstemp(
            suffix=".py", prefix=f"testerpy2_{test_name}_"
        )
        try:
            os.close(tmp_fd)
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(test_code)

            log(f"Executing: {test_name}", "EXEC")

            proc = subprocess.Popen(
                [self.python_exe, temp_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.temp_dir
            )

            if proc_hook:
                proc_hook(proc)

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                result["status"] = "detected"
                result["details"] = f"Timed out after {timeout}s"
                result["detection_info"] = "EDR may have blocked or delayed execution"
                log(f"Test timed out: {test_name}", "WARNING")
                return result

            stdout = stdout.strip()
            stderr = stderr.strip()

            if stderr:
                log(f"Test stderr: {stderr}", "DEBUG")

            if stdout:
                # Tests output a single JSON line last; some emit banner/debug
                # text before it, so scan from the end and fall back to full stdout.
                parsed = None
                for candidate in (stdout.splitlines()[-1], stdout):
                    candidate = candidate.strip()
                    if not candidate:
                        continue
                    try:
                        parsed = json.loads(candidate)
                        break
                    except json.JSONDecodeError:
                        continue

                if parsed is not None:
                    result = parsed
                    log(f"Test result: {result.get('status', 'unknown')}", "INFO")
                else:
                    result["status"] = "success" if proc.returncode == 0 else "failed"
                    result["details"] = stdout
            else:
                result["status"] = "failed" if proc.returncode != 0 else "success"
                result["details"] = f"Exit code: {proc.returncode}"
                if stderr:
                    result["details"] += f"\nError: {stderr}"

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
            try:
                os.remove(temp_file)
            except Exception:
                pass

        return result

    def execute_code_base64(self, code_b64: str, test_name: str,
                            timeout: int = 60, proc_hook=None) -> Dict:
        try:
            test_code = base64.b64decode(code_b64).decode('utf-8')
            return self.execute_code(test_code, test_name, timeout, proc_hook)
        except Exception as e:
            return {
                "status": "failed",
                "details": f"Failed to decode test code: {e}",
                "detection_info": ""
            }


class Agent:
    def __init__(self, server_url: str, beacon_interval: int = 10,
                 api_key: Optional[str] = None):
        self.server_url = server_url.rstrip("/")
        self.beacon_interval = beacon_interval
        self.agent_id = None
        self.running = True
        self.executor = TestExecutor()
        self._running_procs: Dict[str, subprocess.Popen] = {}
        self._procs_lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4)

        headers = {
            "User-Agent": "TESTERPy2-Agent/2.0",
            "Content-Type": "application/json"
        }
        if api_key:
            headers["X-API-Key"] = api_key

        self.session = requests.Session()
        self.session.headers.update(headers)

    def register(self) -> bool:
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
                log(f"Registered. Agent ID: {self.agent_id}", "SUCCESS")
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

            if r.status_code == 404:
                # Server forgot us (e.g. restarted) - re-register rather than
                # looping forever as an unknown agent.
                log("Server returned 404 - re-registering", "WARNING")
                self.agent_id = None
                if self.register():
                    log("Re-registration successful", "SUCCESS")
                else:
                    log("Re-registration failed; will retry next beacon cycle", "WARNING")
            return []

        except Exception as e:
            log(f"Beacon error: {e}", "DEBUG")
            return []

    def submit_result(self, test_id: str, status: str, details: str,
                      detection_info: str):
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
        test_id = command.get("test_id")
        test_name = command.get("test_name")
        test_code = command.get("test_code")
        test_code_b64 = command.get("test_code_b64")
        timeout = command.get("timeout", 60)

        log(f"Executing test: {test_name} (ID: {test_id})", "EXEC")
        self.submit_result(test_id, "running", "Test execution started", "")

        def _register_proc(proc):
            with self._procs_lock:
                self._running_procs[test_id] = proc

        try:
            if test_code_b64:
                result = self.executor.execute_code_base64(
                    test_code_b64, test_name, timeout, proc_hook=_register_proc)
            elif test_code:
                result = self.executor.execute_code(
                    test_code, test_name, timeout, proc_hook=_register_proc)
            else:
                result = {
                    "status": "failed",
                    "details": "No test code provided",
                    "detection_info": ""
                }
        finally:
            with self._procs_lock:
                self._running_procs.pop(test_id, None)

        self.submit_result(
            test_id, result["status"],
            result.get("details", ""), result.get("detection_info", "")
        )

        status_log = {
            "success": "SUCCESS", "detected": "WARNING",
            "failed": "ERROR", "skipped": "DEBUG"
        }
        log(f"Test complete: {result['status']}",
            status_log.get(result["status"], "INFO"))

    def _cancel_test(self, command: dict):
        test_id = command.get("test_id")
        with self._procs_lock:
            proc = self._running_procs.get(test_id)
        if proc:
            proc.kill()
            log(f"Killed subprocess for test: {test_id}", "WARNING")
        self.submit_result(test_id, "cancelled", "Cancelled by operator", "")

    def run(self):
        while not self.register():
            log("Retrying registration in 5s...", "WARNING")
            time.sleep(5)

        log(f"Agent running. Beacon interval: {self.beacon_interval}s", "INFO")

        _backoff = self.beacon_interval

        while self.running:
            try:
                commands = self.beacon()
                _backoff = self.beacon_interval

                for cmd in commands:
                    cmd_type = cmd.get("type")
                    if cmd_type == "execute_test":
                        self._pool.submit(self.execute_test, cmd)
                    elif cmd_type == "cancel_test":
                        self._pool.submit(self._cancel_test, cmd)
                    elif cmd_type == "shutdown":
                        log("Shutdown command received", "WARNING")
                        self.running = False
                    else:
                        log(f"Unknown command type: {cmd_type}", "WARNING")

                time.sleep(_backoff)

            except KeyboardInterrupt:
                log("Interrupted by user", "WARNING")
                self.running = False
            except Exception as e:
                log(f"Error in main loop: {e}", "ERROR")
                _backoff = min(_backoff * 2, _MAX_BACKOFF)
                time.sleep(_backoff)

        self._pool.shutdown(wait=False)
        log("Agent stopped", "INFO")


def main():
    parser = argparse.ArgumentParser(description="TESTERPy2 Agent")
    parser.add_argument("--server", "-s", default="http://localhost:5000",
                        help="Server URL (default: http://localhost:5000)")
    parser.add_argument("--interval", "-i", type=int, default=10,
                        help="Beacon interval in seconds (default: 10)")
    parser.add_argument("--api-key", "-k", default=None,
                        help="API key for server authentication")

    args = parser.parse_args()

    print(f"  Server:   {args.server}")
    print(f"  Interval: {args.interval}s")
    print(f"  Auth:     {'enabled' if args.api_key else 'disabled'}")
    print(f"  Platform: {platform.system()} {platform.release()}")
    print(f"  Python:   {platform.python_version()}")
    print(f"  Hostname: {socket.gethostname()}")
    print()

    try:
        agent = Agent(args.server, args.interval, api_key=args.api_key)
        agent.run()
    except KeyboardInterrupt:
        log("Agent terminated", "INFO")


if __name__ == "__main__":
    main()
