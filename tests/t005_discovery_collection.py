#!/usr/bin/env python3
"""
T005: Python Discovery & Collection
MITRE ATT&CK: T1059.006 + T1082 + T1113

Tests EDR detection of Python-based system discovery and data collection
including system enumeration, screenshots, keylogging, and file discovery.

For authorized security testing only.
"""

import sys
import os
import json
import socket
import platform
import subprocess

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

def run():
    """Execute the discovery & collection test and return results."""
    result = {
        "status": "pending",
        "details": "",
        "detection_info": ""
    }
    
    findings = []
    detected = False
    
    try:
        findings.append(f"=== System Discovery ({platform.system()}) ===")
        
        # Test 1: System Information Enumeration
        try:
            hostname = socket.gethostname()
            system = f"{platform.system()} {platform.release()}"
            arch = platform.machine()
            python_ver = platform.python_version()
            
            findings.append(f"[SYSTEM] Hostname: {hostname}")
            findings.append(f"[SYSTEM] OS: {system}")
            findings.append(f"[SYSTEM] Architecture: {arch}")
            findings.append(f"[SYSTEM] Python: {python_ver}")
        except Exception as e:
            findings.append(f"[SYSTEM] Error: {e}")
        
        # Test 2: Network Information
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            findings.append(f"[NETWORK] Local IP: {local_ip}")
            
            # Get network interfaces (platform-specific)
            if IS_WINDOWS:
                proc = subprocess.run(
                    "ipconfig /all",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Count adapters
                adapters = proc.stdout.count("adapter")
                findings.append(f"[NETWORK] Adapters: {adapters}")
            else:
                proc = subprocess.run(
                    "ip addr 2>/dev/null || ifconfig",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                interfaces = len([l for l in proc.stdout.split('\n') if 'inet ' in l])
                findings.append(f"[NETWORK] Interfaces: {interfaces}")
        except subprocess.TimeoutExpired:
            findings.append("[NETWORK] BLOCKED: Command timeout")
            detected = True
        except Exception as e:
            findings.append(f"[NETWORK] Error: {e}")
        
        # Test 3: Process Enumeration
        try:
            if IS_WINDOWS:
                cmd = "tasklist"
            else:
                cmd = "ps aux"
            
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = proc.stdout.strip().split('\n')
            findings.append(f"[PROCESS] Running processes: {len(lines)}")
            
            # Look for security products
            security_keywords = ['defender', 'antivirus', 'av', 'edr', 'sentinel', 
                               'crowdstrike', 'carbon', 'cylance', 'symantec']
            sec_procs = [l for l in lines if any(k in l.lower() for k in security_keywords)]
            if sec_procs:
                findings.append(f"[PROCESS] Security products detected: {len(sec_procs)}")
            
        except subprocess.TimeoutExpired:
            findings.append("[PROCESS] BLOCKED: Enumeration timeout")
            detected = True
        except Exception as e:
            findings.append(f"[PROCESS] Error: {e}")
        
        # Test 4: Screenshot Capability (Windows)
        if IS_WINDOWS:
            try:
                import ctypes
                user32 = ctypes.windll.user32
                width = user32.GetSystemMetrics(0)
                height = user32.GetSystemMetrics(1)
                findings.append(f"[SCREENSHOT] Screen resolution: {width}x{height}")
                findings.append("[SCREENSHOT] Capture capability: Available")
            except Exception as e:
                findings.append(f"[SCREENSHOT] Error: {e}")
        
        # Test 5: Keylogger Capability (Windows)
        if IS_WINDOWS:
            try:
                import ctypes
                keyboard_state = (ctypes.c_byte * 256)()
                result_kb = ctypes.windll.user32.GetKeyboardState(keyboard_state)
                if result_kb:
                    findings.append("[KEYLOGGER] Keyboard state accessible")
                    findings.append("[KEYLOGGER] Capture capability: Available")
                else:
                    findings.append("[KEYLOGGER] BLOCKED: Cannot read keyboard state")
                    detected = True
            except Exception as e:
                findings.append(f"[KEYLOGGER] Error: {e}")
        
        # Test 6: File System Discovery
        try:
            home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
            home_files = os.listdir(home)
            findings.append(f"[FILES] Home directory items: {len(home_files)}")
            
            # Look for interesting directories
            interesting = ['Documents', 'Desktop', 'Downloads', '.ssh', '.aws']
            found_dirs = [d for d in interesting if d in home_files]
            if found_dirs:
                findings.append(f"[FILES] Interesting directories: {', '.join(found_dirs)}")
            
            # Count files in Documents (if exists)
            docs_path = os.path.join(home, "Documents")
            if os.path.exists(docs_path):
                try:
                    doc_count = len(os.listdir(docs_path))
                    findings.append(f"[FILES] Documents folder: {doc_count} items")
                except PermissionError:
                    findings.append("[FILES] Documents: Access denied")
                    
        except Exception as e:
            findings.append(f"[FILES] Error: {e}")
        
        # Test 7: Clipboard Access (Windows)
        if IS_WINDOWS:
            try:
                import ctypes
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32
                
                if user32.OpenClipboard(0):
                    user32.CloseClipboard()
                    findings.append("[CLIPBOARD] Access: Available")
                else:
                    findings.append("[CLIPBOARD] Access: Denied")
            except Exception as e:
                findings.append(f"[CLIPBOARD] Error: {e}")
        
        # Test 8: Environment Variables
        try:
            env_count = len(os.environ)
            sensitive_vars = ['PATH', 'HOME', 'USERNAME', 'USERPROFILE', 
                            'COMPUTERNAME', 'USERDOMAIN']
            found_vars = [v for v in sensitive_vars if v in os.environ]
            findings.append(f"[ENV] Environment variables: {env_count}")
            findings.append(f"[ENV] Sensitive vars accessible: {len(found_vars)}")
        except Exception as e:
            findings.append(f"[ENV] Error: {e}")
        
        # Compile results
        result["details"] = "\n".join(findings)
        
        if detected:
            result["status"] = "detected"
            result["detection_info"] = "EDR blocked discovery/collection technique(s)"
        else:
            result["status"] = "success"
            
    except Exception as e:
        result["status"] = "failed"
        result["details"] = f"Unexpected error: {e}"
    
    return result


if __name__ == "__main__":
    result = run()
    print(json.dumps(result))
    sys.exit(0 if result["status"] in ["success", "detected", "skipped"] else 1)
