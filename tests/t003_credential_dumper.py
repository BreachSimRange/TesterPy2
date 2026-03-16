#!/usr/bin/env python3
"""
T003: Python Credential Dumper
MITRE ATT&CK: T1059.006 + T1003

Tests EDR detection of Python-based credential harvesting including
SAM database, LSASS memory, DPAPI secrets, and shadow file access.

For authorized security testing only.
"""

import sys
import os
import json
import platform

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

def run():
    """Execute the credential dumper test and return results."""
    result = {
        "status": "pending",
        "details": "",
        "detection_info": ""
    }
    
    findings = []
    detected = False
    
    try:
        if IS_WINDOWS:
            # Windows Credential Tests
            findings.append("=== Windows Credential Access ===")
            
            # Test 1: SAM Registry Access
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SAM\SAM",
                    0,
                    winreg.KEY_READ
                )
                winreg.CloseKey(key)
                findings.append("[SAM] Registry accessible (elevated)")
            except PermissionError:
                findings.append("[SAM] Access Denied (expected without SYSTEM)")
            except FileNotFoundError:
                findings.append("[SAM] Key not found")
            except Exception as e:
                if "denied" in str(e).lower():
                    findings.append(f"[SAM] BLOCKED by EDR: {e}")
                    detected = True
                else:
                    findings.append(f"[SAM] Error: {e}")
            
            # Test 2: LSASS Process Enumeration
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                psapi = ctypes.windll.psapi
                
                pids = (ctypes.c_ulong * 1024)()
                bytes_returned = ctypes.c_ulong()
                psapi.EnumProcesses(
                    ctypes.byref(pids),
                    ctypes.sizeof(pids),
                    ctypes.byref(bytes_returned)
                )
                
                lsass_found = False
                for pid in pids[:bytes_returned.value // 4]:
                    if pid == 0:
                        continue
                    handle = kernel32.OpenProcess(0x0410, False, pid)
                    if handle:
                        name = (ctypes.c_char * 260)()
                        psapi.GetModuleBaseNameA(handle, None, name, 260)
                        kernel32.CloseHandle(handle)
                        
                        if name.value.lower() == b"lsass.exe":
                            lsass_found = True
                            findings.append(f"[LSASS] Found at PID: {pid}")
                            
                            # Try to open with memory read access
                            mem_handle = kernel32.OpenProcess(0x0010, False, pid)
                            if mem_handle:
                                kernel32.CloseHandle(mem_handle)
                                findings.append("[LSASS] Memory read access: GRANTED")
                            else:
                                findings.append("[LSASS] Memory read access: DENIED")
                                detected = True
                            break
                
                if not lsass_found:
                    findings.append("[LSASS] Process not found (may be protected)")
                    
            except Exception as e:
                findings.append(f"[LSASS] Enumeration error: {e}")
            
            # Test 3: DPAPI Master Keys Location
            try:
                dpapi_path = os.path.join(
                    os.environ.get("APPDATA", ""),
                    "..", "Local", "Microsoft", "Protect"
                )
                dpapi_path = os.path.normpath(dpapi_path)
                
                if os.path.exists(dpapi_path):
                    items = os.listdir(dpapi_path)
                    findings.append(f"[DPAPI] Master keys directory: {len(items)} SIDs found")
                else:
                    findings.append("[DPAPI] Protect directory not found")
            except PermissionError:
                findings.append("[DPAPI] BLOCKED: Access denied")
                detected = True
            except Exception as e:
                findings.append(f"[DPAPI] Error: {e}")
        
        elif IS_LINUX or IS_MACOS:
            # Linux/macOS Credential Tests
            findings.append(f"=== {'Linux' if IS_LINUX else 'macOS'} Credential Access ===")
            
            # Test 1: Shadow File Access
            try:
                with open("/etc/shadow", "r") as f:
                    lines = f.readlines()
                    findings.append(f"[SHADOW] Readable: {len(lines)} entries (root access)")
            except PermissionError:
                findings.append("[SHADOW] Access Denied (expected without root)")
            except FileNotFoundError:
                findings.append("[SHADOW] File not found")
            except Exception as e:
                findings.append(f"[SHADOW] Error: {e}")
            
            # Test 2: SSH Key Enumeration
            try:
                ssh_dir = os.path.expanduser("~/.ssh")
                if os.path.exists(ssh_dir):
                    keys = [f for f in os.listdir(ssh_dir) 
                            if f.startswith("id_") and not f.endswith(".pub")]
                    findings.append(f"[SSH] Private keys found: {len(keys)}")
                    for key in keys[:3]:  # Show first 3
                        findings.append(f"[SSH]   - {key}")
                else:
                    findings.append("[SSH] No .ssh directory")
            except PermissionError:
                findings.append("[SSH] BLOCKED: Access denied")
                detected = True
            except Exception as e:
                findings.append(f"[SSH] Error: {e}")
            
            # Test 3: Keyring/Wallet Access (Linux)
            if IS_LINUX:
                try:
                    keyring_path = os.path.expanduser("~/.local/share/keyrings")
                    if os.path.exists(keyring_path):
                        items = os.listdir(keyring_path)
                        findings.append(f"[KEYRING] Found: {len(items)} keyring files")
                    else:
                        findings.append("[KEYRING] No keyring directory")
                except Exception as e:
                    findings.append(f"[KEYRING] Error: {e}")
            
            # Test 4: Passwd file (should be readable)
            try:
                with open("/etc/passwd", "r") as f:
                    lines = f.readlines()
                    users = [l.split(":")[0] for l in lines if not l.startswith("#")]
                    findings.append(f"[PASSWD] {len(users)} user accounts")
            except Exception as e:
                findings.append(f"[PASSWD] Error: {e}")
        
        # Compile results
        result["details"] = "\n".join(findings)
        
        if detected:
            result["status"] = "detected"
            result["detection_info"] = "EDR blocked credential access attempt(s)"
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
