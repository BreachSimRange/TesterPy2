#!/usr/bin/env python3
# T002: Python Defense Evasion - MITRE T1059.006 + T1562.001

import sys
import os
import json
import platform

IS_WINDOWS = platform.system() == "Windows"

def run():
    result = {
        "status": "pending",
        "details": "",
        "detection_info": ""
    }
    
    if not IS_WINDOWS:
        result["status"] = "skipped"
        result["details"] = "Windows-only test - requires AMSI/ETW APIs"
        return result
    
    try:
        import ctypes
    except ImportError:
        result["status"] = "failed"
        result["details"] = "ctypes module not available"
        return result
    
    findings = []
    detected = False
    
    try:
        # Test 1: AMSI Bypass - Locate AmsiScanBuffer
        try:
            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            amsi_scan_buffer = ctypes.windll.kernel32.GetProcAddress(
                amsi._handle,
                b"AmsiScanBuffer"
            )
            if amsi_scan_buffer:
                findings.append(f"[AMSI] AmsiScanBuffer located at: 0x{amsi_scan_buffer:x}")
                findings.append("[AMSI] Bypass preparation successful")
            else:
                findings.append("[AMSI] AmsiScanBuffer not found")
        except OSError as e:
            if "denied" in str(e).lower():
                findings.append(f"[AMSI] BLOCKED: {e}")
                detected = True
            else:
                findings.append(f"[AMSI] Error: {e}")
        except Exception as e:
            findings.append(f"[AMSI] Exception: {e}")
        
        # Test 2: ETW Patching - Locate EtwEventWrite
        try:
            ntdll_handle = ctypes.windll.kernel32.GetModuleHandleW("ntdll.dll")
            etw_write = ctypes.windll.kernel32.GetProcAddress(
                ntdll_handle,
                b"EtwEventWrite"
            )
            if etw_write:
                findings.append(f"[ETW] EtwEventWrite located at: 0x{etw_write:x}")
                findings.append("[ETW] Patch preparation successful")
            else:
                findings.append("[ETW] EtwEventWrite not found")
        except Exception as e:
            findings.append(f"[ETW] Exception: {e}")
        
        # Test 3: Environment Variable Evasion
        try:
            os.environ["COMPLUS_ETWEnabled"] = "0"
            os.environ["COMPlus_ETWEnabled"] = "0"
            findings.append("[ENV] COMPLUS_ETWEnabled set to 0")
            findings.append("[ENV] COMPlus_ETWEnabled set to 0")
        except Exception as e:
            findings.append(f"[ENV] Error: {e}")
        
        # Test 4: Ntdll Unhooking Preparation - Read from disk
        try:
            ntdll_path = r"C:\Windows\System32\ntdll.dll"
            with open(ntdll_path, "rb") as f:
                header = f.read(4096)
                findings.append(f"[NTDLL] Read {len(header)} bytes from disk")
                findings.append("[NTDLL] Unhooking preparation possible")
        except PermissionError as e:
            findings.append(f"[NTDLL] BLOCKED: Access denied")
            detected = True
        except Exception as e:
            findings.append(f"[NTDLL] Error: {e}")
        
        # Test 5: Check for common EDR DLLs
        edr_dlls = ["pstorec.dll", "amsi.dll", "mso.dll"]
        loaded_edrs = []
        try:
            for dll in edr_dlls:
                try:
                    handle = ctypes.windll.kernel32.GetModuleHandleW(dll)
                    if handle:
                        loaded_edrs.append(dll)
                except:
                    pass
            if loaded_edrs:
                findings.append(f"[EDR] Detected DLLs: {', '.join(loaded_edrs)}")
            else:
                findings.append("[EDR] No common EDR DLLs detected")
        except Exception as e:
            findings.append(f"[EDR] Detection check error: {e}")
        
        # Compile results
        result["details"] = "\n".join(findings)
        
        if detected:
            result["status"] = "detected"
            result["detection_info"] = "EDR blocked evasion technique(s)"
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
