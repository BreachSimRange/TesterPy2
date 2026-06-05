#!/usr/bin/env python3
# T001: Python Shellcode Loader - MITRE T1059.006 + T1055.001

import sys
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
        result["details"] = "Windows-only test - requires VirtualAlloc/CreateThread"
        return result
    
    try:
        import ctypes
    except ImportError:
        result["status"] = "failed"
        result["details"] = "ctypes module not available"
        return result
    
    try:
        # Benign shellcode: NOP sled + xor eax,eax + ret
        # This does nothing harmful - just returns cleanly
        shellcode = b"\x90" * 16 + b"\x31\xc0" + b"\xc3"
        
        kernel32 = ctypes.windll.kernel32
        
        # Memory allocation constants
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        MEM_RELEASE = 0x8000
        
        # Step 1: Allocate executable memory
        ptr = kernel32.VirtualAlloc(
            ctypes.c_void_p(0),
            len(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        
        if not ptr:
            result["status"] = "failed"
            result["details"] = "VirtualAlloc failed - could not allocate memory"
            return result
        
        # Step 2: Copy shellcode to allocated memory
        ctypes.memmove(ptr, shellcode, len(shellcode))
        
        # Step 3: Create thread to execute shellcode
        thread_id = ctypes.c_ulong(0)
        thread_handle = kernel32.CreateThread(
            ctypes.c_void_p(0),      # lpThreadAttributes
            0,                        # dwStackSize
            ctypes.c_void_p(ptr),    # lpStartAddress
            ctypes.c_void_p(0),      # lpParameter
            0,                        # dwCreationFlags
            ctypes.byref(thread_id)
        )
        
        if thread_handle:
            # Step 4: Wait for execution and cleanup
            kernel32.WaitForSingleObject(thread_handle, 1000)
            kernel32.CloseHandle(thread_handle)
            kernel32.VirtualFree(ctypes.c_void_p(ptr), 0, MEM_RELEASE)
            
            result["status"] = "success"
            result["details"] = f"Shellcode executed successfully\nMemory address: 0x{ptr:x}\nThread ID: {thread_id.value}\nShellcode size: {len(shellcode)} bytes"
        else:
            kernel32.VirtualFree(ctypes.c_void_p(ptr), 0, MEM_RELEASE)
            result["status"] = "detected"
            result["details"] = "CreateThread was blocked"
            result["detection_info"] = "EDR blocked thread creation from allocated memory"
            
    except OSError as e:
        if "denied" in str(e).lower() or "access" in str(e).lower():
            result["status"] = "detected"
            result["details"] = f"Operation blocked: {e}"
            result["detection_info"] = "EDR blocked memory operation"
        else:
            result["status"] = "failed"
            result["details"] = f"OS Error: {e}"
    except Exception as e:
        result["status"] = "failed"
        result["details"] = f"Unexpected error: {e}"
    
    return result


if __name__ == "__main__":
    # Execute and output JSON result
    result = run()
    print(json.dumps(result))
    sys.exit(0 if result["status"] in ["success", "detected", "skipped"] else 1)
