#!/usr/bin/env python3
# T004: Python Browser Stealer - MITRE T1059.006 + T1555.003

import sys
import os
import json
import shutil
import tempfile
import sqlite3
import platform

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

def get_chrome_path():
    """Get Chrome user data path based on OS."""
    if IS_WINDOWS:
        return os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Google", "Chrome", "User Data", "Default"
        )
    elif IS_LINUX:
        return os.path.expanduser("~/.config/google-chrome/Default")
    elif IS_MACOS:
        return os.path.expanduser(
            "~/Library/Application Support/Google/Chrome/Default"
        )
    return None

def get_firefox_path():
    """Get Firefox profiles path based on OS."""
    if IS_WINDOWS:
        return os.path.join(
            os.environ.get("APPDATA", ""),
            "Mozilla", "Firefox", "Profiles"
        )
    else:
        return os.path.expanduser("~/.mozilla/firefox")

def get_edge_path():
    """Get Edge user data path (Windows only)."""
    if IS_WINDOWS:
        return os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Microsoft", "Edge", "User Data", "Default"
        )
    return None

def run():
    result = {
        "status": "pending",
        "details": "",
        "detection_info": ""
    }
    
    findings = []
    detected = False
    
    try:
        findings.append(f"=== Browser Credential Access ({platform.system()}) ===")
        
        # Test 1: Chrome Credential Database
        chrome_path = get_chrome_path()
        if chrome_path and os.path.exists(chrome_path):
            login_data = os.path.join(chrome_path, "Login Data")
            
            if os.path.exists(login_data):
                tmp_fd, tmp_db = tempfile.mkstemp(suffix=".db",
                                                   prefix="testerpy2_chr_")
                os.close(tmp_fd)
                conn = None
                try:
                    # Copy database to temp (Chrome locks the file)
                    shutil.copy2(login_data, tmp_db)
                    conn = sqlite3.connect(tmp_db)
                    cursor = conn.cursor()

                    # Count stored credentials
                    cursor.execute("SELECT COUNT(*) FROM logins")
                    count = cursor.fetchone()[0]

                    # Get origin URLs (not passwords)
                    cursor.execute("SELECT origin_url FROM logins LIMIT 5")
                    urls = [row[0] for row in cursor.fetchall()]
                    conn.close()
                    conn = None

                    findings.append(f"[CHROME] Login Data accessible")
                    findings.append(f"[CHROME] Stored credentials: {count}")
                    if urls:
                        findings.append(f"[CHROME] Sample origins: {len(urls)} sites")

                except sqlite3.OperationalError as e:
                    if "locked" in str(e).lower():
                        findings.append("[CHROME] Database locked (browser running)")
                    else:
                        findings.append(f"[CHROME] BLOCKED: {e}")
                        detected = True
                except PermissionError:
                    findings.append(f"[CHROME] BLOCKED: Access denied")
                    detected = True
                except Exception as e:
                    findings.append(f"[CHROME] Error: {e}")
                finally:
                    if conn:
                        conn.close()
                    if os.path.exists(tmp_db):
                        os.remove(tmp_db)
            else:
                findings.append("[CHROME] Login Data not found")
        else:
            findings.append("[CHROME] Profile not found")
        
        # Test 2: Firefox Credential Database
        firefox_path = get_firefox_path()
        if firefox_path and os.path.exists(firefox_path):
            try:
                profiles = [d for d in os.listdir(firefox_path) 
                           if "default" in d.lower() and os.path.isdir(
                               os.path.join(firefox_path, d))]
                
                if profiles:
                    profile_path = os.path.join(firefox_path, profiles[0])
                    
                    # Check logins.json
                    logins_json = os.path.join(profile_path, "logins.json")
                    if os.path.exists(logins_json):
                        try:
                            with open(logins_json, "r") as f:
                                data = json.load(f)
                                logins = data.get("logins", [])
                                findings.append(f"[FIREFOX] logins.json accessible")
                                findings.append(f"[FIREFOX] Stored credentials: {len(logins)}")
                        except PermissionError:
                            findings.append("[FIREFOX] BLOCKED: Access denied")
                            detected = True
                        except Exception as e:
                            findings.append(f"[FIREFOX] logins.json error: {e}")
                    
                    # Check key4.db (master key database)
                    key_db = os.path.join(profile_path, "key4.db")
                    if os.path.exists(key_db):
                        findings.append("[FIREFOX] key4.db found (master key store)")
                    
                    # Check cookies.sqlite
                    cookies_db = os.path.join(profile_path, "cookies.sqlite")
                    if os.path.exists(cookies_db):
                        tmp_fd, tmp_db = tempfile.mkstemp(suffix=".db",
                                                           prefix="testerpy2_ff_")
                        os.close(tmp_fd)
                        conn = None
                        try:
                            shutil.copy2(cookies_db, tmp_db)
                            conn = sqlite3.connect(tmp_db)
                            count = conn.cursor().execute(
                                "SELECT COUNT(*) FROM moz_cookies"
                            ).fetchone()[0]
                            conn.close()
                            conn = None
                            findings.append(f"[FIREFOX] Cookies accessible: {count} cookies")
                        except Exception as e:
                            findings.append(f"[FIREFOX] Cookies error: {e}")
                        finally:
                            if conn:
                                conn.close()
                            if os.path.exists(tmp_db):
                                os.remove(tmp_db)
                else:
                    findings.append("[FIREFOX] No default profile found")
                    
            except PermissionError:
                findings.append("[FIREFOX] BLOCKED: Profiles access denied")
                detected = True
            except Exception as e:
                findings.append(f"[FIREFOX] Error: {e}")
        else:
            findings.append("[FIREFOX] Not installed or profile not found")
        
        # Test 3: Edge Credential Database (Windows)
        if IS_WINDOWS:
            edge_path = get_edge_path()
            if edge_path and os.path.exists(edge_path):
                login_data = os.path.join(edge_path, "Login Data")
                
                if os.path.exists(login_data):
                    tmp_fd, tmp_db = tempfile.mkstemp(suffix=".db",
                                                       prefix="testerpy2_edge_")
                    os.close(tmp_fd)
                    conn = None
                    try:
                        shutil.copy2(login_data, tmp_db)
                        conn = sqlite3.connect(tmp_db)
                        count = conn.cursor().execute(
                            "SELECT COUNT(*) FROM logins"
                        ).fetchone()[0]
                        conn.close()
                        conn = None

                        findings.append(f"[EDGE] Login Data accessible")
                        findings.append(f"[EDGE] Stored credentials: {count}")

                    except sqlite3.OperationalError as e:
                        if "locked" in str(e).lower():
                            findings.append("[EDGE] Database locked (browser running)")
                        else:
                            findings.append(f"[EDGE] Error: {e}")
                    except PermissionError:
                        findings.append("[EDGE] BLOCKED: Access denied")
                        detected = True
                    except Exception as e:
                        findings.append(f"[EDGE] Error: {e}")
                    finally:
                        if conn:
                            conn.close()
                        if os.path.exists(tmp_db):
                            os.remove(tmp_db)
                else:
                    findings.append("[EDGE] Login Data not found")
            else:
                findings.append("[EDGE] Profile not found")
        
        # Compile results
        result["details"] = "\n".join(findings)
        
        if detected:
            result["status"] = "detected"
            result["detection_info"] = "EDR blocked browser credential access"
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
