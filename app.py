#!/usr/bin/env python3
"""
TESTERPy2 - T1059.006 EDR/AV Testing Platform
A professional security testing dashboard focused on Python-based offensive techniques.

MITRE ATT&CK: T1059.006 - Command and Scripting Interpreter: Python
https://attack.mitre.org/techniques/T1059/006/

For authorized security testing only.
"""

import os
import json
import uuid
import base64
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Path to test files
TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tests')

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Agent:
    agent_id: str
    hostname: str
    platform: str
    python_version: str
    username: str
    ip_address: str
    first_seen: str
    last_seen: str
    status: str = "active"

@dataclass  
class TestResult:
    test_id: str
    agent_id: str
    test_name: str
    test_category: str
    mitre_id: str
    status: str  # pending, running, success, detected, failed, skipped
    start_time: str
    end_time: Optional[str] = None
    details: Optional[str] = None
    detection_info: Optional[str] = None

# ============================================================================
# IN-MEMORY STORAGE
# ============================================================================

agents: Dict[str, Agent] = {}
test_results: Dict[str, TestResult] = {}
pending_commands: Dict[str, List[dict]] = {}  # agent_id -> list of commands
agents_lock = threading.Lock()

# ============================================================================
# TEST DEFINITIONS - T1059.006 Python Techniques
# ============================================================================

# Mapping from test name to test file
TEST_FILES = {
    "shellcode_loader": "t001_shellcode_loader.py",
    "defense_evasion": "t002_defense_evasion.py",
    "credential_dumper": "t003_credential_dumper.py",
    "browser_stealer": "t004_browser_stealer.py",
    "discovery_collection": "t005_discovery_collection.py"
}

def load_test_code(test_name: str) -> Optional[str]:
    """Load test code from file and return as base64-encoded string."""
    if test_name not in TEST_FILES:
        logger.warning(f"Unknown test: {test_name}")
        return None
    
    test_file = os.path.join(TESTS_DIR, TEST_FILES[test_name])
    
    if not os.path.exists(test_file):
        logger.error(f"Test file not found: {test_file}")
        return None
    
    try:
        with open(test_file, 'r', encoding='utf-8') as f:
            code = f.read()
        return base64.b64encode(code.encode('utf-8')).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to load test file {test_file}: {e}")
        return None

TEST_SCENARIOS = {
    "shellcode_loader": {
        "id": "T001",
        "name": "Python Shellcode Loader",
        "description": "Tests EDR detection of Python-based shellcode injection using ctypes for memory allocation and execution. Emulates techniques used by APT29's SeaDuke and Donut framework.",
        "category": "Execution",
        "mitre_id": "T1059.006",
        "mitre_secondary": ["T1055.001", "T1106"],
        "platforms": ["windows"],
        "risk_level": "high",
        "test_file": "t001_shellcode_loader.py",
        "details": [
            "Allocates executable memory via VirtualAlloc",
            "Copies shellcode bytes to allocated region", 
            "Creates thread pointing to shellcode",
            "Shellcode: MessageBox (benign demonstration)"
        ],
        "detection_points": [
            "Python process calling VirtualAlloc with PAGE_EXECUTE_READWRITE",
            "CreateThread from Python with suspicious start address",
            "Memory region with RWX permissions"
        ]
    },
    "defense_evasion": {
        "id": "T002", 
        "name": "Python Defense Evasion",
        "description": "Tests EDR detection of Python-based security product tampering. Includes AMSI bypass, ETW patching, and API unhooking techniques used by sophisticated malware.",
        "category": "Defense Evasion",
        "mitre_id": "T1059.006",
        "mitre_secondary": ["T1562.001", "T1027"],
        "platforms": ["windows"],
        "risk_level": "critical",
        "test_file": "t002_defense_evasion.py",
        "details": [
            "AMSI bypass via AmsiScanBuffer patching",
            "ETW provider disabling",
            "Ntdll unhooking from disk",
            "Environment variable manipulation"
        ],
        "detection_points": [
            "Writes to amsi.dll memory",
            "ETW provider tampering",
            "Reading ntdll.dll from disk",
            "Suspicious ctypes usage patterns"
        ]
    },
    "credential_dumper": {
        "id": "T003",
        "name": "Python Credential Dumper", 
        "description": "Tests EDR detection of Python-based credential access. Emulates techniques from Mimikatz, LaZagne, and APT malware for extracting credentials from memory and registry.",
        "category": "Credential Access",
        "mitre_id": "T1059.006",
        "mitre_secondary": ["T1003.001", "T1003.002", "T1552.001"],
        "platforms": ["windows", "linux"],
        "risk_level": "critical",
        "test_file": "t003_credential_dumper.py",
        "details": [
            "SAM database extraction attempt",
            "LSA secrets enumeration",
            "DPAPI credential extraction",
            "Linux shadow file access attempt"
        ],
        "detection_points": [
            "Registry access to SAM/SECURITY hives",
            "LSASS memory access",
            "CryptUnprotectData calls",
            "/etc/shadow access from Python"
        ]
    },
    "browser_stealer": {
        "id": "T004",
        "name": "Python Browser Stealer",
        "description": "Tests EDR detection of Python-based browser data theft. Emulates CookieMiner, Lumma Stealer, and other infostealers targeting browser credentials and sessions.",
        "category": "Collection",
        "mitre_id": "T1059.006",
        "mitre_secondary": ["T1555.003", "T1539", "T1552.001"],
        "platforms": ["windows", "linux"],
        "risk_level": "high",
        "test_file": "t004_browser_stealer.py",
        "details": [
            "Chrome/Chromium Login Data extraction",
            "Firefox logins.json parsing",
            "Cookie database copying",
            "Browser history extraction"
        ],
        "detection_points": [
            "Access to browser profile directories",
            "SQLite operations on Login Data",
            "Copying Cookies database",
            "DPAPI decryption of browser secrets"
        ]
    },
    "discovery_collection": {
        "id": "T005",
        "name": "Python Discovery & Collection",
        "description": "Tests EDR detection of Python-based reconnaissance and data collection. Emulates techniques from Machete, PoetRAT, and InvisibleFerret for system enumeration and surveillance.",
        "category": "Discovery",
        "mitre_id": "T1059.006",
        "mitre_secondary": ["T1082", "T1083", "T1056.001", "T1113"],
        "platforms": ["windows", "linux"],
        "risk_level": "medium",
        "test_file": "t005_discovery_collection.py",
        "details": [
            "System information enumeration",
            "Network configuration discovery",
            "Process listing and analysis",
            "Screenshot capture",
            "Keylogger initialization"
        ],
        "detection_points": [
            "Bulk system enumeration commands",
            "Screenshot via Python imaging",
            "Keyboard hook installation",
            "Suspicious file system traversal"
        ]
    }
}

# ============================================================================
# API ROUTES - Agent Communication
# ============================================================================

@app.route('/api/agent/register', methods=['POST'])
def register_agent():
    """Agent registration endpoint"""
    data = request.json
    agent_id = data.get('agent_id') or str(uuid.uuid4())[:8]
    
    with agents_lock:
        agent = Agent(
            agent_id=agent_id,
            hostname=data.get('hostname', 'unknown'),
            platform=data.get('platform', 'unknown'),
            python_version=data.get('python_version', 'unknown'),
            username=data.get('username', 'unknown'),
            ip_address=request.remote_addr,
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            status="active"
        )
        agents[agent_id] = agent
        pending_commands[agent_id] = []
    
    logger.info(f"Agent registered: {agent_id} ({agent.hostname})")
    return jsonify({"status": "registered", "agent_id": agent_id})

@app.route('/api/agent/beacon', methods=['POST'])
def agent_beacon():
    """Agent check-in and command retrieval"""
    data = request.json
    agent_id = data.get('agent_id')
    
    if not agent_id or agent_id not in agents:
        return jsonify({"error": "Unknown agent"}), 404
    
    with agents_lock:
        agents[agent_id].last_seen = datetime.now().isoformat()
        agents[agent_id].status = "active"
        
        # Get pending commands
        commands = pending_commands.get(agent_id, [])
        pending_commands[agent_id] = []
    
    return jsonify({"commands": commands})

@app.route('/api/agent/result', methods=['POST'])
def submit_result():
    """Agent submits test results"""
    data = request.json
    test_id = data.get('test_id')
    
    if test_id and test_id in test_results:
        with agents_lock:
            result = test_results[test_id]
            result.status = data.get('status', 'completed')
            result.end_time = datetime.now().isoformat()
            result.details = data.get('details', '')
            result.detection_info = data.get('detection_info', '')
    
    return jsonify({"status": "received"})

# ============================================================================
# API ROUTES - Dashboard
# ============================================================================

@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get all registered agents"""
    with agents_lock:
        # Update status based on last seen
        now = datetime.now()
        for agent in agents.values():
            last_seen = datetime.fromisoformat(agent.last_seen)
            if (now - last_seen) > timedelta(minutes=2):
                agent.status = "inactive"
            elif (now - last_seen) > timedelta(seconds=30):
                agent.status = "stale"
        
        return jsonify([asdict(a) for a in agents.values()])

@app.route('/api/tests', methods=['GET'])
def get_tests():
    """Get available test scenarios"""
    return jsonify(TEST_SCENARIOS)

@app.route('/api/results', methods=['GET'])
def get_results():
    """Get all test results"""
    with agents_lock:
        return jsonify([asdict(r) for r in test_results.values()])

@app.route('/api/execute', methods=['POST'])
def execute_test():
    """Queue a test for execution on an agent"""
    data = request.json
    agent_id = data.get('agent_id')
    test_name = data.get('test_name')
    
    if not agent_id or agent_id not in agents:
        return jsonify({"error": "Invalid agent"}), 400
    
    if not test_name or test_name not in TEST_SCENARIOS:
        return jsonify({"error": "Invalid test"}), 400
    
    test_id = str(uuid.uuid4())[:12]
    test_info = TEST_SCENARIOS[test_name]
    
    # Load test code
    test_code_b64 = load_test_code(test_name)
    if not test_code_b64:
        return jsonify({"error": f"Failed to load test code for: {test_name}"}), 500
    
    # Create result record
    result = TestResult(
        test_id=test_id,
        agent_id=agent_id,
        test_name=test_info['name'],
        test_category=test_info['category'],
        mitre_id=test_info['mitre_id'],
        status="pending",
        start_time=datetime.now().isoformat()
    )
    
    with agents_lock:
        test_results[test_id] = result
        pending_commands[agent_id].append({
            "type": "execute_test",
            "test_id": test_id,
            "test_name": test_name,
            "test_code_b64": test_code_b64,
            "timeout": 60
        })
    
    logger.info(f"Test queued: {test_name} for agent {agent_id}")
    return jsonify({"status": "queued", "test_id": test_id})

@app.route('/api/execute_all', methods=['POST'])
def execute_all_tests():
    """Execute all tests on an agent"""
    data = request.json
    agent_id = data.get('agent_id')
    
    if not agent_id or agent_id not in agents:
        return jsonify({"error": "Invalid agent"}), 400
    
    test_ids = []
    errors = []
    
    for test_name, test_info in TEST_SCENARIOS.items():
        test_id = str(uuid.uuid4())[:12]
        
        # Load test code
        test_code_b64 = load_test_code(test_name)
        if not test_code_b64:
            errors.append(f"Failed to load: {test_name}")
            continue
        
        result = TestResult(
            test_id=test_id,
            agent_id=agent_id,
            test_name=test_info['name'],
            test_category=test_info['category'],
            mitre_id=test_info['mitre_id'],
            status="pending",
            start_time=datetime.now().isoformat()
        )
        
        with agents_lock:
            test_results[test_id] = result
            pending_commands[agent_id].append({
                "type": "execute_test",
                "test_id": test_id,
                "test_name": test_name,
                "test_code_b64": test_code_b64,
                "timeout": 60
            })
        
        test_ids.append(test_id)
    
    response = {"status": "queued", "test_ids": test_ids}
    if errors:
        response["errors"] = errors
    
    return jsonify(response)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    with agents_lock:
        total_agents = len(agents)
        active_agents = sum(1 for a in agents.values() if a.status == "active")
        
        total_tests = len(test_results)
        successful = sum(1 for r in test_results.values() if r.status == "success")
        detected = sum(1 for r in test_results.values() if r.status == "detected")
        failed = sum(1 for r in test_results.values() if r.status == "failed")
        pending = sum(1 for r in test_results.values() if r.status in ["pending", "running"])
        
        return jsonify({
            "agents": {"total": total_agents, "active": active_agents},
            "tests": {
                "total": total_tests,
                "success": successful,
                "detected": detected,
                "failed": failed,
                "pending": pending
            }
        })

# ============================================================================
# WEB ROUTES
# ============================================================================

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html', tests=TEST_SCENARIOS)

@app.route('/technique')
def technique_info():
    """T1059.006 Technique documentation"""
    return render_template('technique.html')

@app.route('/technique/<test_name>')
def technique_detail(test_name):
    """Individual technique detail pages"""
    template_map = {
        'shellcode_loader': 'technique_shellcode_loader.html',
        'defense_evasion': 'technique_defense_evasion.html',
        'credential_dumper': 'technique_credential_dumper.html',
        'browser_stealer': 'technique_browser_stealer.html',
        'discovery_collection': 'technique_discovery_collection.html'
    }
    
    if test_name in template_map:
        # Load the test code from file
        test_code = ""
        if test_name in TEST_FILES:
            test_file = os.path.join(TESTS_DIR, TEST_FILES[test_name])
            if os.path.exists(test_file):
                try:
                    with open(test_file, 'r', encoding='utf-8') as f:
                        test_code = f.read()
                except Exception as e:
                    logger.error(f"Failed to read test file: {e}")
        
        return render_template(template_map[test_name], test_code=test_code)
    else:
        return render_template('technique.html')

@app.route('/agents')
def agents_page():
    """Connected agents page"""
    return render_template('agents.html')

@app.route('/results')
def results_page():
    """Test results page"""
    return render_template('results.html')

@app.route('/about')
def about_page():
    """About page"""
    return render_template('about.html')

@app.route('/tests')
def tests_page():
    """Run tests page"""
    return render_template('tests.html')

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ████████╗███████╗███████╗████████╗███████╗██████╗                       ║
    ║   ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗                      ║
    ║      ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝                      ║
    ║      ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗                      ║
    ║      ██║   ███████╗███████║   ██║   ███████╗██║  ██║                      ║
    ║      ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                      ║
    ║                                                                           ║
    ║   ██████╗ ██╗   ██╗██████╗     T1059.006 Security Testing Platform        ║
    ║   ██╔══██╗╚██╗ ██╔╝╚════██╗    Python-Based EDR/AV Validation             ║
    ║   ██████╔╝ ╚████╔╝  █████╔╝                                               ║
    ║   ██╔═══╝   ╚██╔╝  ██╔═══╝     For authorized security testing only       ║
    ║   ██║        ██║   ███████╗                                               ║
    ║   ╚═╝        ╚═╝   ╚══════╝                                               ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """)
    print(f"  [*] Dashboard: http://127.0.0.1:5000")
    print(f"  [*] API Base:  http://127.0.0.1:5000/api")
    print(f"  [*] Waiting for agent connections...\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
