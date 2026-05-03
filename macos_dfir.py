#!/usr/bin/env python3
"""
Mac OS Digital Forensics Artifact Collector & MITRE ATT&CK Mapper
Author: DFIR Expert
Purpose: Collect forensic artifacts from macOS, parse them, map to MITRE ATT&CK, export CSV
"""

import os
import sys
import json
import csv
import hashlib
import sqlite3
import plistlib
import subprocess
import datetime
import re
import glob
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# MITRE ATT&CK Mapping for macOS
MITRE_TECHNIQUES = {
    # Initial Access
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access", "platforms": ["macOS"]},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access", "platforms": ["macOS"]},
    "T1078.001": {"name": "Valid Accounts: Default Accounts", "tactic": "Initial Access", "platforms": ["macOS"]},
    
    # Execution
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution", "platforms": ["macOS"]},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution", "platforms": ["macOS"]},
    "T1553.001": {"name": "Gatekeeper Bypass", "tactic": "Execution", "platforms": ["macOS"]},
    "T1204.002": {"name": "Malicious File", "tactic": "Execution", "platforms": ["macOS"]},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control", "platforms": ["macOS"]},
    
    # Persistence
    "T1543.001": {"name": "Launch Agent", "tactic": "Persistence", "platforms": ["macOS"]},
    "T1543.004": {"name": "Launch Daemon", "tactic": "Persistence", "platforms": ["macOS"]},
    "T1547.007": {"name": "Re-opened Applications", "tactic": "Persistence", "platforms": ["macOS"]},
    "T1547.011": {"name": "Plist Modification", "tactic": "Persistence", "platforms": ["macOS"]},
    "T1546.001": {"name": "Change Default File Association", "tactic": "Persistence", "platforms": ["macOS"]},
    "T1136.001": {"name": "Local Account Creation", "tactic": "Persistence", "platforms": ["macOS"]},
    "T1078.003": {"name": "Valid Accounts: Local Accounts", "tactic": "Persistence", "platforms": ["macOS"]},
    
    # Privilege Escalation
    "T1548.001": {"name": "Setuid and Setgid", "tactic": "Privilege Escalation", "platforms": ["macOS"]},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "platforms": ["macOS"]},
    "T1078.003": {"name": "Valid Accounts: Local Accounts", "tactic": "Privilege Escalation", "platforms": ["macOS"]},
    "T1053.003": {"name": "Cron", "tactic": "Privilege Escalation", "platforms": ["macOS"]},
    "T1037.002": {"name": "Login Hook", "tactic": "Privilege Escalation", "platforms": ["macOS"]},
    
    # Defense Evasion
    "T1070.002": {"name": "Clear Linux or Mac System Logs", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1070.003": {"name": "Clear Command History", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1070.006": {"name": "Timestomp", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1027.002": {"name": "Obfuscated Files or Information: Software Packing", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1553.001": {"name": "Gatekeeper Bypass", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1564.001": {"name": "Hidden Files and Directories", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1564.002": {"name": "Hidden Users", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    "T1222.002": {"name": "Linux and Mac File and Directory Permissions Modification", "tactic": "Defense Evasion", "platforms": ["macOS"]},
    
    # Credential Access
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access", "platforms": ["macOS"]},
    "T1555.001": {"name": "Keychain", "tactic": "Credential Access", "platforms": ["macOS"]},
    "T1003.008": {"name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactic": "Credential Access", "platforms": ["macOS"]},
    "T1056.001": {"name": "Keylogging", "tactic": "Credential Access", "platforms": ["macOS"]},
    "T1557.001": {"name": "LLMNR/NBT-NS Poisoning and SMB Relay", "tactic": "Credential Access", "platforms": ["macOS"]},
    
    # Discovery
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1087.001": {"name": "Local Account", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1010": {"name": "Application Window Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1012": {"name": "Query Registry", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1518.001": {"name": "Security Software Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1497.001": {"name": "System Checks", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery", "platforms": ["macOS"]},
    "T1046": {"name": "Network Service Scanning", "tactic": "Discovery", "platforms": ["macOS"]},
    
    # Lateral Movement
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement", "platforms": ["macOS"]},
    "T1021.005": {"name": "VNC", "tactic": "Lateral Movement", "platforms": ["macOS"]},
    "T1021.007": {"name": "Windows Remote Management", "tactic": "Lateral Movement", "platforms": ["macOS"]},
    "T1550.002": {"name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "Lateral Movement", "platforms": ["macOS"]},
    
    # Collection
    "T1560.001": {"name": "Archive via Utility", "tactic": "Collection", "platforms": ["macOS"]},
    "T1125": {"name": "Video Capture", "tactic": "Collection", "platforms": ["macOS"]},
    "T1113": {"name": "Screen Capture", "tactic": "Collection", "platforms": ["macOS"]},
    "T1115": {"name": "Clipboard Data", "tactic": "Collection", "platforms": ["macOS"]},
    "T1056.001": {"name": "Keylogging", "tactic": "Collection", "platforms": ["macOS"]},
    "T1005": {"name": "Data from Local System", "tactic": "Collection", "platforms": ["macOS"]},
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "Collection", "platforms": ["macOS"]},
    "T1074.001": {"name": "Local Data Staging", "tactic": "Collection", "platforms": ["macOS"]},
    
    # Command and Control
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1071.004": {"name": "Application Layer Protocol: DNS", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1573.002": {"name": "Asymmetric Cryptography", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1090.001": {"name": "Internal Proxy", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1090.003": {"name": "Multi-hop Proxy", "tactic": "Command and Control", "platforms": ["macOS"]},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control", "platforms": ["macOS"]},
    
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "platforms": ["macOS"]},
    "T1048.001": {"name": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration", "platforms": ["macOS"]},
    "T1048.003": {"name": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol", "tactic": "Exfiltration", "platforms": ["macOS"]},
    "T1567.002": {"name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration", "platforms": ["macOS"]},
    "T1020": {"name": "Automated Exfiltration", "tactic": "Exfiltration", "platforms": ["macOS"]},
    "T1030": {"name": "Data Transfer Size Limits", "tactic": "Exfiltration", "platforms": ["macOS"]},
    
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "platforms": ["macOS"]},
    "T1491.001": {"name": "Defacement: Internal Defacement", "tactic": "Impact", "platforms": ["macOS"]},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "platforms": ["macOS"]},
    "T1529": {"name": "System Shutdown/Reboot", "tactic": "Impact", "platforms": ["macOS"]},
}

@dataclass
class ForensicArtifact:
    """Represents a collected forensic artifact"""
    artifact_type: str
    source_path: str
    description: str
    timestamp: str
    data: Dict[str, Any]
    mitre_techniques: List[str]
    risk_score: int  # 0-100
    raw_content: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "artifact_type": self.artifact_type,
            "source_path": self.source_path,
            "description": self.description,
            "timestamp": self.timestamp,
            "data": json.dumps(self.data),
            "mitre_techniques": ";".join(self.mitre_techniques),
            "risk_score": self.risk_score,
            "raw_content": self.raw_content[:1000]  # Truncate for CSV
        }

class MacOSForensicCollector:
    """Main class for collecting and analyzing macOS forensic artifacts"""
    
    def __init__(self, output_dir: str = "./forensics_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts: List[ForensicArtifact] = []
        self.system_info = self._get_system_info()
        
    def _get_system_info(self) -> Dict:
        """Gather basic system information"""
        info = {
            "hostname": subprocess.getoutput("scutil --get ComputerName"),
            "os_version": subprocess.getoutput("sw_vers -productVersion"),
            "build_version": subprocess.getoutput("sw_vers -buildVersion"),
            "hardware_uuid": subprocess.getoutput("system_profiler SPHardwareDataType | grep UUID | awk '{print $3}'"),
            "current_user": os.getenv("USER"),
            "collection_time": datetime.datetime.now().isoformat(),
            "serial_number": subprocess.getoutput("system_profiler SPHardwareDataType | grep 'Serial Number' | awk '{print $4}'")
        }
        return info
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def _parse_plist(self, plist_path: str) -> Optional[Dict]:
        """Parse Apple plist file"""
        try:
            with open(plist_path, 'rb') as f:
                return plistlib.load(f)
        except Exception as e:
            return None
    
    def _run_command(self, cmd: str, timeout: int = 30) -> str:
        """Execute shell command safely"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def _add_artifact(self, artifact: ForensicArtifact):
        """Add artifact to collection"""
        self.artifacts.append(artifact)
        print(f"[+] Collected: {artifact.artifact_type} - {artifact.description} (Risk: {artifact.risk_score})")
    
    # ==================== COLLECTION METHODS ====================
    
    def collect_launch_agents_daemons(self):
        """Collect LaunchAgents and LaunchDaemons (T1543.001, T1543.004)"""
        paths = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
            os.path.expanduser("~/Library/LaunchAgents"),
            os.path.expanduser("~/Library/LaunchDaemons")
        ]
        
        for base_path in paths:
            if not os.path.exists(base_path):
                continue
                
            for plist_file in glob.glob(os.path.join(base_path, "*.plist")):
                try:
                    plist_data = self._parse_plist(plist_file)
                    if not plist_data:
                        continue
                    
                    # Check for suspicious indicators
                    risk_score = 0
                    suspicious_indicators = []
                    
                    program = plist_data.get("Program", "")
                    program_args = plist_data.get("ProgramArguments", [])
                    run_at_load = plist_data.get("RunAtLoad", False)
                    keep_alive = plist_data.get("KeepAlive", False)
                    watch_paths = plist_data.get("WatchPaths", [])
                    start_interval = plist_data.get("StartInterval", 0)
                    
                    # Analyze program path
                    full_program = program if program else (program_args[0] if program_args else "")
                    
                    if full_program:
                        if any(x in full_program.lower() for x in ['/tmp/', '/var/tmp/', '/Users/Shared/', 'python', 'bash', 'sh', 'curl', 'wget']):
                            risk_score += 30
                            suspicious_indicators.append("Suspicious program path")
                        
                        if not os.path.exists(full_program) and not full_program.startswith('/System/'):
                            risk_score += 20
                            suspicious_indicators.append("Program does not exist")
                    
                    # Check for persistence mechanisms
                    if run_at_load:
                        risk_score += 10
                    if keep_alive:
                        risk_score += 10
                    if start_interval and start_interval < 300:  # Less than 5 minutes
                        risk_score += 15
                        suspicious_indicators.append("Frequent execution interval")
                    
                    # Check for hidden execution
                    if 'nice' in str(program_args).lower() or 'nohup' in str(program_args).lower():
                        risk_score += 10
                        suspicious_indicators.append("Process hiding techniques")
                    
                    # Determine MITRE techniques
                    mitre_techs = []
                    if "LaunchAgents" in plist_file:
                        mitre_techs.append("T1543.001")
                    else:
                        mitre_techs.append("T1543.004")
                    
                    if suspicious_indicators:
                        mitre_techs.append("T1547.011")  # Plist modification
                    
                    artifact = ForensicArtifact(
                        artifact_type="Persistence_LaunchItem",
                        source_path=plist_file,
                        description=f"{'Suspicious ' if suspicious_indicators else ''}LaunchAgent/Daemon: {os.path.basename(plist_file)}",
                        timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(plist_file)).isoformat(),
                        data={
                            "program": full_program,
                            "program_arguments": program_args,
                            "run_at_load": run_at_load,
                            "keep_alive": keep_alive,
                            "start_interval": start_interval,
                            "watch_paths": watch_paths,
                            "suspicious_indicators": suspicious_indicators,
                            "plist_hash": self._calculate_file_hash(plist_file)
                        },
                        mitre_techniques=mitre_techs,
                        risk_score=min(risk_score, 100),
                        raw_content=str(plist_data)
                    )
                    self._add_artifact(artifact)
                    
                except Exception as e:
                    print(f"[!] Error processing {plist_file}: {e}")
    
    def collect_login_items(self):
        """Collect Login Items (T1547.007)"""
        # Check user login items
        cmd = 'osascript -e \'tell application "System Events" to get the name of every login item\' 2>/dev/null'
        result = self._run_command(cmd)
        
        if result and "ERROR" not in result:
            items = [item.strip() for item in result.split(',') if item.strip()]
            for item in items:
                artifact = ForensicArtifact(
                    artifact_type="Persistence_LoginItem",
                    source_path="System Events",
                    description=f"Login Item: {item}",
                    timestamp=datetime.datetime.now().isoformat(),
                    data={"name": item, "type": "User Login Item"},
                    mitre_techniques=["T1547.007"],
                    risk_score=20,
                    raw_content=result
                )
                self._add_artifact(artifact)
        
        # Check Background Task Management (macOS 13+)
        btm_path = "/private/var/db/com.apple.backgroundtaskmanagement/BackgroundTaskManagementAgentData.sqlite"
        if os.path.exists(btm_path):
            try:
                conn = sqlite3.connect(btm_path)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT a.item_id, a.executable_path, a.executable_mod_time, b.is_executable 
                    FROM access a 
                    LEFT JOIN access_state b ON a.item_id = b.item_id
                """)
                
                for row in cursor.fetchall():
                    item_id, exec_path, mod_time, is_exec = row
                    risk_score = 30 if is_exec else 10
                    
                    artifact = ForensicArtifact(
                        artifact_type="Persistence_BackgroundTask",
                        source_path=btm_path,
                        description=f"Background Task: {exec_path}",
                        timestamp=datetime.datetime.fromtimestamp(mod_time).isoformat() if mod_time else "Unknown",
                        data={
                            "item_id": item_id,
                            "executable_path": exec_path,
                            "is_executable": bool(is_exec),
                            "database_path": btm_path
                        },
                        mitre_techniques=["T1543.001", "T1547.007"],
                        risk_score=risk_score,
                        raw_content=str(row)
                    )
                    self._add_artifact(artifact)
                conn.close()
            except Exception as e:
                print(f"[!] Error reading BTM database: {e}")
    
    def collect_cron_jobs(self):
        """Collect Cron jobs (T1053.003)"""
        cron_paths = [
            "/etc/crontab",
            "/var/at/tabs/",
            "/usr/lib/cron/tabs/",
            "/private/var/at/tabs/"
        ]
        
        # System crontab
        if os.path.exists("/etc/crontab"):
            with open("/etc/crontab", 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        risk_score = 40 if any(x in line.lower() for x in ['curl', 'wget', 'bash', 'sh', 'python', 'tmp']) else 20
                        
                        artifact = ForensicArtifact(
                            artifact_type="Persistence_Cron",
                            source_path="/etc/crontab",
                            description=f"System Cron: {line[:80]}",
                            timestamp=datetime.datetime.fromtimestamp(os.path.getmtime("/etc/crontab")).isoformat(),
                            data={"cron_entry": line, "type": "system"},
                            mitre_techniques=["T1053.003"],
                            risk_score=risk_score,
                            raw_content=line
                        )
                        self._add_artifact(artifact)
        
        # User crontabs
        for cron_dir in ["/var/at/tabs/", "/usr/lib/cron/tabs/", "/private/var/at/tabs/"]:
            if os.path.exists(cron_dir):
                for cron_file in glob.glob(os.path.join(cron_dir, "*")):
                    try:
                        with open(cron_file, 'r') as f:
                            content = f.read()
                            user = os.path.basename(cron_file)
                            
                            for line in content.split('\n'):
                                if line.strip() and not line.startswith('#'):
                                    risk_score = 40 if any(x in line.lower() for x in ['curl', 'wget', 'bash', 'sh', 'python', 'tmp']) else 20
                                    
                                    artifact = ForensicArtifact(
                                        artifact_type="Persistence_Cron",
                                        source_path=cron_file,
                                        description=f"User Cron ({user}): {line[:80]}",
                                        timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(cron_file)).isoformat(),
                                        data={"cron_entry": line, "user": user, "type": "user"},
                                        mitre_techniques=["T1053.003"],
                                        risk_score=risk_score,
                                        raw_content=line
                                    )
                                    self._add_artifact(artifact)
                    except Exception as e:
                        print(f"[!] Error reading cron file {cron_file}: {e}")
    
    def collect_bash_history(self):
        """Collect Shell history files (T1070.003)"""
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.sh_history"),
            "/root/.bash_history",
            "/var/root/.bash_history"
        ]
        
        # Also check all users
        try:
            users = os.listdir("/Users/")
            for user in users:
                if user not in ['Shared', 'Guest']:
                    for shell in ['bash', 'zsh', 'sh']:
                        hist_path = f"/Users/{user}/.{shell}_history"
                        if os.path.exists(hist_path):
                            history_files.append(hist_path)
        except:
            pass
        
        for hist_file in history_files:
            if os.path.exists(hist_file):
                try:
                    with open(hist_file, 'r', errors='ignore') as f:
                        lines = f.readlines()
                    
                    suspicious_commands = [
                        'curl', 'wget', 'nc ', 'netcat', 'bash -i', 'sh -i', 'python -c', 
                        'pty.spawn', 'socket', 'connect', 'exec', 'eval', 'base64', 
                        'openssl', 'chmod +x', 'chmod 777', 'sudo', 'su -', 'passwd',
                        'defaults write', 'launchctl', 'plutil', 'sqlite3', 'mdfind',
                        'screencapture', 'osascript', 'do shell script', 'dd if=',
                        'mkfifo', '/dev/tcp/', '/dev/udp/', '.bash_profile', '.zshrc'
                    ]
                    
                    for i, line in enumerate(lines[-500:]):  # Last 500 commands
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Check for suspicious commands
                        found_suspicious = [cmd for cmd in suspicious_commands if cmd in line.lower()]
                        
                        if found_suspicious:
                            risk_score = min(30 + (len(found_suspicious) * 10), 90)
                            
                            # Check for potential credential access
                            if any(x in line for x in ['password', 'keychain', 'security find', 'dump']):
                                mitre_techs = ["T1070.003", "T1552.001", "T1555.001"]
                                risk_score += 10
                            else:
                                mitre_techs = ["T1070.003", "T1059.004"]
                            
                            artifact = ForensicArtifact(
                                artifact_type="Execution_ShellHistory",
                                source_path=hist_file,
                                description=f"Suspicious command: {line[:100]}",
                                timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(hist_file)).isoformat(),
                                data={
                                    "command": line,
                                    "suspicious_indicators": found_suspicious,
                                    "user": os.path.basename(os.path.dirname(hist_file)),
                                    "shell": os.path.basename(hist_file).replace('_history', '').replace('.', '')
                                },
                                mitre_techniques=mitre_techs,
                                risk_score=risk_score,
                                raw_content=line
                            )
                            self._add_artifact(artifact)
                            
                except Exception as e:
                    print(f"[!] Error reading history {hist_file}: {e}")
    
    def collect_system_logs(self):
        """Collect Unified Logs (T1070.002)"""
        # Collect last 24 hours of interesting log entries
        time_range = "1d"
        
        log_queries = [
            ("show process launches", "process == 'launchd' AND eventMessage CONTAINS 'exec'", ["T1543.001", "T1543.004"]),
            ("sudo usage", "process == 'sudo'", ["T1548.003", "T1078.003"]),
            ("authentication events", "process == 'loginwindow' OR process == 'authd'", ["T1078.001", "T1078.003"]),
            ("file modifications", "process == 'kernel' AND eventMessage CONTAINS 'modif'", ["T1070.006"]),
            ("network connections", "process == 'kernel' AND eventMessage CONTAINS 'socket'", ["T1049", "T1071.001"]),
            ("gatekeeper events", "process == 'syspolicyd'", ["T1553.001"]),
            ("quarantine events", "process == 'quarantine'", ["T1553.001", "T1204.002"]),
        ]
        
        for desc, predicate, mitre_techs in log_queries:
            cmd = f"log show --predicate '{predicate}' --last {time_range} --style compact 2>/dev/null | head -100"
            result = self._run_command(cmd, timeout=60)
            
            if result and len(result) > 50:
                lines = result.strip().split('\n')
                for line in lines[:20]:  # Limit entries per category
                    if line.strip():
                        artifact = ForensicArtifact(
                            artifact_type="Log_Entry",
                            source_path="Unified Log",
                            description=f"{desc}: {line[:150]}",
                            timestamp=datetime.datetime.now().isoformat(),
                            data={
                                "log_type": desc,
                                "predicate": predicate,
                                "entry": line
                            },
                            mitre_techniques=mitre_techs,
                            risk_score=25,
                            raw_content=line
                        )
                        self._add_artifact(artifact)
    
    def collect_quarantine_data(self):
        """Collect Quarantine database (T1553.001, T1204.002)"""
        quarantine_db = os.path.expanduser("~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        
        if not os.path.exists(quarantine_db):
            quarantine_db = os.path.expanduser("~/Library/Preferences/com.apple.LaunchServices.QuarantineEvents")
        
        if os.path.exists(quarantine_db):
            try:
                conn = sqlite3.connect(quarantine_db)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 100")
                
                columns = [description[0] for description in cursor.description]
                
                for row in cursor.fetchall():
                    data = dict(zip(columns, row))
                    
                    # Calculate risk based on quarantine data
                    risk_score = 10
                    suspicious_indicators = []
                    
                    # Check for suspicious download sources
                    agent = data.get('LSQuarantineAgentBundleIdentifier', '')
                    url = data.get('LSQuarantineOriginURLString', '')
                    data_url = data.get('LSQuarantineDataURLString', '')
                    
                    if url:
                        if any(x in url.lower() for x in ['.zip', '.dmg', '.pkg', '.app']):
                            risk_score += 10
                        if any(x in url.lower() for x in ['http:', 'https:']):
                            risk_score += 5
                    
                    # Check for suspicious applications
                    if agent:
                        if any(x in agent.lower() for x in ['torrent', 'curl', 'wget', 'python', 'java']):
                            risk_score += 20
                            suspicious_indicators.append("Suspicious download agent")
                    
                    artifact = ForensicArtifact(
                        artifact_type="Evidence_Quarantine",
                        source_path=quarantine_db,
                        description=f"Quarantine: {data.get('LSQuarantineOriginURLString', 'Unknown')[:80]}",
                        timestamp=datetime.datetime.now().isoformat(),
                        data={
                            "quarantine_data": data,
                            "suspicious_indicators": suspicious_indicators
                        },
                        mitre_techniques=["T1553.001", "T1204.002", "T1566.001", "T1566.002"],
                        risk_score=min(risk_score, 80),
                        raw_content=str(data)
                    )
                    self._add_artifact(artifact)
                
                conn.close()
            except Exception as e:
                print(f"[!] Error reading quarantine database: {e}")
    
    def collect_browser_data(self):
        """Collect browser history and downloads (T1071.001, T1567.002)"""
        browsers = {
            "Safari": os.path.expanduser("~/Library/Safari/History.db"),
            "Chrome": os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History"),
            "Firefox": os.path.expanduser("~/Library/Application Support/Firefox/Profiles/*/places.sqlite")
        }
        
        for browser_name, db_path in browsers.items():
            if not os.path.exists(db_path):
                # Try wildcard for Firefox
                if '*' in db_path:
                    matches = glob.glob(db_path)
                    if matches:
                        db_path = matches[0]
                    else:
                        continue
                else:
                    continue
            
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                if browser_name == "Safari":
                    cursor.execute("""
                        SELECT hi.visit_time, hi.title, hi.url, hv.visit_count 
                        FROM history_items hi 
                        JOIN history_visits hv ON hi.id = hv.history_item 
                        ORDER BY hi.visit_time DESC LIMIT 50
                    """)
                    
                    for row in cursor.fetchall():
                        visit_time, title, url, count = row
                        
                        # Check for suspicious URLs
                        risk_score = 0
                        suspicious = []
                        
                        if url:
                            if any(x in url.lower() for x in ['pastebin', 'github.com/raw', 'transfer.sh', 'file.io']):
                                risk_score += 30
                                suspicious.append("Potential data exfiltration service")
                            if any(x in url.lower() for x in ['.exe', '.dll', '.bat', '.ps1', '.sh']):
                                risk_score += 20
                                suspicious.append("Executable download")
                            if any(x in url.lower() for x in ['phishing', 'malware', 'hack', 'crack']):
                                risk_score += 40
                                suspicious.append("Suspicious keyword")
                        
                        if risk_score > 0:
                            artifact = ForensicArtifact(
                                artifact_type="Network_BrowserHistory",
                                source_path=db_path,
                                description=f"Suspicious {browser_name} visit: {url[:80]}",
                                timestamp=datetime.datetime.now().isoformat(),
                                data={
                                    "browser": browser_name,
                                    "url": url,
                                    "title": title,
                                    "visit_count": count,
                                    "suspicious_indicators": suspicious
                                },
                                mitre_techniques=["T1071.001", "T1567.002", "T1566.002"],
                                risk_score=min(risk_score, 90),
                                raw_content=url
                            )
                            self._add_artifact(artifact)
                
                elif browser_name == "Chrome":
                    cursor.execute("""
                        SELECT urls.url, urls.title, urls.visit_count, urls.last_visit_time,
                               downloads.url as download_url, downloads.received_bytes
                        FROM urls 
                        LEFT JOIN downloads ON urls.url = downloads.tab_url
                        ORDER BY urls.last_visit_time DESC LIMIT 50
                    """)
                    
                    for row in cursor.fetchall():
                        url, title, count, last_visit, download_url, received_bytes = row
                        
                        risk_score = 0
                        suspicious = []
                        
                        if download_url:
                            risk_score += 15
                            suspicious.append("File download")
                            if received_bytes and received_bytes > 10000000:  # > 10MB
                                risk_score += 10
                                suspicious.append("Large file download")
                        
                        if url and any(x in url.lower() for x in ['pastebin', 'transfer.sh', 'file.io', 'mega.nz']):
                            risk_score += 30
                            suspicious.append("Potential exfiltration")
                        
                        if risk_score > 15:
                            artifact = ForensicArtifact(
                                artifact_type="Network_BrowserActivity",
                                source_path=db_path,
                                description=f"{browser_name} activity: {url[:80]}",
                                timestamp=datetime.datetime.now().isoformat(),
                                data={
                                    "browser": browser_name,
                                    "url": url,
                                    "title": title,
                                    "download_url": download_url,
                                    "received_bytes": received_bytes,
                                    "suspicious_indicators": suspicious
                                },
                                mitre_techniques=["T1071.001", "T1567.002", "T1105"],
                                risk_score=min(risk_score, 85),
                                raw_content=str(row)
                            )
                            self._add_artifact(artifact)
                
                conn.close()
            except Exception as e:
                print(f"[!] Error reading {browser_name} database: {e}")
    
    def collect_network_connections(self):
        """Collect active network connections (T1049, T1071.001)"""
        # Get netstat output
        cmd = "netstat -anv | grep ESTABLISHED"
        result = self._run_command(cmd)
        
        if result:
            for line in result.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        proto, recv_q, send_q, local_addr, foreign_addr = parts[:5]
                        
                        # Check for suspicious connections
                        risk_score = 0
                        suspicious = []
                        
                        if foreign_addr:
                            # Check for non-standard ports
                            try:
                                port = int(foreign_addr.split('.')[-1].split(':')[-1])
                                if port > 50000:
                                    risk_score += 10
                                    suspicious.append("High port number")
                                if port in [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]:
                                    risk_score += 30
                                    suspicious.append("Suspicious port (common C2)")
                            except:
                                pass
                        
                        if risk_score > 0:
                            artifact = ForensicArtifact(
                                artifact_type="Network_Connection",
                                source_path="netstat",
                                description=f"Active connection: {foreign_addr}",
                                timestamp=datetime.datetime.now().isoformat(),
                                data={
                                    "protocol": proto,
                                    "local_address": local_addr,
                                    "foreign_address": foreign_addr,
                                    "suspicious_indicators": suspicious
                                },
                                mitre_techniques=["T1049", "T1071.001", "T1571"],
                                risk_score=risk_score,
                                raw_content=line
                            )
                            self._add_artifact(artifact)
        
        # Get lsof for listening ports
        cmd = "lsof -i -P | grep LISTEN"
        result = self._run_command(cmd)
        
        if result:
            for line in result.strip().split('\n')[:20]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 9:
                        command, pid, user, fd, type_, device, size, node, name = parts[:9]
                        
                        risk_score = 0
                        suspicious = []
                        
                        # Check for suspicious listening processes
                        if command.lower() not in ['launchd', 'sshd', 'mDNSResponde', 'SystemUIServ', 'Google Chrome', 'firefox']:
                            risk_score += 20
                            suspicious.append(f"Uncommon listening process: {command}")
                        
                        if risk_score > 0:
                            artifact = ForensicArtifact(
                                artifact_type="Network_Listening",
                                source_path="lsof",
                                description=f"Listening process: {command} on {name}",
                                timestamp=datetime.datetime.now().isoformat(),
                                data={
                                    "command": command,
                                    "pid": pid,
                                    "user": user,
                                    "name": name,
                                    "suspicious_indicators": suspicious
                                },
                                mitre_techniques=["T1046", "T1049", "T1071.001"],
                                risk_score=risk_score,
                                raw_content=line
                            )
                            self._add_artifact(artifact)
    
    def collect_keychain_analysis(self):
        """Analyze keychain for suspicious access (T1555.001)"""
        keychain_paths = [
            os.path.expanduser("~/Library/Keychains/login.keychain-db"),
            os.path.expanduser("~/Library/Keychains/login.keychain"),
            "/Library/Keychains/System.keychain"
        ]
        
        for kc_path in keychain_paths:
            if os.path.exists(kc_path):
                # Check keychain modification time
                stat = os.stat(kc_path)
                
                # Look for keychain dumping attempts in logs
                cmd = f"log show --predicate 'process == \"security\" AND eventMessage CONTAINS \"keychain\"' --last 7d --style compact 2>/dev/null | head -20"
                result = self._run_command(cmd)
                
                if result and len(result) > 50:
                    artifact = ForensicArtifact(
                        artifact_type="Credential_Keychain",
                        source_path=kc_path,
                        description="Keychain access detected",
                        timestamp=datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        data={
                            "keychain_path": kc_path,
                            "size": stat.st_size,
                            "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "log_entries": result[:500]
                        },
                        mitre_techniques=["T1555.001"],
                        risk_score=40,
                        raw_content=result[:1000]
                    )
                    self._add_artifact(artifact)
    
    def collect_ssh_data(self):
        """Collect SSH artifacts (T1021.004)"""
        ssh_paths = [
            os.path.expanduser("~/.ssh/authorized_keys"),
            os.path.expanduser("~/.ssh/known_hosts"),
            os.path.expanduser("~/.ssh/config"),
            "/etc/ssh/sshd_config",
            "/var/log/system.log"  # SSH logs often here
        ]
        
        # Check for authorized_keys
        auth_keys = os.path.expanduser("~/.ssh/authorized_keys")
        if os.path.exists(auth_keys):
            with open(auth_keys, 'r') as f:
                content = f.read()
                keys = [line for line in content.split('\n') if line.strip() and not line.startswith('#')]
                
                for key in keys:
                    risk_score = 20
                    suspicious = []
                    
                    # Check for suspicious key types or comments
                    if 'ssh-rsa' in key or 'ssh-dss' in key:
                        suspicious.append("Legacy key algorithm")
                        risk_score += 10
                    
                    artifact = ForensicArtifact(
                        artifact_type="LateralMovement_SSH",
                        source_path=auth_keys,
                        description=f"SSH authorized key: {key[:50]}...",
                        timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(auth_keys)).isoformat(),
                        data={
                            "key_type": key.split()[0] if len(key.split()) > 0 else "unknown",
                            "key_comment": key.split()[-1] if len(key.split()) > 2 else "none",
                            "full_key": key[:200]
                        },
                        mitre_techniques=["T1021.004", "T1078.003"],
                        risk_score=risk_score,
                        raw_content=key[:500]
                    )
                    self._add_artifact(artifact)
        
        # Check SSH config for unusual settings
        ssh_config = os.path.expanduser("~/.ssh/config")
        if os.path.exists(ssh_config):
            with open(ssh_config, 'r') as f:
                content = f.read()
                
                suspicious_options = ['ProxyCommand', 'LocalForward', 'RemoteForward', 'DynamicForward', ' PermitLocalCommand']
                found_suspicious = [opt for opt in suspicious_options if opt in content]
                
                if found_suspicious:
                    artifact = ForensicArtifact(
                        artifact_type="LateralMovement_SSH",
                        source_path=ssh_config,
                        description=f"SSH config with suspicious options: {', '.join(found_suspicious)}",
                        timestamp=datetime.datetime.fromtimestamp(os.path.getmtime(ssh_config)).isoformat(),
                        data={
                            "suspicious_options": found_suspicious,
                            "config_hash": self._calculate_file_hash(ssh_config)
                        },
                        mitre_techniques=["T1021.004", "T1090.001"],
                        risk_score=50,
                        raw_content=content[:1000]
                    )
                    self._add_artifact(artifact)
    
    def collect_kernel_extensions(self):
        """Collect Kernel Extensions (KEXTs) (T1547.006 - macOS equivalent)"""
        # Check loaded KEXTs
        cmd = "kextstat | grep -v com.apple"
        result = self._run_command(cmd)
        
        if result:
            for line in result.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        index, refs, address, size, wired, name = parts[:6]
                        
                        artifact = ForensicArtifact(
                            artifact_type="Persistence_KernelExtension",
                            source_path="kextstat",
                            description=f"Third-party KEXT: {name}",
                            timestamp=datetime.datetime.now().isoformat(),
                            data={
                                "kext_name": name,
                                "address": address,
                                "size": size,
                                "refs": refs
                            },
                            mitre_techniques=["T1547.006", "T1547.011"],
                            risk_score=60,  # Third-party kexts are high risk on modern macOS
                            raw_content=line
                        )
                        self._add_artifact(artifact)
        
        # Check for deprecated KEXTs (shouldn't exist on modern macOS)
        kext_dirs = [
            "/Library/Extensions",
            "/System/Library/Extensions"
        ]
        
        for kext_dir in kext_dirs:
            if os.path.exists(kext_dir):
                for kext in glob.glob(os.path.join(kext_dir, "*.kext")):
                    if not os.path.basename(kext).startswith("com.apple"):
                        stat = os.stat(kext)
                        artifact = ForensicArtifact(
                            artifact_type="Persistence_KernelExtension",
                            source_path=kext,
                            description=f"KEXT bundle: {os.path.basename(kext)}",
                            timestamp=datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            data={
                                "path": kext,
                                "size": stat.st_size,
                                "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()
                            },
                            mitre_techniques=["T1547.006"],
                            risk_score=70,
                            raw_content=f"KEXT path: {kext}"
                        )
                        self._add_artifact(artifact)
    
    def collect_user_accounts(self):
        """Collect user account information (T1087.001, T1136.001)"""
        # Get local users
        cmd = "dscl . list /Users | grep -v '^_' | grep -v 'daemon' | grep -v 'nobody' | grep -v 'root'"
        result = self._run_command(cmd)
        
        if result:
            users = [u.strip() for u in result.strip().split('\n') if u.strip()]
            
            for user in users:
                # Get user details
                cmd = f"dscl . read /Users/{user} 2>/dev/null"
                user_info = self._run_command(cmd)
                
                # Check for hidden users (UID < 500)
                cmd_uid = f"dscl . read /Users/{user} UniqueID 2>/dev/null | awk '{{print $2}}'"
                uid = self._run_command(cmd_uid).strip()
                
                risk_score = 0
                suspicious = []
                
                if uid and int(uid) < 500:
                    risk_score += 30
                    suspicious.append("Hidden user (UID < 500)")
                
                # Check for admin privileges
                cmd_groups = f"groups {user} 2>/dev/null"
                groups = self._run_command(cmd_groups)
                if 'admin' in groups:
                    risk_score += 10
                
                # Check for password hints
                cmd_hint = f"dscl . read /Users/{user} hint 2>/dev/null"
                hint = self._run_command(cmd_hint)
                if hint and "hint" in hint:
                    suspicious.append("Password hint set")
                
                artifact = ForensicArtifact(
                    artifact_type="Discovery_UserAccount",
                    source_path="dscl",
                    description=f"User account: {user} (UID: {uid})",
                    timestamp=datetime.datetime.now().isoformat(),
                    data={
                        "username": user,
                        "uid": uid,
                        "groups": groups,
                        "user_info": user_info[:500],
                        "suspicious_indicators": suspicious
                    },
                    mitre_techniques=["T1087.001", "T1136.001", "T1564.002"],
                    risk_score=risk_score,
                    raw_content=user_info
                )
                self._add_artifact(artifact)
    
    def collect_file_system_artifacts(self):
        """Collect file system artifacts (T1083, T1564.001)"""
        # Check for hidden files in home directory
        home = os.path.expanduser("~")
        hidden_files = []
        
        for item in os.listdir(home):
            if item.startswith('.') and os.path.isfile(os.path.join(home, item)):
                # Check if recently modified
                stat = os.stat(os.path.join(home, item))
                mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
                age_days = (datetime.datetime.now() - mtime).days
                
                if age_days < 30:  # Recently modified hidden files
                    hidden_files.append({
                        "name": item,
                        "path": os.path.join(home, item),
                        "mtime": mtime.isoformat(),
                        "size": stat.st_size
                    })
        
        if hidden_files:
            artifact = ForensicArtifact(
                artifact_type="Discovery_FileSystem",
                source_path=home,
                description=f"Recent hidden files: {len(hidden_files)} found",
                timestamp=datetime.datetime.now().isoformat(),
                data={
                    "hidden_files": hidden_files,
                    "location": "User home directory"
                },
                mitre_techniques=["T1564.001", "T1083"],
                risk_score=30,
                raw_content=str(hidden_files)
            )
            self._add_artifact(artifact)
        
        # Check /tmp and /var/tmp for suspicious files
        tmp_dirs = ['/tmp', '/var/tmp']
        suspicious_patterns = ['.sh', '.py', '.pl', 'shell', 'backdoor', 'payload', 'exploit']
        
        for tmp_dir in tmp_dirs:
            if os.path.exists(tmp_dir):
                try:
                    files = os.listdir(tmp_dir)
                    suspicious_files = []
                    
                    for f in files:
                        if any(pattern in f.lower() for pattern in suspicious_patterns):
                            full_path = os.path.join(tmp_dir, f)
                            stat = os.stat(full_path)
                            suspicious_files.append({
                                "name": f,
                                "path": full_path,
                                "size": stat.st_size,
                                "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
                            })
                    
                    if suspicious_files:
                        artifact = ForensicArtifact(
                            artifact_type="DefenseEvasion_TempFiles",
                            source_path=tmp_dir,
                            description=f"Suspicious temp files: {len(suspicious_files)} found",
                            timestamp=datetime.datetime.now().isoformat(),
                            data={
                                "suspicious_files": suspicious_files,
                                "patterns_matched": suspicious_patterns
                            },
                            mitre_techniques=["T1564.001", "T1074.001", "T1059.004"],
                            risk_score=50,
                            raw_content=str(suspicious_files)
                        )
                        self._add_artifact(artifact)
                except PermissionError:
                    pass
    
    def collect_sudo_logs(self):
        """Collect sudo usage logs (T1548.003)"""
        # Check sudo logs in system.log
        cmd = "grep -i sudo /var/log/system.log 2>/dev/null | tail -50"
        result = self._run_command(cmd)
        
        if result:
            for line in result.strip().split('\n'):
                if line.strip():
                    # Check for suspicious sudo usage
                    risk_score = 10
                    suspicious = []
                    
                    if any(cmd in line.lower() for cmd in ['bash', 'sh', 'python', 'perl', 'ruby', 'nc ', 'netcat']):
                        risk_score += 30
                        suspicious.append("Shell/command execution via sudo")
                    
                    if "incorrect password" in line.lower():
                        risk_score += 20
                        suspicious.append("Failed sudo authentication")
                    
                    if risk_score > 10:
                        artifact = ForensicArtifact(
                            artifact_type="PrivilegeEscalation_Sudo",
                            source_path="/var/log/system.log",
                            description=f"Sudo activity: {line[:120]}",
                            timestamp=datetime.datetime.now().isoformat(),
                            data={
                                "log_entry": line,
                                "suspicious_indicators": suspicious
                            },
                            mitre_techniques=["T1548.003", "T1078.003"],
                            risk_score=risk_score,
                            raw_content=line
                        )
                        self._add_artifact(artifact)
    
    def collect_install_history(self):
        """Collect software installation history (T1072)"""
        install_history = "/Library/Receipts/InstallHistory.plist"
        
        if os.path.exists(install_history):
            try:
                with open(install_history, 'rb') as f:
                    history = plistlib.load(f)
                
                # Check recent installations (last 30 days)
                cutoff = datetime.datetime.now() - datetime.timedelta(days=30)
                
                for item in history:
                    install_date = item.get('date', None)
                    if install_date and isinstance(install_date, datetime.datetime):
                        if install_date > cutoff:
                            display_name = item.get('displayName', 'Unknown')
                            package_identifiers = item.get('packageIdentifiers', [])
                            
                            risk_score = 0
                            suspicious = []
                            
                            # Check for suspicious package names
                            suspicious_names = ['backdoor', 'trojan', 'virus', 'exploit', 'payload', 'crypt']
                            if any(name in display_name.lower() for name in suspicious_names):
                                risk_score += 50
                                suspicious.append("Suspicious package name")
                            
                            # Check for non-App Store installs
                            if not item.get('appleDomainsVersion', 0) > 0:
                                risk_score += 10
                            
                            artifact = ForensicArtifact(
                                artifact_type="Execution_Installation",
                                source_path=install_history,
                                description=f"Software installed: {display_name}",
                                timestamp=install_date.isoformat(),
                                data={
                                    "display_name": display_name,
                                    "package_identifiers": package_identifiers,
                                    "process_name": item.get('processName', 'Unknown'),
                                    "suspicious_indicators": suspicious
                                },
                                mitre_techniques=["T1072", "T1204.002", "T1553.001"],
                                risk_score=risk_score,
                                raw_content=str(item)
                            )
                            self._add_artifact(artifact)
            except Exception as e:
                print(f"[!] Error reading install history: {e}")
    
    def collect_gatekeeper_logs(self):
        """Collect Gatekeeper bypass attempts (T1553.001)"""
        cmd = "log show --predicate 'process == \"syspolicyd\" OR process == \"amfid\"' --last 7d --style compact 2>/dev/null | grep -i 'bypass\\|disabled\\|unsigned\\|ad-hoc'"
        result = self._run_command(cmd)
        
        if result:
            for line in result.strip().split('\n'):
                if line.strip():
                    artifact = ForensicArtifact(
                        artifact_type="DefenseEvasion_Gatekeeper",
                        source_path="Unified Logs",
                        description=f"Gatekeeper event: {line[:150]}",
                        timestamp=datetime.datetime.now().isoformat(),
                        data={
                            "log_entry": line,
                            "process": "syspolicyd/amfid"
                        },
                        mitre_techniques=["T1553.001"],
                        risk_score=60,
                        raw_content=line
                    )
                    self._add_artifact(artifact)
    
    def collect_tcc_database(self):
        """Collect Transparency, Consent, and Control (TCC) database (T1562.001)"""
        tcc_db = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
        system_tcc = "/Library/Application Support/com.apple.TCC/TCC.db"
        
        for db_path in [tcc_db, system_tcc]:
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT service, client, client_type, auth_value, auth_reason, last_modified FROM access")
                    
                    for row in cursor.fetchall():
                        service, client, client_type, auth_value, auth_reason, last_modified = row
                        
                        # Check for suspicious TCC permissions
                        risk_score = 0
                        suspicious = []
                        
                        sensitive_services = ['kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceScreenCapture', 
                                               'kTCCServiceAccessibility', 'kTCCServicePostEvent', 'kTCCServiceSystemPolicyAllFiles']
                        
                        if service in sensitive_services:
                            risk_score += 20
                        
                        if auth_value == 2:  # Allowed
                            risk_score += 10
                            if service in sensitive_services:
                                risk_score += 20
                                suspicious.append(f"Sensitive permission granted: {service}")
                        
                        # Check for recently modified permissions
                        if last_modified:
                            try:
                                mod_time = datetime.datetime.fromtimestamp(last_modified)
                                if (datetime.datetime.now() - mod_time).days < 7:
                                    risk_score += 15
                                    suspicious.append("Recently modified permission")
                            except:
                                pass
                        
                        if risk_score > 20:
                            artifact = ForensicArtifact(
                                artifact_type="DefenseEvasion_TCC",
                                source_path=db_path,
                                description=f"TCC: {client} - {service}",
                                timestamp=datetime.datetime.fromtimestamp(last_modified).isoformat() if last_modified else "Unknown",
                                data={
                                    "service": service,
                                    "client": client,
                                    "client_type": client_type,
                                    "authorized": auth_value == 2,
                                    "suspicious_indicators": suspicious
                                },
                                mitre_techniques=["T1562.001", "T1125", "T1113"],
                                risk_score=min(risk_score, 80),
                                raw_content=str(row)
                            )
                            self._add_artifact(artifact)
                    
                    conn.close()
                except Exception as e:
                    print(f"[!] Error reading TCC database {db_path}: {e}")
    
    def run_all_collections(self):
        """Execute all collection methods"""
        print(f"[*] Starting macOS Forensic Collection on {self.system_info['hostname']}")
        print(f"[*] OS Version: {self.system_info['os_version']} ({self.system_info['build_version']})")
        print(f"[*] Collection Time: {self.system_info['collection_time']}")
        print("=" * 80)
        
        collections = [
            ("Launch Agents/Daemons", self.collect_launch_agents_daemons),
            ("Login Items", self.collect_login_items),
            ("Cron Jobs", self.collect_cron_jobs),
            ("Shell History", self.collect_bash_history),
            ("System Logs", self.collect_system_logs),
            ("Quarantine Data", self.collect_quarantine_data),
            ("Browser Data", self.collect_browser_data),
            ("Network Connections", self.collect_network_connections),
            ("Keychain Analysis", self.collect_keychain_analysis),
            ("SSH Artifacts", self.collect_ssh_data),
            ("Kernel Extensions", self.collect_kernel_extensions),
            ("User Accounts", self.collect_user_accounts),
            ("File System Artifacts", self.collect_file_system_artifacts),
            ("Sudo Logs", self.collect_sudo_logs),
            ("Install History", self.collect_install_history),
            ("Gatekeeper Logs", self.collect_gatekeeper_logs),
            ("TCC Database", self.collect_tcc_database),
        ]
        
        for name, method in collections:
            print(f"\n[*] Collecting: {name}")
            try:
                method()
            except Exception as e:
                print(f"[!] Error in {name}: {e}")
        
        print(f"\n[*] Collection complete. Total artifacts: {len(self.artifacts)}")
    
    def export_to_csv(self, filename: str = "macos_forensics_report.csv"):
        """Export all artifacts to CSV"""
        if not self.artifacts:
            print("[!] No artifacts to export")
            return
        
        output_path = self.output_dir / filename
        
        fieldnames = [
            "artifact_type", "source_path", "description", "timestamp",
            "mitre_techniques", "risk_score", "data", "raw_content"
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for artifact in self.artifacts:
                writer.writerow(artifact.to_dict())
        
        print(f"\n[+] CSV Report exported to: {output_path}")
        
        # Also create summary JSON
        summary_path = self.output_dir / "forensics_summary.json"
        summary = {
            "system_info": self.system_info,
            "collection_stats": {
                "total_artifacts": len(self.artifacts),
                "by_type": {},
                "by_mitre_technique": {},
                "high_risk_count": 0
            },
            "artifacts": [artifact.to_dict() for artifact in self.artifacts]
        }
        
        # Calculate statistics
        for artifact in self.artifacts:
            # By type
            t = artifact.artifact_type
            summary["collection_stats"]["by_type"][t] = summary["collection_stats"]["by_type"].get(t, 0) + 1
            
            # By MITRE technique
            for tech in artifact.mitre_techniques:
                summary["collection_stats"]["by_mitre_technique"][tech] = \
                    summary["collection_stats"]["by_mitre_technique"].get(tech, 0) + 1
            
            # High risk
            if artifact.risk_score >= 70:
                summary["collection_stats"]["high_risk_count"] += 1
        
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] JSON Summary exported to: {summary_path}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("COLLECTION SUMMARY")
        print("=" * 80)
        print(f"Total Artifacts: {summary['collection_stats']['total_artifacts']}")
        print(f"High Risk Items (>=70): {summary['collection_stats']['high_risk_count']}")
        print("\nArtifacts by Type:")
        for t, count in sorted(summary["collection_stats"]["by_type"].items(), key=lambda x: x[1], reverse=True):
            print(f"  - {t}: {count}")
        print("\nMITRE ATT&CK Techniques Detected:")
        for tech, count in sorted(summary["collection_stats"]["by_mitre_technique"].items(), key=lambda x: x[1], reverse=True):
            tech_info = MITRE_TECHNIQUES.get(tech, {"name": "Unknown", "tactic": "Unknown"})
            print(f"  - {tech} ({tech_info['name']}): {count} occurrences")

def main():
    """Main entry point"""
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║           macOS Digital Forensics Incident Response Tool         ║
    ║                    MITRE ATT&CK Mapping Edition   
               Created By Mohamed Aqeel for all DFIR and SecOps folks. ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Check if running on macOS
    if sys.platform != "darwin":
        print("[!] Warning: This script is designed for macOS. Detected platform:", sys.platform)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. Some artifacts may be inaccessible.")
        print("[*] Consider running with sudo for full access.")
        print()
    
    # Initialize collector
    output_dir = input("Enter output directory [./forensics_output]: ").strip() or "./forensics_output"
    
    collector = MacOSForensicCollector(output_dir)
    
    # Run collections
    collector.run_all_collections()
    
    # Export results
    collector.export_to_csv()
    
    print("\n[*] Forensic collection complete!")
    print(f"[*] Review the CSV report and JSON summary in: {output_dir}")

if __name__ == "__main__":
    main()