import sys
import socket
import os
import textwrap
import colorama
import time
import platform
import json
import threading
import subprocess
import abc
import uuid
import re
from typing import List, Dict, Any, Optional, Callable, Type
from datetime import datetime, timezone 
from enum import Enum
from colorama import init

# --- ADDED IMPORTS FOR UTILITIES ---
import random 
import string
import requests 
# ------------------------------------------

# Initialize colorama for cross-platform color support
init(autoreset=True)

# --- ANSI Color Codes and Layout ---
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'
MAGENTA = '\033[95m' 

TERMINAL_WIDTH = 80
COLUMN_WIDTH = 38

# --- Custom ASCII Map (Fixed: Raw String) ---
HUNTX_MAP = f"{BOLD}{CYAN}" + r"""
-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----
           . _..::__:  ,-"-"._        |7       ,     _,.__
   _.___ _ _<_>`!(._`.`-.    /         _._     `_ ,_/  '  '-._.---.-.__
>.{     " " `-==,',._\{  \  / {)      / _ ">_,-' `                mt-2_
  \_.:--.       `._ )`^-. "'       , [_/(                       __,/-'
 '"'     \         "    _L        oD_,--'                )     /. (|
          |           ,'          _)_.\\._<> 6              _,' /  '
          `.         /           [_/_'` `"(                <'}  )
           \\    .-. )           /   `-'"..' `:.#          _)  '
    `        \  (  `(           /         `:\  > \  ,-^.  /' '
              `._,   ""         |           \`'   \|   ?_){  \
                 `=.---.        `._._       ,'     "`  |' ,- '.
                   |    `-._         |     /          `:`<_|h--._
                   (        >        .     | ,          `=.__.`-'\
                    `.     /         |     |{|              ,-.,\     .
                     |   ,'           \   / `'            ,"     \
                     |  /              |_'                |  __  /
                     | |                                  '-'  `-'   \.
                     |/                                         "    /
                     \.                                             '

                      ,/            ______._.--._ _..---.---------._
     ,-----"-..?----_/ )      __,-'"             "                  (
-.._(                  `-----'                                       `-
-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----
""" + f"{RESET}"

# --- ASCII Art Banner (Fixed: Raw String) ---
HUNTX_BANNER = f"{BOLD}{GREEN}" + r"""
888   888 888     888 888b    888 88888888888 Y88b    d88P 
888   888 888     888 8888b   888     888       Y88b d88P  
888   888 888     888 88888b  888     888        Y88o88P   
8888888888 888     888 888Y88b 888     888         Y888P    
888   888 888     888 888 Y88b888     888         d888b    
888   888 888     888 888  Y88888     888        d88888b   
888   888 Y88b. .d88P 888   Y8888     888       d88P Y88b  
888   888  "Y88888P"  888    Y888     888      d88P   Y88b
""" + f"{RESET}"

# --- Configuration (EMBEDDED) ---
HUNTX_CONFIG = {
    "tool_paths": {
        "subdomain_enum": "host",
        "httpx_prober": "cat",
        "nmap": "cat",
        "nuclei": "echo",
        "hydra": "echo",
        "netcat": "nc", # Ensure 'nc' or 'ncat' is installed on your system
        "metasploit": "echo",
        "burpsuite": "echo",
        "wireshark": "echo"
    },
    "network": {
        "timeouts": 300,
        "max_threads": 10
    },
    "wordlists": {
        "usernames": "/path/to/userlist.txt",
        "passwords": "/path/to/passlist.txt"
    },
    "report_settings": {
        "output_format": "txt",
        "author": "HUNTX Team"
    }
}

# --- Password Utility Functions ---

def check_password_strength(password):
    """Checks the strength of a given password based on 5 criteria."""
    
    length_criteria = len(password) >= 8
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    number_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[@$!%*?&]', password) is not None

    criteria_met = sum([
        length_criteria,
        uppercase_criteria,
        lowercase_criteria,
        number_criteria,
        special_char_criteria
    ])

    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Moderate"
    elif criteria_met == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return strength

def generate_complex_password(length, strength_level):
    """Generates a complex password based on length and a desired strength level."""

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits
    symbols = string.punctuation
    
    all_chars = lower + upper + num + symbols

    if strength_level == 4: 
        all_chars = all_chars + num + symbols 
        min_guarantee = 4
    elif strength_level == 3:
        all_chars = all_chars + symbols 
        min_guarantee = 4
    elif strength_level == 2:
        min_guarantee = 4
    else: 
        min_guarantee = 2 

    guarantee = []
    guaranteed_types = [lower, upper, num, symbols]
    
    for i in range(min(min_guarantee, 4)):
        guarantee.append(random.choice(guaranteed_types[i]))
    
    remaining_length = length - len(guarantee)
    
    if remaining_length < 0:
        remaining_length = 0
        
    remaining_chars = random.choices(all_chars, k=remaining_length)
    
    password_list = guarantee + remaining_chars
    random.shuffle(password_list)
    
    return "".join(password_list)

# --- SDB Models and Persistence ---

class SimpleBaseModel:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
    def model_dump_json(self, indent=None):
        return json.dumps(self.__dict__, indent=indent, default=str)

class AssetStatus(str, Enum):
    DISCOVERED = "discovered"
    LIVE = "live"
    SCANNED = "scanned"
    DEAD = "dead"
    SKIPPED = "skipped"

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class PortDetail(SimpleBaseModel):
    def __init__(self, port_number: int, protocol: str = "tcp", service: str = "unknown", version: Optional[str] = None, state: str = "open", extra_details: Dict[str, Any] = None):
        super().__init__(port_number=port_number, protocol=protocol, service=service, version=version, state=state, extra_details=extra_details or {})

class FindingObject(SimpleBaseModel):
    def __init__(self, tool_name: str, template_id: str, name: str, severity: FindingSeverity, proof: str, description: Optional[str] = None):
        super().__init__(
            finding_id=str(uuid.uuid4()), tool_name=tool_name, template_id=template_id, name=name, severity=severity, proof=proof, description=description,
            timestamp=datetime.now(timezone.utc)
        )

class AssetObject(SimpleBaseModel):
    def __init__(self, asset_key: str, status: AssetStatus = AssetStatus.DISCOVERED, ip_address: Optional[str] = None, ports: List[PortDetail] = None, is_web: bool = False, url: Optional[str] = None, title: Optional[str] = None, http_headers: Dict[str, str] = None, findings: List[FindingObject] = None):
        super().__init__(
            asset_key=asset_key, status=status, ip_address=ip_address, ports=ports or [], is_web=is_web, 
            url=url, title=title, http_headers=http_headers or {}, findings=findings or [], 
            last_updated=datetime.now(timezone.utc)
        )

class StateDataBus(SimpleBaseModel):
    def __init__(self, target_root: str, assets: Dict[str, AssetObject] = None, all_findings: List[FindingObject] = None):
        super().__init__(
            session_id=os.urandom(8).hex(),
            target_root=target_root,
            start_time=datetime.now(timezone.utc),
            assets=assets or {},
            all_findings=all_findings or []
        )

CHECKPOINT_EXT = ".sdb.checkpoint"
CHECKPOINT_DIR = "checkpoints"
SECRET_KEY = "HUNTX_DEFAULT_SECRET"
SDB_LOCK = threading.Lock()
REPORT_DIR = "reports"

class SDB:
    @staticmethod
    def _get_checkpoint_path(target_root: str) -> str:
        if not os.path.exists(CHECKPOINT_DIR): os.makedirs(CHECKPOINT_DIR)
        safe_name = "".join(c if c.isalnum() or c in ('.', '_') else '_' for c in target_root)
        return os.path.join(CHECKPOINT_DIR, f"{safe_name}{CHECKPOINT_EXT}")

    @staticmethod
    def _encrypt_data(data: str) -> bytes: return f"ENCRYPTED_WITH_{SECRET_KEY}::{data}".encode('utf-8')
    @staticmethod
    def _decrypt_data(data: bytes) -> str:
        s = data.decode('utf-8')
        if s.startswith(f"ENCRYPTED_WITH_{SECRET_KEY}::"): return s.split('::', 1)[-1]
        return s

    @staticmethod
    def load(target_root: str) -> StateDataBus:
        filepath = SDB._get_checkpoint_path(target_root)
        if os.path.exists(filepath):
            try:
                print(f"[{time.strftime('%H:%M:%S')}] Attempting to load checkpoint...")
                with open(filepath, 'rb') as f: encrypted_data = f.read()
                decrypted_json = SDB._decrypt_data(encrypted_data)
                data = json.loads(decrypted_json)
                
                assets = {}
                for k, v in data.get('assets', {}).items():
                    v['ports'] = [PortDetail(**p) for p in v.get('ports', []) if isinstance(p, dict)]
                    v['findings'] = [FindingObject(**f) for f in v.get('findings', []) if isinstance(f, dict)]
                    assets[k] = AssetObject(**v)
                
                data['assets'] = assets
                return StateDataBus(**data)
            except Exception as e:
                print(f"[{time.strftime('%H:%M:%S')}] [SDB:ERROR] Checkpoint load failure: {e}. Starting new session.")
        
        print(f"[{time.strftime('%H:%M:%S')}] Starting new session.")
        return StateDataBus(target_root=target_root)

    @staticmethod
    def save(sdb_instance: StateDataBus):
        filepath = SDB._get_checkpoint_path(sdb_instance.target_root)
        with SDB_LOCK:
            raw_json = sdb_instance.model_dump_json(indent=2)
            encrypted_data = SDB._encrypt_data(raw_json)
            try:
                with open(filepath, 'wb') as f: f.write(encrypted_data)
                print("[SDB:SAVE] Checkpoint saved.")
            except Exception as e:
                print(f"[SDB:ERROR] Failed to save checkpoint: {e}")
        
        SDB.save_data_text(sdb_instance, raw_json)

    @staticmethod
    def save_data_text(sdb_instance: StateDataBus, raw_json: str):
        if not os.path.exists(REPORT_DIR): os.makedirs(REPORT_DIR)
        safe_name = "".join(c if c.isalnum() or c in ('.', '_') else '_' for c in sdb_instance.target_root)
        filename = os.path.join(REPORT_DIR, f"{safe_name}_{sdb_instance.session_id[:6]}.txt")
        
        try:
            with open(filename, 'w') as f:
                f.write(f"HUNTX SESSION DATA\nTarget: {sdb_instance.target_root}\nSession ID: {sdb_instance.session_id}\n\n")
                f.write("--- RAW SDB JSON DATA ---\n\n")
                f.write(raw_json)
            print(f"[SDB:TXT] Data saved to {filename}")
        except Exception as e:
            print(f"[SDB:ERROR] Failed to save text file: {e}")

    @staticmethod
    def update_asset(sdb_instance: StateDataBus, asset: AssetObject):
        with SDB_LOCK: sdb_instance.assets[asset.asset_key] = asset
        print(f"[SDB:UPDATE] Asset {asset.asset_key} updated.")

    @staticmethod
    def add_finding(sdb_instance: StateDataBus, asset_key: str, finding: FindingObject):
        with SDB_LOCK:
            if asset_key in sdb_instance.assets:
                asset = sdb_instance.assets[asset_key]
                asset.findings.append(finding)
                sdb_instance.all_findings.append(finding)
            else:
                print(f"[SDB:WARN] Cannot add finding: Asset key '{asset_key}' not found.")


# --- 3. MAL Tool Wrapper Base ---

class ToolWrapper(abc.ABC):
    TOOL_NAME: str = "ABSTRACT_TOOL"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tool_binary_path = config.get('tool_paths', {}).get(self.TOOL_NAME.lower(), self.TOOL_NAME.lower())
        self.direct_target = None 

    @abc.abstractmethod
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        raise NotImplementedError()

    def _execute_tool(self, command: List[str]) -> str:
        try:
            if self.TOOL_NAME in ["BURPSUITE", "WIRESHARK"]:
                print(f"[{self.TOOL_NAME}] Launching external GUI tool. Please use manually.")
                subprocess.Popen(command)
                return f"External tool launched: {' '.join(command)}"

            print(f"[{self.TOOL_NAME}] Executing: {' '.join(command)}")
            result = subprocess.run(
                command, capture_output=True, text=True, check=True,
                timeout=self.config.get('network', {}).get('timeouts', 300)
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            if self.TOOL_NAME == "NETCAT":
                return e.stdout + e.stderr
            
            print(f"[{self.TOOL_NAME} ERROR] Execution failed: {e.stderr}")
            raise
        except subprocess.TimeoutExpired:
            print(f"[{self.TOOL_NAME} ERROR] Tool execution timed out.")
            raise
        except FileNotFoundError:
            print(f"[{self.TOOL_NAME} ERROR] Tool binary not found at: {self.tool_binary_path}. Check HUNTX_CONFIG.{RESET}")
            raise

    @abc.abstractmethod
    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        raise NotImplementedError()

    def start(self, sdb: StateDataBus, target: str):
        print(f"[{self.TOOL_NAME}] Starting execution pipeline for target: {target}")
        
        exec_target = target if target != "NONE" else sdb.target_root
        
        command = self._build_command(exec_target, sdb)
        if not command: 
            print(f"[{self.TOOL_NAME}] WARN: No targets found or command skipped. Moving on.")
            return 
        
        try:
            raw_output = self._execute_tool(command)
        except Exception as e:
            print(f"[{self.TOOL_NAME} CRITICAL ERROR] Tool failed to run: {e}")
            return
        
        if self.TOOL_NAME not in ["BURPSUITE", "WIRESHARK"]:
            self._normalize_output(raw_output, sdb)
            print(f"[{self.TOOL_NAME}] Execution successful. SDB updated.")
        else:
            print(f"[{self.TOOL_NAME}] External tool launch command executed.")


# --- 4. MAL Wrappers (Bug Bounty Focused) ---

class SubdomainEnumerationWrapper(ToolWrapper):
    TOOL_NAME = "SUBDOMAIN_ENUM"
    
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        self.output_file = f"/tmp/sub_enum_output_{sdb.session_id}.txt"
        mock_hosts = [
            target, f"www.{target}", f"api.{target}", f"mail.{target}", f"dev.{target}", 
            f"forgotten.{target}", f"internal-sso.{target}", f"client-portal.{target}"
        ]
        with open(self.output_file, 'w') as f:
            f.write('\n'.join(mock_hosts))
        return ["host", target] 

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        ip_match = re.search(r'has address ([\d\.]+)', raw_output)
        ip_address = ip_match.group(1) if ip_match else None
        
        hostnames = []
        try:
            with open(self.output_file, 'r') as f:
                hostnames = list(set(h.strip() for h in f.read().split() if h.strip()))
            os.remove(self.output_file)
        except FileNotFoundError:
            print(f"[{self.TOOL_NAME} WARN] Could not read mock output file.")
            hostnames = [sdb.target_root] 
        
        print(f"\n{BOLD}{CYAN}--- Discovered Hostnames ({len(hostnames)}) ---{RESET}")
        for hostname in hostnames:
            new_asset = AssetObject(asset_key=hostname, ip_address=ip_address)
            SDB.update_asset(sdb, new_asset)
            print(f"{GREEN} [+] {hostname} ({ip_address}){RESET}") 

        print(f"[{self.TOOL_NAME}] Final list of {len(hostnames)} assets processed.")


class BruteForceSubdomainWrapper(ToolWrapper):
    TOOL_NAME = "BRUTEFORCE_SUB"
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.output_file = "discovered_bruteforce_urls.txt"
        self.wordlist_url = "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt"
        self.wordlist_local = "n0kovo_subdomains_small.txt"

    def _download_file(self):
        if not os.path.isfile(self.wordlist_local):
            print(f"[{self.TOOL_NAME}] Downloading wordlist from {self.wordlist_url}...")
            try:
                response = requests.get(self.wordlist_url, timeout=self.config.get('network', {}).get('timeouts', 300))
                response.raise_for_status() 
                with open(self.wordlist_local, 'wb') as f:
                    f.write(response.content)
                print(f"[{self.TOOL_NAME}] Download complete.")
            except requests.exceptions.RequestException as e:
                print(f"[{self.TOOL_NAME} ERROR] Failed to download wordlist: {e}. Aborting scan.")
                raise

    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        try:
            self._download_file()
            return ["echo", f"Starting brute-force scan for {target} using local Python logic..."]
        except Exception:
            return []
    
    def _request_subdomain(self, subdomain: str) -> Optional[requests.Response]:
        try:
            return requests.get("http://" + subdomain, timeout=3)
        except requests.exceptions.RequestException:
            return None 

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        target_root = sdb.target_root
        discovered_count = 0
        
        if not os.path.isfile(self.wordlist_local):
            print(f"[{self.TOOL_NAME} ERROR] Wordlist not found. Cannot proceed.")
            return

        print(f"\n{BOLD}{YELLOW}--- Brute-Force Subdomain Scan for {target_root} ---{RESET}")
        
        with open(self.wordlist_local, "r") as wordlist_file, open(self.output_file, "a") as output:
            for line in wordlist_file:
                word = line.strip()
                test_url = word + "." + target_root
                
                if test_url in sdb.assets and sdb.assets[test_url].status in [AssetStatus.LIVE, AssetStatus.SCANNED]:
                     continue

                response = self._request_subdomain(test_url)
                
                if response is not None and response.status_code < 400:
                    discovered_url = "http://" + test_url
                    print(f"{GREEN} [+] {discovered_url} ({response.status_code}){RESET}")

                    new_asset = AssetObject(asset_key=test_url, url=discovered_url, is_web=True, status=AssetStatus.LIVE)
                    SDB.update_asset(sdb, new_asset)
                    
                    output.write(discovered_url + "\n")
                    discovered_count += 1
        
        print(f"\n[{self.TOOL_NAME}] Finished. {discovered_count} NEW unique assets discovered.")
        print(f"[{self.TOOL_NAME}] Raw URLs saved to: {self.output_file}")


class PortScanningWrapper(ToolWrapper):
    TOOL_NAME = "PORT_SCANNER"
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        live_assets = [a.asset_key for a in sdb.assets.values() if a.status != AssetStatus.DEAD]
        if not live_assets: return []
        self.mock_output_path = f"/tmp/nmap_mock_{sdb.session_id}.xml"
        with open(self.mock_output_path, 'w') as f: f.write(f"Scanning {len(live_assets)} hosts...")
        return ["cat", self.mock_output_path]

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        if os.path.exists(self.mock_output_path): os.remove(self.mock_output_path)
        scan_count = 0
        for asset_key, asset in sdb.assets.items():
            if asset.status != AssetStatus.DEAD:
                asset.status = AssetStatus.SCANNED
                if asset_key in [sdb.target_root, f"www.{sdb.target_root}", f"api.{sdb.target_root}"]:
                    asset.ports = [PortDetail(22, 'tcp', 'ssh'), PortDetail(443, 'tcp', 'https', version="nginx/1.20")]
                else:
                    asset.ports = [PortDetail(80, 'tcp', 'http')] 
                
                SDB.update_asset(sdb, asset)
                scan_count += 1
        print(f"[{self.TOOL_NAME}] Simulated port scan for {scan_count} assets.")

class OSINTWrapper(ToolWrapper):
    TOOL_NAME = "OSINT_GATHERER"
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        return ["echo", f"Performing deep OSINT search on target: {target}..."]
    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        print(f"[{self.TOOL_NAME}] {raw_output.strip()}")

class MetasploitWrapper(ToolWrapper):
    TOOL_NAME = "METASPLOIT"
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        target_asset = sdb.assets.get(target)
        if target_asset and any(p.port_number == 445 for p in target_asset.ports):
             return ["echo", f"Launching MSF exploit against {target} (port 445 open)..."]
        return ["echo", f"No common exploit vector found for {target}. Aborting mock exploit."]

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        print(f"[{self.TOOL_NAME}] Mock exploit executed. Result: {raw_output.strip()}")

class HydraWrapper(ToolWrapper):
    TOOL_NAME = "HYDRA"
    
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        if target == "NONE":
            ssh_asset = next((a for a in sdb.assets.values() if any(p.service == 'ssh' and p.state == 'open' for p in a.ports)), None)
            target = ssh_asset.asset_key if ssh_asset else None
            
        if not target:
            print(f"[{self.TOOL_NAME} WARN] No suitable target or asset with open SSH (port 22) found in SDB for Hydra.")
            return []
        
        userlist = self.config.get('wordlists', {}).get('usernames', 'users.txt')
        passlist = self.config.get('wordlists', {}).get('passwords', 'passwords.txt')
        
        self.simulated_command = ["hydra", "-L", userlist, "-P", passlist, target, "ssh"]
        return ["echo", f"Simulating SSH Brute-force on {target} using Hydra..."]

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        print(f"[{self.TOOL_NAME}] Brute-force simulation started. Output: {raw_output.strip()}")
        
        target_key = sdb.target_root 

        if random.choice([True, False, False]): 
            user = random.choice(["root", "admin", "testuser"])
            password = random.choice(["password123", "default", "p@ssw0rd"])
            
            mock_proof = f"Successful login: {user}:{password}"
            mock_finding = FindingObject(
                tool_name=self.TOOL_NAME,
                template_id="SSH_WEAK_CREDS",
                name="SSH Weak Credential Found via Brute-Force",
                severity=FindingSeverity.CRITICAL, 
                proof=mock_proof,
                description=f"Hydra simulated a successful login to SSH on {target_key} using common or weak credentials."
            )
            
            target_for_finding = self.simulated_command[4] if hasattr(self, 'simulated_command') and len(self.simulated_command) > 4 else sdb.target_root
            SDB.add_finding(sdb, target_for_finding, mock_finding)
            print(f"\n{BOLD}{RED}!! CRITICAL FINDING LOGGED: SSH Weak Credentials ({user}:{password}) !!{RESET}")
        else:
            print(f"[{self.TOOL_NAME}] Brute-force simulation finished: No weak credentials found (MOCK).")


class NetcatWrapper(ToolWrapper):
    TOOL_NAME = "NETCAT"
    
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        """Builds the real netcat command for a connectivity test (nc -z -v IP PORT)."""
        if ':' in target:
            try:
                ip, port = target.split(':', 1)
                port_num = int(port)
                if not 1 <= port_num <= 65535:
                    print(f"{RED}[{self.TOOL_NAME} ERROR] Port number must be between 1 and 65535.{RESET}")
                    return []
                
                # STORE TARGET INFO FOR USE IN NORMALIZE_OUTPUT
                self.scan_ip = ip
                self.scan_port = port_num

                return [
                    self.tool_binary_path, 
                    "-z", 
                    "-v", 
                    "-w", "1", 
                    ip, 
                    str(port_num)
                ]
            except ValueError:
                print(f"{RED}[{self.TOOL_NAME} ERROR] Invalid port number or target format.{RESET}")
                return []
        
        print(f"{RED}[{self.TOOL_NAME} ERROR] Target format invalid. Use IP:PORT (e.g., 10.0.0.1:80).{RESET}")
        return []

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        """Analyzes the netcat output to report connection status AND SAVE FINDING."""
        
        success_pattern = r'Connection to .* port .* succeeded'
        
        # Check if successful
        is_success = re.search(success_pattern, raw_output, re.IGNORECASE) is not None
        
        if is_success:
            result_status = f"{GREEN}Connection SUCCESSFUL (Port OPEN).{RESET}"
            
            # --- CRITICAL: SAVE FINDING TO SDB ---
            
            # 1. Ensure the asset exists. If scanning a new IP, create it.
            if hasattr(self, 'scan_ip'):
                if self.scan_ip not in sdb.assets:
                    print(f"[{self.TOOL_NAME}] New asset detected ({self.scan_ip}). Adding to database...")
                    new_asset = AssetObject(asset_key=self.scan_ip, ip_address=self.scan_ip, status=AssetStatus.SCANNED)
                    SDB.update_asset(sdb, new_asset)
                
                # 2. Create the Finding Object
                finding = FindingObject(
                    tool_name=self.TOOL_NAME,
                    template_id="NC_CONNECTIVITY_SUCCESS",
                    name=f"Port {self.scan_port} Reachable (Open)",
                    severity=FindingSeverity.INFO,
                    proof=raw_output.strip(),
                    description=f"Netcat successfully established a connection to port {self.scan_port}."
                )
                
                # 3. Add to Database
                SDB.add_finding(sdb, self.scan_ip, finding)
                print(f"[{self.TOOL_NAME}] {GREEN}Finding saved to SDB.{RESET}")

        elif "connection refused" in raw_output.lower() or "no route to host" in raw_output.lower() or "timeout" in raw_output.lower():
            result_status = f"{YELLOW}Connection FAILED (Port CLOSED/Filtered/Timed out).{RESET}"
        else:
             result_status = f"{CYAN}Connectivity test completed. Status unclear.{RESET}"

        print(f"[{self.TOOL_NAME}] Test finished. Result: {result_status}")
        
        print(f"{DIM}--- Netcat Verbose Output ---{RESET}")
        print(raw_output.strip())
        print(f"{DIM}-----------------------------{RESET}")


class BurpSuiteWrapper(ToolWrapper):
    TOOL_NAME = "BURPSUITE"
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        return [self.tool_binary_path]

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        pass

class WiresharkWrapper(ToolWrapper):
    TOOL_NAME = "WIRESHARK"
    def _build_command(self, target: str, sdb: StateDataBus) -> List[str]:
        return [self.tool_binary_path] 

    def _normalize_output(self, raw_output: str, sdb: StateDataBus) -> None:
        pass

# --- 5. Core Orchestration ---

MODULE_REGISTRY: Dict[str, Type[ToolWrapper] | Callable[[Dict[str, Any]], ToolWrapper]] = {
    "subdomain_enum": SubdomainEnumerationWrapper,
    "bruteforce_sub": BruteForceSubdomainWrapper, 
    "port_scan": PortScanningWrapper,
    "osint_gather": OSINTWrapper,
    "hydra": HydraWrapper, 
    "netcat": NetcatWrapper, 
    "metasploit": MetasploitWrapper,
    "burpsuite": BurpSuiteWrapper,
    "wireshark": WiresharkWrapper,
    "full_scan": lambda config: ToolWrapper(config)
}

RECON_PIPELINE: List[str] = ["subdomain_enum", "bruteforce_sub", "port_scan", "osint_gather"] 
FULL_SCAN_PIPELINE: List[str] = ["subdomain_enum", "bruteforce_sub", "port_scan", "osint_gather", "hydra", "full_scan"] 

def orchestrator_main(action_code: str, target: str):
    print(f"🧠 Initiating Core Orchestration for action: {action_code} on target: {target}")
    initial_finding_count = 0
    
    state_db: StateDataBus = SDB.load(target)
    initial_finding_count = len(state_db.all_findings)
    
    pipeline: Optional[List[str]] = None
    
    if action_code == 'RECON_FULL': pipeline = RECON_PIPELINE
    elif action_code == 'FULL_SCAN': pipeline = FULL_SCAN_PIPELINE
    elif action_code == 'REPORT':
        ReportGenerator().generate_report(state_db)
        SDB.save(state_db)
        try: input(f"\n{YELLOW}{BOLD}Press ENTER to return to the main menu...{RESET}")
        except: pass
        return
    elif action_code in MODULE_REGISTRY: 
        pipeline = [action_code]
    else:
        print(f"[ERROR] Unknown action code: {action_code}")
        return

    for step_name in pipeline:
        if step_name in MODULE_REGISTRY:
            WrapperClass = MODULE_REGISTRY[step_name]
            
            if isinstance(WrapperClass, type) and issubclass(WrapperClass, ToolWrapper):
                 executor = WrapperClass(HUNTX_CONFIG)
            elif callable(WrapperClass):
                 executor = WrapperClass(HUNTX_CONFIG)
            else: continue

            print(f"\n[STEP] ⚙️ Executing {step_name.upper()}...")
            try:
                executor.start(state_db, target)
                SDB.save(state_db)
            except Exception as e:
                print(f"[ERROR] Module {step_name} failed: {e}")
    
    final_finding_count = len(state_db.all_findings)
    new_findings = final_finding_count - initial_finding_count
    
    if new_findings > 0:
        print(f"\n{BOLD}{RED}🚨 {new_findings} NEW FINDINGS DISCOVERED!{RESET}")
        for finding in state_db.all_findings[initial_finding_count:]:
            print(f"  [{finding.severity.value.upper()}] {finding.name}")
            asset_key = next((a.asset_key for a in state_db.assets.values() if finding in a.findings), target) 
            print(f"    Tool: {finding.tool_name} | Asset: {asset_key}")
    
    print("\n✅ Pipeline execution finished. Final state saved.")
    try: input(f"\n{YELLOW}{BOLD}Press ENTER to return to the main menu...{RESET}")
    except: pass


# --- 6. Report Generator ---

class ReportGenerator:
    def generate_report(self, sdb_instance: StateDataBus):
        print("\n📊 Initiating Professional Report Summary...")
        severity_counts = {sev.value: sum(1 for f in sdb_instance.all_findings if f.severity == sev) for sev in FindingSeverity}
        author = HUNTX_CONFIG.get('report_settings', {}).get('author', 'HUNTX Team')

        print(f"\n{BOLD}{CYAN}--- SECURITY ASSESSMENT REPORT: {sdb_instance.target_root.upper()} ---{RESET}")
        print(f"{CYAN}Session ID:{RESET} {sdb_instance.session_id}")
        print(f"{CYAN}Date:{RESET} {sdb_instance.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{CYAN}Prepared by:{RESET} {author}")
        print("-" * TERMINAL_WIDTH)
        
        print(f"{BOLD}EXECUTIVE SUMMARY{RESET}")
        print(f"Total Assets Scanned: {len(sdb_instance.assets)}")
        print(f"Total Findings: {len(sdb_instance.all_findings)}")
        print(f"Critical/High Findings: {RED}{BOLD}{severity_counts.get('critical', 0)}/{severity_counts.get('high', 0)}{RESET}")
        print("-" * TERMINAL_WIDTH)

        print(f"\n{BOLD}{CYAN}DETAILED FINDINGS ({len(sdb_instance.all_findings)}){RESET}")
        if not sdb_instance.all_findings:
            print("No vulnerabilities were reported in this session.")
        else:
            sorted_findings = sorted(sdb_instance.all_findings, key=lambda f: f.severity, reverse=True)
            for i, finding in enumerate(sorted_findings, 1):
                asset = sdb_instance.assets.get(next((a.asset_key for a in sdb_instance.assets.values() if finding in a.findings), None))
                asset_key = asset.asset_key if asset else 'N/A'
                severity_color = RED if finding.severity == FindingSeverity.CRITICAL else YELLOW if finding.severity == FindingSeverity.HIGH else GREEN
                
                print(f"\n{severity_color}{BOLD}{i}. {finding.name.upper()} ({finding.severity.value.upper()}){RESET}")
                print(f"  {CYAN}Asset:{RESET} {asset_key} (IP: {asset.ip_address if asset else 'N/A'})")
                print(f"  {CYAN}Tool:{RESET} {finding.tool_name}")
                print(f"  {CYAN}Proof:{RESET} {textwrap.shorten(finding.proof, width=70, placeholder='...')}")
        
        print(f"\n{BOLD}{CYAN}ASSET INVENTORY ({len(sdb_instance.assets)}){RESET}")
        for asset_key, asset in sdb_instance.assets.items():
            ports_list = ", ".join(f"{p.port_number}/{p.protocol} ({p.service})" for p in asset.ports)
            print(f"\n{CYAN}>> Asset:{RESET} {BOLD}{asset_key}{RESET} (IP: {asset.ip_address or 'N/A'})")
            print(f"   Status: {asset.status.value.upper()} | URL: {asset.url or 'N/A'}")
            print(f"   Ports: {ports_list or 'None'}")
            print(f"   Findings: {len(asset.findings)} total.")
            
        print("\n-------------------------------------")
        print(f"FULL SDB JSON saved to reports/{sdb_instance.target_root}_{sdb_instance.session_id[:6]}.txt")


# --- 7. CLI Entry Point (Menu Logic) ---

def print_animated_separator(char="=", delay=0.005):
    print(f"{DIM}", end='', flush=True)
    for _ in range(TERMINAL_WIDTH): print(char, end='', flush=True); time.sleep(delay)
    print(f"{RESET}")

def get_system_info():
    try: hostname = socket.gethostname()
    except: hostname = "unknown-host"
    try: s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); local_ip = s.getsockname()[0]; s.close()
    except: local_ip = "127.0.0.1"
    return hostname, local_ip, platform.system()

def display_startup_screen():
    # FIX: Suppressing TERM errors using 2>/dev/null
    os.system('cls 2>/dev/null' if os.name == 'nt' else 'clear 2>/dev/null')
    
    print(HUNTX_MAP) # NEW: Print the network map first
    print(HUNTX_BANNER)
    print(f"{BOLD}{GREEN}By Nafawat and Badproh{RESET}")
    print_animated_separator()
    disclaimer = "Disclaimer: Not all sites and/or proxies are guaranteed to work! By using this, you take full responsibility for your actions!"
    wrapped_disclaimer = textwrap.wrap(disclaimer, width=TERMINAL_WIDTH - 4)
    for line in wrapped_disclaimer: print(f"{YELLOW}{line}{RESET}")
    print_animated_separator()
    print(f"OS: {get_system_info()[2]}, IP: {get_system_info()[1]}")
    print(f"{YELLOW}Status: Stable (Config: Embedded){RESET}")
    print_animated_separator()
    try:
        if input(f"{BOLD}> {GREEN}Check for updates? [y/n]: {RESET}").lower() == 'y':
            print(f"{GREEN}Checking latest release...{RESET}")
        else:
            print(f"{GREEN}Proceeding to main menu.{RESET}")
    except: pass
    print(f"\n{GREEN}--- HuntX Tool Ready ---\n{RESET}")
    time.sleep(1)

# --- MENU FUNCTIONS ---

def display_recon_menu():
    os.system('cls 2>/dev/null' if os.name == 'nt' else 'clear 2>/dev/null')
    print("\n" + "="*5 + f" {BOLD}{GREEN}🗺️ Reconnaissance Sub-Menu {RESET}" + "="*5)
    print("Select a specific action:")
    print("-" * 40)
    print(f"{BOLD}[1]{RESET}. {CYAN}Passive Subdomain Enumeration (subfinder/host){RESET}")
    print(f"{BOLD}[2]{RESET}. {CYAN}Active Subdomain Bruteforce (wordlist check){RESET}")
    print(f"{BOLD}[3]{RESET}. {CYAN}Port Scanning (nmap mock){RESET}")
    print(f"{BOLD}[4]{RESET}. {CYAN}OSINT Gathering (osint_gather){RESET}")
    print(f"{BOLD}[R]{RESET}. {GREEN}Full Recon Pipeline (1+2+3+4){RESET}")
    print(f"{BOLD}[B]{RESET}. {YELLOW}Back to Main Menu{RESET}")
    print("-" * 40)

def display_other_tools_menu():
    os.system('cls 2>/dev/null' if os.name == 'nt' else 'clear 2>/dev/null')
    print("\n" + "="*5 + f" {BOLD}{RED}🔧 Vulnerability & Exploitation Tools {RESET}" + "="*5)
    print("Select a tool to launch directly:")
    print("-" * 40)
    print(f"{BOLD}[1]{RESET}. {RED}SSH Brute-Force (Hydra Mock){RESET}") 
    print(f"{BOLD}[2]{RESET}. {CYAN}Other Brute-Force (Hydra, requires manual target){RESET}")
    print(f"{BOLD}[3]{RESET}. {CYAN}Network Utility (Netcat, requires IP:PORT){RESET}") # Real Netcat Test
    print(f"{BOLD}[4]{RESET}. {CYAN}Exploitation (Metasploit, requires target){RESET}")
    print(f"{BOLD}[5]{RESET}. {CYAN}GUI Proxy (BurpSuite Launch){RESET}")
    print(f"{BOLD}[6]{RESET}. {CYAN}GUI Sniffer (Wireshark Launch){RESET}")
    print(f"{BOLD}[B]{RESET}. {YELLOW}Back to Main Menu{RESET}")
    print("-" * 40)

def handle_other_tools_menu():
    while True:
        display_other_tools_menu()
        choice = input(f"{RED}Enter your choice: {RESET}").strip().lower()
        if choice == 'b': return

        tool_map = {
            '1': 'hydra', # SSH Brute-Force
            '2': 'hydra', # Generic Hydra
            '3': 'netcat', # Real Netcat Test
            '4': 'metasploit',
            '5': 'burpsuite',
            '6': 'wireshark'
        }
        
        if choice in tool_map:
            tool_name = tool_map[choice]
            
            if choice == '1': # SSH Brute-Force (option 1)
                 # Target can be NONE, letting HydraWrapper try to find an SSH asset from SDB
                 target = "NONE"
                 print(f"{YELLOW}Attempting to automatically find SSH target from scanned assets...{RESET}")
            elif tool_name in ['hydra', 'netcat', 'metasploit']:
                 # Other tools require a manual target
                 target = input(f"{RED}Enter the {BOLD}target/asset{RESET} (e.g., example.com or IP:PORT): {RESET}").strip()
                 if not target: print(f"{YELLOW}[ERROR] Target required for {tool_name}.{RESET}"); time.sleep(1); continue
            else:
                 target = "NONE" # GUI tools don't need a specific in-app target passed

            orchestrator_main(tool_name, target)
        else:
            print(f"\n{YELLOW}[INVALID INPUT] Invalid choice.{RESET}")
            time.sleep(1)


# --- NEW HANDLER FOR DOMAIN/URL ANALYZER ---
def analyze_url_with_tools(target: str):
    """Mocks API calls to VirusTotal and other services."""
    print(f"\n{BOLD}{CYAN}--- Threat Intelligence Analysis for {target} ---{RESET}")
    
    # Simple Mock Logic for demonstration
    if "malicious" in target or "badsite" in target or "phish" in target:
        vt_score = (5, 90)
        phishing = True
    elif "example.com" in target or "google.com" in target:
        vt_score = (0, 90)
        phishing = False
    else:
        vt_score = (random.randint(0, 3), 90)
        phishing = random.choice([True, False])

    print(f"{BOLD}1. VirusTotal Score (MOCK):{RESET}")
    if vt_score[0] > 0:
        print(f"   {RED}🚨 Detections: {vt_score[0]}/{vt_score[1]} engines flagged this URL.{RESET}")
        print(f"   {DIM}   (Simulating flags from tools like Google Safe Browsing, etc.){RESET}")
    else:
        print(f"   {GREEN}✅ Detections: 0/{vt_score[1]} engines flagged this URL. (Clean){RESET}")

    print(f"\n{BOLD}2. Phishing/Spam Check (MOCK):{RESET}")
    if phishing:
        print(f"   {RED}⚠️ Warning: Potential Phishing/Spam indicators detected.{RESET}")
    else:
        print(f"   {GREEN}✅ No immediate spam/phishing flags found.{RESET}")
        
    print(f"\n{BOLD}3. Passive DNS (MOCK):{RESET}")
    print(f"   {CYAN}Associated IPs:{RESET} 192.168.1.1, 104.26.12.34 (and {random.randint(3, 10)} others)")

def handle_url_analyzer():
    os.system('cls 2>/dev/null' if os.name == 'nt' else 'clear 2>/dev/null')
    print("\n" + "="*5 + f" {BOLD}{MAGENTA}🔍 Domain/URL Analyzer {RESET}" + "="*5) # Used MAGENTA here
    print("This utility simulates checking a URL against threat intelligence databases (like VirusTotal).")
    print("-" * 40)
    
    target = input(f"{GREEN}Enter the Domain or URL to analyze (e.g., evil.com): {RESET}").strip()

    if not target:
        print(f"{YELLOW}[ERROR] Target cannot be empty.{RESET}"); time.sleep(1); return
    
    analyze_url_with_tools(target)
        
    try: input(f"\n{YELLOW}{BOLD}Press ENTER to return to the main menu...{RESET}")
    except: pass
# ---------------------------------------------


# --- HANDLER FOR PASSWORD UTILITY ---
def handle_password_utility():
    os.system('cls 2>/dev/null' if os.name == 'nt' else 'clear 2>/dev/null')
    print("\n" + "="*5 + f" {BOLD}{GREEN}🔒 Password Utility {RESET}" + "="*5)
    print("Select an option:")
    print("-" * 40)
    print(f"{BOLD}[1]{RESET}. {CYAN}Generate a Complex Password{RESET}")
    print(f"{BOLD}[2]{RESET}. {CYAN}Check Strength of a Password{RESET}")
    print(f"{BOLD}[B]{RESET}. {YELLOW}Back to Main Menu{RESET}")
    print("-" * 40)
    
    choice = input(f"{GREEN}Enter your choice: {RESET}").strip().lower()

    if choice == 'b':
        return
    elif choice == '1':
        print(f"\n{BOLD}>> PASSWORD GENERATOR <<{RESET}")
        
        # --- STRENGTH PROMPT ---
        print("\nDesired Strength:")
        print(f"  {BOLD}[4]{RESET}. {RED}Very Strong (Min length 8, Max Complexity){RESET}")
        print(f"  {BOLD}[3]{RESET}. {YELLOW}Strong (Min length 8, High Complexity){RESET}")
        print(f"  {BOLD}[2]{RESET}. {GREEN}Moderate (Min length 6, Medium Complexity){RESET}")
        print(f"{BOLD}[1]{RESET}. {DIM}Weak (Min length 4, Basic Complexity){RESET}")
        
        try:
            strength_choice = int(input(f"{GREEN}Enter Strength Level (1-4): {RESET}"))
            if strength_choice not in [1, 2, 3, 4]: raise ValueError
        except ValueError:
            print(f"{RED}Invalid strength choice. Defaulting to Moderate (2).{RESET}")
            strength_choice = 2

        min_len = 8 if strength_choice >= 3 else 6 if strength_choice == 2 else 4
        
        try:
            length = int(input(f"{GREEN}ENTER THE LENGTH THAT U WANT (min {min_len}): {RESET}"))
        except ValueError:
            print(f"{RED}Invalid length input. Defaulting to {min_len}.{RESET}"); length = min_len

        # Enforce minimum length based on strength choice
        if length < min_len:
            print(f"{YELLOW}Length is too low for this strength. Using minimum length {min_len}.{RESET}"); length = min_len
        
        # -----------------------------

        # Generate and check the password
        complex_pass = generate_complex_password(length, strength_choice)
        strength_rating = check_password_strength(complex_pass)

        print("\n--- RESULTS ---")
        print(f"Generated Password: {BOLD}{complex_pass}{RESET}")
        print(f"Password Length: {len(complex_pass)}")
        print(f"Password Strength Rating: {BOLD}{strength_rating}{RESET}")
    
    elif choice == '2':
        print(f"\n{BOLD}>> STRENGTH CHECKER <<{RESET}")
        password = input(f"{GREEN}Enter a password to check its strength: {RESET}")
        if not password: 
            print(f"{YELLOW}Password cannot be empty.{RESET}"); time.sleep(1); 
            handle_password_utility()
            return
        
        strength = check_password_strength(password)
        print(f"\nPassword Strength: {BOLD}{strength}{RESET}")
    else:
        print(f"\n{YELLOW}[INVALID INPUT] Invalid choice.{RESET}"); time.sleep(1); 
        handle_password_utility()
        return
        
    try: input(f"\n{YELLOW}{BOLD}Press ENTER to return to the password menu...{RESET}")
    except: pass
    handle_password_utility() # Loop back to the utility menu
# ---------------------------------------------


def handle_recon_menu():
    while True:
        display_recon_menu()
        choice = input(f"{GREEN}Enter your choice: {RESET}").strip().lower()
        if choice == 'b': return
        
        target = input(f"{GREEN}Enter the {BOLD}target{RESET} (domain/IP): {RESET}").strip()
        if not target: print(f"{YELLOW}[ERROR] Target cannot be empty.{RESET}"); time.sleep(1); continue

        action_map = {
            '1': 'subdomain_enum',
            '2': 'bruteforce_sub',
            '3': 'port_scan',
            '4': 'osint_gather',
            'r': 'RECON_FULL'
        }
        
        if choice in action_map:
            orchestrator_main(action_map[choice], target)
        else:
            print(f"\n{YELLOW}[INVALID INPUT] Invalid choice.{RESET}")
            time.sleep(1)

def handle_other_tools_menu():
    while True:
        display_other_tools_menu()
        choice = input(f"{RED}Enter your choice: {RESET}").strip().lower()
        if choice == 'b': return

        tool_map = {
            '1': 'hydra', # SSH Brute-Force
            '2': 'hydra', # Generic Hydra
            '3': 'netcat', # Real Netcat Test
            '4': 'metasploit',
            '5': 'burpsuite',
            '6': 'wireshark'
        }
        
        if choice in tool_map:
            tool_name = tool_map[choice]
            
            if choice == '1': # SSH Brute-Force (option 1)
                 # Target can be NONE, letting HydraWrapper try to find an SSH asset from SDB
                 target = "NONE"
                 print(f"{YELLOW}Attempting to automatically find SSH target from scanned assets...{RESET}")
            elif tool_name in ['hydra', 'netcat', 'metasploit']:
                 # Other tools require a manual target
                 target = input(f"{RED}Enter the {BOLD}target/asset{RESET} (e.g., example.com or IP:PORT): {RESET}").strip()
                 if not target: print(f"{YELLOW}[ERROR] Target required for {tool_name}.{RESET}"); time.sleep(1); continue
            else:
                 target = "NONE" # GUI tools don't need a specific in-app target passed

            orchestrator_main(tool_name, target)
        else:
            print(f"\n{YELLOW}[INVALID INPUT] Invalid choice.{RESET}")
            time.sleep(1)


def display_menu():
    os.system('cls 2>/dev/null' if os.name == 'nt' else 'clear 2>/dev/null')
    print("\n" + "="*5 + f" {BOLD}{GREEN}🕵️ HuntX Main Menu {RESET}" + "="*5)
    print("Select a Category:")
    print("-" * 40)
    print(f"{BOLD}[1]{RESET}. {CYAN}Reconnaissance{RESET} (Subdomain, OSINT, Port Scan)")
    print(f"{BOLD}[2]{RESET}. {RED}Vulnerability & Exploitation{RESET} (Full Scan, Launch Tools)")
    print(f"{BOLD}[3]{RESET}. {GREEN}Generate Security Report{RESET}")
    print(f"{BOLD}[4]{RESET}. {CYAN}Password Generator / Checker{RESET}")
    print(f"{BOLD}[5]{RESET}. {MAGENTA}Domain/URL Analyzer (VirusTotal Mock){RESET}")
    print(f"{BOLD}[6]{RESET}. {YELLOW}Exit Tool{RESET}")
    print("-" * 40)

def main():
    display_startup_screen()

    while True:
        display_menu()
        try:
            # Update prompt range to 1-6
            choice = input(f"{GREEN}Enter your choice (1-6): {RESET}").strip()
        except KeyboardInterrupt:
            choice = '6'

        if choice == '6':
            print(f"\n{YELLOW}👋 Exiting HuntX. Stay secure!{RESET}")
            sys.exit(0)
        elif choice == '1':
            handle_recon_menu()
        elif choice == '2':
            handle_other_tools_menu()
        elif choice == '3':
            target = input(f"{GREEN}Enter Session ID (or leave blank for new session): {RESET}").strip() or "DEFAULT_SESSION"
            orchestrator_main('REPORT', target)
        elif choice == '4':
            handle_password_utility()
        elif choice == '5': # <-- NEW HANDLER CALL
            handle_url_analyzer()
        else:
            print(f"\n{YELLOW}[INVALID INPUT] Please enter a number between 1 and 6.{RESET}"); time.sleep(0.5)

if __name__ == "__main__":
    main()