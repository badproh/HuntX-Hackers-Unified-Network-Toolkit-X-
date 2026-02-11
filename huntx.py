#!/usr/bin/env python3
import sys
import socket
import os
import textwrap
import colorama
import time
import json
import threading
import subprocess
import abc
import uuid
import re
import shutil
import stat
import tarfile
import zipfile
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timezone 
from enum import Enum
from colorama import init
import random 
import string
import requests
import concurrent.futures 

# --- INITIALIZATION ---
init(autoreset=True)

# --- ANSI COLOR CODES ---
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'
MAGENTA = '\033[95m'

# --- ASSETS ---
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

# --- TOOL MANAGER (Plug & Play Engine) ---
class ToolManager:
    BIN_DIR = "bin"
    TOOLS = {
        "ffuf": {
            "url": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz", 
            "type": "tar", 
            "bin": "ffuf"
        },
        "gobuster": {
            "url": "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_3.6.0_linux_amd64.tar.gz", 
            "type": "tar", 
            "bin": "gobuster"
        },
        "subfinder": {
            "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip", 
            "type": "zip", 
            "bin": "subfinder"
        },
        "nuclei": {
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip", 
            "type": "zip", 
            "bin": "nuclei"
        }
    }

    @staticmethod
    def get_path(tool):
        # 1. Local Bin
        local = os.path.join(os.getcwd(), ToolManager.BIN_DIR, tool)
        if os.path.exists(local): return local
        # 2. System Path
        sys_path = shutil.which(tool)
        if sys_path: return sys_path
        return None

    @staticmethod
    def ensure(tool):
        path = ToolManager.get_path(tool)
        if path: return path
        
        if tool in ToolManager.TOOLS:
            print(f"{YELLOW}[INSTALLER] {tool} missing. Auto-downloading...{RESET}")
            return ToolManager._download(tool)
        return None

    @staticmethod
    def _download(tool):
        if not os.path.exists(ToolManager.BIN_DIR): os.makedirs(ToolManager.BIN_DIR)
        meta = ToolManager.TOOLS[tool]
        try:
            r = requests.get(meta['url'], stream=True, timeout=60)
            r.raise_for_status()
            bio = io.BytesIO(r.content)
            
            if meta['type'] == 'tar':
                with tarfile.open(fileobj=bio, mode="r:gz") as t:
                    m = next((i for i in t.getmembers() if i.name.endswith(meta['bin'])), None)
                    if m: 
                        m.name = meta['bin']
                        t.extract(m, ToolManager.BIN_DIR)
            elif meta['type'] == 'zip':
                with zipfile.ZipFile(bio) as z:
                    for i in z.infolist():
                        if i.filename.endswith(meta['bin']):
                            i.filename = meta['bin']
                            z.extract(i, ToolManager.BIN_DIR)
            
            final = os.path.join(ToolManager.BIN_DIR, meta['bin'])
            os.chmod(final, os.stat(final).st_mode | stat.S_IEXEC)
            print(f"{GREEN}[SUCCESS] Installed {tool}{RESET}")
            return final
        except Exception as e:
            print(f"{RED}[ERROR] Install failed for {tool}: {e}{RESET}")
            return None

# --- MODELS & SDB ---
class SimpleBaseModel:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)
    
    # Recursive serialization helper
    def to_dict_recursive(self):
        def obj_to_dict(obj):
            if hasattr(obj, '__dict__'):
                return {k: obj_to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list):
                return [obj_to_dict(i) for i in obj]
            elif isinstance(obj, dict):
                return {k: obj_to_dict(v) for k, v in obj.items()}
            else:
                return str(obj)
        return obj_to_dict(self)

class AssetObject(SimpleBaseModel):
    def __init__(self, asset_key, status="discovered", ip_address=None, ports=None, findings=None):
        super().__init__(
            asset_key=asset_key, status=status, ip_address=ip_address, 
            ports=ports or [], findings=findings or []
        )

class FindingObject(SimpleBaseModel):
    def __init__(self, tool, name, severity, proof, description=None):
        super().__init__(
            tool=tool, name=name, severity=severity, proof=proof, 
            description=description, date=str(datetime.now())
        )

class PortDetail(SimpleBaseModel):
    def __init__(self, port, service="unknown", state="open"):
        super().__init__(port=port, service=service, state=state)

class SDB:
    # Initialize with empty structure
    data = {"target": "", "assets": {}, "findings": []}
    lock = threading.Lock()

    @staticmethod
    def init(target): 
        # FIX: Reset the entire database when a new target is set.
        # This keeps RAM clean but leaves reports/ files untouched.
        SDB.data = {
            "target": target, 
            "assets": {}, 
            "findings": []
        }
        print(f"{YELLOW}[*] Session memory cleared. New target set to: {target}{RESET}")
    
    @staticmethod
    def update_asset(asset_obj):
        with SDB.lock: SDB.data["assets"][asset_obj.asset_key] = asset_obj

    @staticmethod
    def add_finding(target_key, finding_obj):
        with SDB.lock:
            # Add to global list
            SDB.data["findings"].append(finding_obj)
            # Add to specific asset if exists
            if target_key in SDB.data["assets"]:
                SDB.data["assets"][target_key].findings.append(finding_obj)

    @staticmethod
    def save():
        if not os.path.exists("reports"): os.makedirs("reports")
        
        # Ensure target name is safe for filesystem
        target_name = SDB.data["target"] if SDB.data["target"] else "Unknown_Target"
        safe_t = re.sub(r'[^a-zA-Z0-9]', '_', target_name)
        
        # Unique Filename (Timestamp) -> NEVER Deletes Old Files
        fname = f"reports/{safe_t}_{int(time.time())}.json"
        
        # Serialize properly
        export_data = {
            "target": SDB.data["target"],
            "findings": [f.to_dict_recursive() for f in SDB.data["findings"]],
            "assets": {k: v.to_dict_recursive() for k, v in SDB.data["assets"].items()}
        }
        
        with open(fname, 'w') as f: f.write(json.dumps(export_data, indent=2))
        return fname

# --- UTILITIES ---
def gen_password(length, strength):
    chars = string.ascii_lowercase + string.digits
    if strength > 2: chars += string.ascii_uppercase
    if strength > 3: chars += string.punctuation
    return "".join(random.choices(chars, k=length))

def check_password_strength(pwd):
    score = 0
    if len(pwd) >= 8: score += 1
    if re.search(r"\d", pwd): score += 1
    if re.search(r"[A-Z]", pwd): score += 1
    if re.search(r"\W", pwd): score += 1
    return ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(score, 4)]

# --- WRAPPERS ---

class SubfinderWrapper:
    def run(self, target):
        print(f"\n{CYAN}[SUBFINDER] Passive Enumeration...{RESET}")
        bin_path = ToolManager.ensure("subfinder")
        if not bin_path: return
        
        try:
            cmd = [bin_path, "-d", target, "-silent", "-all"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            subs = [l.strip() for l in res.stdout.splitlines() if l.strip()]
            
            print(f"{GREEN}>> Found {len(subs)} subdomains.{RESET}")
            for s in subs:
                print(f" + {s}")
                SDB.update_asset(AssetObject(asset_key=s, status="discovered"))
        except Exception as e: print(f"{RED}[ERROR] Subfinder: {e}{RESET}")

class ActiveReconWrapper:
    def run(self, target):
        print(f"\n{CYAN}[ACTIVE RECON] FFUF + Gobuster Pipeline...{RESET}")
        ffuf = ToolManager.ensure("ffuf")
        gob = ToolManager.ensure("gobuster")
        
        # Wordlist
        wlist = "subdomains.txt"
        if not os.path.exists(wlist):
            print(f"{YELLOW}>> Downloading wordlist...{RESET}")
            try:
                r = requests.get("https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt")
                with open(wlist, 'wb') as f: f.write(r.content)
            except: print(f"{RED}Wordlist DL failed.{RESET}"); return

        found = set()

        # Gobuster
        if gob:
            print(f"{YELLOW}>> Running Gobuster (DNS)...{RESET}")
            try:
                # Increased timeout to 600s (10 mins) for larger targets
                cmd = [gob, "dns", "-d", target, "-w", wlist, "-q", "--wildcard"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                for line in res.stdout.splitlines():
                    if "Found:" in line: found.add(line.split("Found:")[1].strip())
            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[WARN] Gobuster timed out (10m limit). Partial results used.{RESET}")
            except Exception as e: print(f"{RED}Gobuster Error: {e}{RESET}")

        # FFUF
        if ffuf:
            print(f"{YELLOW}>> Running FFUF (VHost)...{RESET}")
            try:
                # Increased timeout to 600s
                cmd = [ffuf, "-u", f"http://{target}", "-w", wlist, "-H", f"Host: FUZZ.{target}", "-mc", "200,302", "-s"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                for line in res.stdout.splitlines():
                    if line.strip(): found.add(f"{line.strip()}.{target}")
            except subprocess.TimeoutExpired:
                print(f"{YELLOW}[WARN] FFUF timed out (10m limit). Partial results used.{RESET}")
            except Exception as e: print(f"{RED}FFUF Error: {e}{RESET}")

        print(f"{GREEN}>> Active Recon finished. {len(found)} unique subdomains found.{RESET}")
        for s in found:
            print(f" + {s}")
            SDB.update_asset(AssetObject(asset_key=s, status="live"))

class PortScanWrapper:
    def run(self, target):
        print(f"\n{CYAN}[PORT SCAN] Hybrid Strategy Engine...{RESET}")
        
        # Determine Assets
        hosts = [k for k in SDB.data["assets"].keys()]
        if not hosts: 
            # If no subdomains found, scan the main target
            hosts = [target]
            # Ensure the main target is in the database
            SDB.update_asset(AssetObject(asset_key=target, status="live"))
        
        nmap_path = shutil.which("nmap")
        
        if nmap_path:
            self._nmap_scan(nmap_path, hosts)
        else:
            print(f"{YELLOW}[WARN] Nmap not found. Falling back to Python Native Scanner.{RESET}")
            self._native_scan(hosts)

    def _nmap_scan(self, bin_path, hosts):
        print(f"{YELLOW}>> Nmap detected. Running advanced scan...{RESET}")
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        flags = ["-sV", "-sC", "-T4", "-oX", "-"]
        if is_root: 
            print(f"{MAGENTA}[INFO] Running as Root: OS Detection (-O) Enabled.{RESET}")
            flags.insert(0, "-O")
        
        for host in hosts:
            print(f"Scanning {host}...")
            try:
                cmd = [bin_path] + flags + [host]
                res = subprocess.run(cmd, capture_output=True, text=True)
                
                # Basic XML parsing to avoid extra dependencies
                root = ET.fromstring(res.stdout)
                ports = []
                for port in root.findall(".//port"):
                    pid = port.get('portid')
                    state = port.find('state').get('state')
                    service_elem = port.find('service')
                    service = service_elem.get('name') if service_elem is not None else "unknown"
                    if state == 'open':
                        ports.append(PortDetail(pid, service))
                
                if ports:
                    print(f"{GREEN} + {host}: {len(ports)} ports found.{RESET}")
                    asset = SDB.data["assets"].get(host, AssetObject(host))
                    asset.ports = ports
                    asset.status = "scanned"
                    SDB.update_asset(asset)
                    
            except Exception as e: print(f"{RED}Nmap Error on {host}: {e}{RESET}")

    def _native_scan(self, hosts):
        print(f"{YELLOW}>> Starting Python Threaded Scanner...{RESET}")
        top_ports = [21,22,23,25,53,80,110,135,139,443,445,3306,3389,8080]
        
        def check(host, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((host, port)) == 0: return port
            except: pass
            return None

        for host in hosts:
            print(f"Scanning {host}...")
            open_p = []
            with concurrent.futures.ThreadPoolExecutor(max_threads=50) as ex:
                futures = [ex.submit(check, host, p) for p in top_ports]
                for f in concurrent.futures.as_completed(futures):
                    if f.result(): open_p.append(PortDetail(f.result()))
            
            if open_p:
                print(f"{GREEN} + {host}: {len(open_p)} ports found.{RESET}")
                asset = SDB.data["assets"].get(host, AssetObject(host))
                asset.ports = open_p
                asset.status = "scanned"
                SDB.update_asset(asset)

class NucleiWrapper:
    def run(self, target):
        print(f"\n{CYAN}[NUCLEI] Vulnerability Scan...{RESET}")
        bin_path = ToolManager.ensure("nuclei")
        if not bin_path: return

        urls = [f"http://{k}" for k in SDB.data["assets"].keys()]
        if not urls: urls = [f"http://{target}"]
        
        tfile = "targets.tmp"
        with open(tfile, "w") as f: f.write("\n".join(urls))
        
        try:
            print(f"{YELLOW}>> Scanning {len(urls)} targets...{RESET}")
            cmd = [bin_path, "-l", tfile, "-t", "technologies,misconfiguration", "-silent", "-json"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in res.stdout.splitlines():
                try:
                    data = json.loads(line)
                    name = data.get('info', {}).get('name', 'Unknown Vuln')
                    host = data.get('host')
                    print(f"{RED}[VULN] {name} at {host}{RESET}")
                    
                    SDB.add_finding(host, FindingObject("Nuclei", name, "High", line))
                except: pass
        except Exception as e: print(f"{RED}Nuclei Error: {e}{RESET}")
        if os.path.exists(tfile): os.remove(tfile)

class NetcatWrapper:
    def run(self, target):
        print(f"\n{CYAN}[NETCAT] Connectivity Test{RESET}")
        nc = shutil.which("nc") or shutil.which("netcat") or shutil.which("ncat")
        if not nc: print(f"{RED}[ERROR] Netcat not found.{RESET}"); return
        
        if ":" not in target: print(f"{RED}Format: IP:PORT{RESET}"); return
        ip, port = target.split(":")
        
        try:
            res = subprocess.run([nc, "-z", "-v", "-w", "1", ip, port], capture_output=True, text=True)
            out = res.stdout + "\n" + res.stderr
            
            if re.search(r"(succeeded|open|connected)", out, re.IGNORECASE):
                print(f"{GREEN}[SUCCESS] Port {port} is OPEN.{RESET}")
                SDB.add_finding(ip, FindingObject("Netcat", f"Port {port} Open", "Info", out))
            else:
                print(f"{YELLOW}[FAILED] Connection refused/timeout.{RESET}")
        except Exception as e: print(f"{RED}Exec Error: {e}{RESET}")

class HydraWrapper:
    def run(self, target):
        print(f"\n{CYAN}[HYDRA] SSH Brute Force{RESET}")
        hydra = shutil.which("hydra")
        if not hydra: print(f"{RED}[ERROR] Hydra not installed. Run 'sudo ./install.sh' first.{RESET}"); return
        
        user_list = "users.txt"
        pass_list = "passwords.txt"
        
        # Check if lists exist, else create dummies
        if not os.path.exists(user_list):
            with open(user_list, "w") as f: f.write("root\nadmin\nuser")
        if not os.path.exists(pass_list):
            with open(pass_list, "w") as f: f.write("123456\npassword\nroot")

        print(f"{YELLOW}>> Running Hydra against {target} (SSH)...{RESET}")
        cmd = [hydra, "-I", "-l", "root", "-P", pass_list, f"ssh://{target}", "-t", "4", "-f"]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            found = False
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None: break
                if output:
                    print(output.strip())
                    if "host:" in output.lower() and "login:" in output.lower():
                        found = True
                        SDB.add_finding(target, FindingObject("Hydra", "SSH Creds Found", "Critical", output.strip()))
            
            if found: print(f"{GREEN}[CRITICAL] Credentials Found! Saved to report.{RESET}")
            else: print(f"{DIM}No credentials found.{RESET}")
            
        except Exception as e: print(f"{RED}Hydra Error: {e}{RESET}")

# --- MENUS ---
def handle_password_menu():
    while True:
        print(f"\n{BOLD}--- Password Utility ---{RESET}")
        print("1. Generate Password")
        print("2. Check Strength")
        print("B. Back")
        c = input("Choice: ").lower()
        if c == 'b': return
        if c == '1':
            l_in = input("Length (min 8) [12]: ")
            l = int(l_in) if l_in else 12
            s_in = input("Strength (1-4) [4]: ")
            s = int(s_in) if s_in else 4
            print(f"{GREEN}Pass: {gen_password(l, s)}{RESET}")
        elif c == '2':
            p = input("Password: ")
            print(f"Strength: {check_password_strength(p)}")

def handle_recon_menu(target):
    print(f"\n{BOLD}--- Recon: {target} ---{RESET}")
    print("1. Passive (Subfinder)")
    print("2. Active (Ffuf + Gobuster)")
    print("3. Port Scan (Hybrid Nmap/Native)")
    print("4. Full Recon Pipeline (1+2+3)")
    print("B. Back")
    c = input("Choice: ").lower()
    
    if c == '1': SubfinderWrapper().run(target)
    elif c == '2': ActiveReconWrapper().run(target)
    elif c == '3': PortScanWrapper().run(target)
    elif c == '4':
        SubfinderWrapper().run(target)
        ActiveReconWrapper().run(target)
        PortScanWrapper().run(target)

def handle_vuln_menu(target):
    print(f"\n{BOLD}--- Vuln Tools ---{RESET}")
    print("1. Nuclei (Vuln Scan)")
    print("2. Netcat (Conn Check)")
    print("3. Hydra (SSH Brute)")
    print("4. Launch Wireshark (GUI)")
    print("B. Back")
    c = input("Choice: ").lower()
    
    if c == '1': NucleiWrapper().run(target)
    elif c == '2': 
        t = input(f"Target [{target}]: ") or target
        if ":" not in t: t = input("Enter IP:PORT: ")
        NetcatWrapper().run(t)
    elif c == '3':
        t = input(f"Target IP [{target}]: ") or target
        HydraWrapper().run(t)
    elif c == '4':
        print("Launching Wireshark...")
        try: subprocess.Popen(["wireshark"])
        except: print(f"{RED}Wireshark not found.{RESET}")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(HUNTX_MAP + HUNTX_BANNER)
        
        # Display current target status
        target_display = SDB.data['target'] if SDB.data['target'] else f"{DIM}None{RESET}"
        print(f"{BOLD}Target Session: {target_display}{RESET}")
        
        print("1. Set Target")
        print("2. Reconnaissance")
        print("3. Vulnerability Tools")
        print("4. Utilities (Password/URL)")
        print("5. Save & Generate Report")
        print("6. Exit")
        
        c = input(f"\n{GREEN}HuntX > {RESET}").lower()
        
        if c == '1': 
            t = input("Enter Target Domain/IP: ")
            if t: SDB.init(t)
        elif c == '2':
            if not SDB.data['target']: print(f"{RED}Set target first!{RESET}"); time.sleep(1); continue
            handle_recon_menu(SDB.data['target'])
            input("Press Enter...")
        elif c == '3': 
            if not SDB.data['target']: print(f"{RED}Set target first!{RESET}"); time.sleep(1); continue
            handle_vuln_menu(SDB.data['target'])
            input("Press Enter...")
        elif c == '4':
            print("1. Password Tools\n2. URL Analyzer (Mock)")
            sc = input("Choice: ")
            if sc == '1': handle_password_menu()
            elif sc == '2': print("Analyzing..."); time.sleep(1); print(f"{GREEN}Clean (Mock Result){RESET}")
            input("Press Enter...")
        elif c == '5':
            path = SDB.save()
            print(f"{GREEN}Report saved to: {path}{RESET}")
            input("Press Enter...")
        elif c == '6': sys.exit()

if __name__ == "__main__":
    main()