# RC1 Build - Final Verification
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

# Initialize Colors
init(autoreset=True)
GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'; CYAN = '\033[96m'
BOLD = '\033[1m'; DIM = '\033[2m'; RESET = '\033[0m'; MAGENTA = '\033[95m'

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
        "ffuf": {"url": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz", "type": "tar", "bin": "ffuf"},
        "gobuster": {"url": "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_3.6.0_linux_amd64.tar.gz", "type": "tar", "bin": "gobuster"},
        "subfinder": {"url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip", "type": "zip", "bin": "subfinder"},
        "nuclei": {"url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip", "type": "zip", "bin": "nuclei"}
    }

    @staticmethod
    def get_path(tool):
        local = os.path.join(os.getcwd(), ToolManager.BIN_DIR, tool)
        if os.path.exists(local): return local
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
                    if m: m.name = meta['bin']; t.extract(m, ToolManager.BIN_DIR)
            elif meta['type'] == 'zip':
                with zipfile.ZipFile(bio) as z:
                    for i in z.infolist():
                        if i.filename.endswith(meta['bin']):
                            i.filename = meta['bin']; z.extract(i, ToolManager.BIN_DIR)
            
            final = os.path.join(ToolManager.BIN_DIR, meta['bin'])
            os.chmod(final, os.stat(final).st_mode | stat.S_IEXEC)
            print(f"{GREEN}[SUCCESS] Installed {tool}{RESET}"); return final
        except Exception as e:
            print(f"{RED}[ERROR] Install failed for {tool}: {e}{RESET}"); return None

# --- MODELS & SDB ---
class SimpleBaseModel:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)
    def to_dict_recursive(self):
        def obj_to_dict(obj):
            if hasattr(obj, '__dict__'): return {k: obj_to_dict(v) for k, v in obj.__dict__.items()}
            elif isinstance(obj, list): return [obj_to_dict(i) for i in obj]
            elif isinstance(obj, dict): return {k: obj_to_dict(v) for k, v in obj.items()}
            else: return str(obj)
        return obj_to_dict(self)

class AssetObject(SimpleBaseModel):
    def __init__(self, asset_key, status="discovered", ip_address=None, ports=None, findings=None):
        super().__init__(asset_key=asset_key, status=status, ip_address=ip_address, ports=ports or [], findings=findings or [])

class FindingObject(SimpleBaseModel):
    def __init__(self, tool, name, severity, proof, description=None):
        super().__init__(tool=tool, name=name, severity=severity, proof=proof, description=description, date=str(datetime.now()))

class PortDetail(SimpleBaseModel):
    def __init__(self, port, service="unknown", state="open"):
        super().__init__(port=port, service=service, state=state)

class SDB:
    data = {"target": "", "assets": {}, "findings": []}
    lock = threading.Lock()

    @staticmethod
    def init(target): 
        SDB.data = {"target": target, "assets": {}, "findings": []}
        print(f"{YELLOW}[*] Session memory cleared. New target set to: {target}{RESET}")
    
    @staticmethod
    def update_asset(asset_obj):
        with SDB.lock: SDB.data["assets"][asset_obj.asset_key] = asset_obj

    @staticmethod
    def add_finding(target_key, finding_obj):
        with SDB.lock:
            SDB.data["findings"].append(finding_obj)
            if target_key in SDB.data["assets"]:
                SDB.data["assets"][target_key].findings.append(finding_obj)

    @staticmethod
    def save():
        if not os.path.exists("reports"): os.makedirs("reports")
        target_name = SDB.data["target"] if SDB.data["target"] else "Unknown_Target"
        safe_t = re.sub(r'[^a-zA-Z0-9]', '_', target_name)
        fname = f"reports/{safe_t}_{int(time.time())}.json"
        
        export_data = {
            "target": SDB.data["target"],
            "findings": [f.to_dict_recursive() for f in SDB.data["findings"]],
            "assets": {k: v.to_dict_recursive() for k, v in SDB.data["assets"].items()}
        }
        
        with open(fname, 'w') as f: f.write(json.dumps(export_data, indent=2))
        return fname

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
                SDB.update_asset(AssetObject(asset_key=s, status="discovered"))
        except Exception as e: print(f"{RED}[ERROR] Subfinder: {e}{RESET}")

class ActiveReconWrapper:
    def run(self, target):
        print(f"\n{CYAN}[ACTIVE RECON] FFUF + Gobuster Pipeline...{RESET}")
        ffuf = ToolManager.ensure("ffuf")
        gob = ToolManager.ensure("gobuster")
        wlist = "subdomains.txt"
        if not os.path.exists(wlist):
            try:
                r = requests.get("https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt")
                with open(wlist, 'wb') as f: f.write(r.content)
            except: print(f"{RED}Wordlist DL failed.{RESET}"); return

        found = set()
        if gob:
            print(f"{YELLOW}>> Running Gobuster (DNS)...{RESET}")
            try:
                cmd = [gob, "dns", "-d", target, "-w", wlist, "-q", "--wildcard"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                for line in res.stdout.splitlines():
                    if "Found:" in line: found.add(line.split("Found:")[1].strip())
            except subprocess.TimeoutExpired: print(f"{YELLOW}[WARN] Gobuster timed out.{RESET}")
            except Exception: pass

        if ffuf:
            print(f"{YELLOW}>> Running FFUF (VHost)...{RESET}")
            try:
                cmd = [ffuf, "-u", f"http://{target}", "-w", wlist, "-H", f"Host: FUZZ.{target}", "-mc", "200,302", "-s"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                for line in res.stdout.splitlines():
                    if line.strip(): found.add(f"{line.strip()}.{target}")
            except subprocess.TimeoutExpired: print(f"{YELLOW}[WARN] FFUF timed out.{RESET}")
            except Exception: pass

        print(f"{GREEN}>> Active Recon: {len(found)} unique subdomains.{RESET}")
        for s in found: SDB.update_asset(AssetObject(asset_key=s, status="live"))

class PortScanWrapper:
    def run(self, target):
        print(f"\n{CYAN}[PORT SCAN] Hybrid Strategy...{RESET}")
        hosts = [k for k in SDB.data["assets"].keys()]
        if not hosts: 
            hosts = [target]
            SDB.update_asset(AssetObject(asset_key=target, status="live"))
        
        nmap = shutil.which("nmap")
        if nmap:
            print(f"{YELLOW}>> Nmap detected.{RESET}")
            flags = ["-sV", "-sC", "-T4", "-oX", "-"]
            if (os.geteuid() == 0) if hasattr(os, "geteuid") else False: flags.insert(0, "-O")
            for host in hosts:
                print(f"Scanning {host}...")
                try:
                    res = subprocess.run([nmap] + flags + [host], capture_output=True, text=True)
                    root = ET.fromstring(res.stdout)
                    ports = []
                    for p in root.findall(".//port"):
                        if p.find('state').get('state') == 'open':
                            s = p.find('service').get('name') if p.find('service') is not None else "unknown"
                            ports.append(PortDetail(p.get('portid'), s))
                    if ports:
                        print(f"{GREEN} + {host}: {len(ports)} ports open.{RESET}")
                        asset = SDB.data["assets"].get(host, AssetObject(host))
                        asset.ports = ports; asset.status = "scanned"
                        SDB.update_asset(asset)
                except Exception: pass
        else:
            print(f"{YELLOW}[WARN] Using Native Scanner.{RESET}")
            top_p = [21,22,23,25,53,80,443,445,3306,8080]
            for host in hosts:
                print(f"Scanning {host}...")
                open_p = []
                with concurrent.futures.ThreadPoolExecutor(50) as ex:
                    fs = {ex.submit(self._sock_check, host, p): p for p in top_p}
                    for f in concurrent.futures.as_completed(fs):
                        if f.result(): open_p.append(PortDetail(f.result()))
                if open_p:
                    print(f"{GREEN} + {host}: {len(open_p)} ports open.{RESET}")
                    asset = SDB.data["assets"].get(host, AssetObject(host))
                    asset.ports = open_p; SDB.update_asset(asset)

    def _sock_check(self, h, p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((h, p)) == 0: return p
        except: pass
        return None

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
                    d = json.loads(line)
                    name = d.get('info', {}).get('name', 'Unknown')
                    host = d.get('host')
                    print(f"{RED}[VULN] {name} at {host}{RESET}")
                    SDB.add_finding(host, FindingObject("Nuclei", name, "High", line))
                except: pass
        except Exception: pass
        if os.path.exists(tfile): os.remove(tfile)

class NetcatWrapper:
    def run(self, target):
        print(f"\n{CYAN}[NETCAT] Connectivity...{RESET}")
        nc = shutil.which("nc") or shutil.which("netcat")
        if not nc: print(f"{RED}Netcat missing.{RESET}"); return
        if ":" not in target: print(f"{RED}Format: IP:PORT{RESET}"); return
        ip, port = target.split(":")
        try:
            res = subprocess.run([nc, "-z", "-v", "-w", "1", ip, port], capture_output=True, text=True)
            if re.search(r"(succeeded|open|connected)", res.stdout+res.stderr, re.IGNORECASE):
                print(f"{GREEN}[SUCCESS] Port {port} Open.{RESET}")
                SDB.add_finding(ip, FindingObject("Netcat", f"Port {port} Open", "Info", res.stdout+res.stderr))
            else: print(f"{YELLOW}Failed.{RESET}")
        except: pass

class HydraWrapper:
    def run(self, target):
        print(f"\n{CYAN}[HYDRA] SSH Brute Force...{RESET}")
        hydra = shutil.which("hydra")
        if not hydra: print(f"{RED}Hydra missing. Run install.sh.{RESET}"); return
        # Dummies for demo safety
        if not os.path.exists("users.txt"): open("users.txt","w").write("root\nadmin")
        if not os.path.exists("passwords.txt"): open("passwords.txt","w").write("123456\npassword")
        print(f"{YELLOW}>> Attacking {target}...{RESET}")
        try:
            p = subprocess.Popen([hydra, "-I", "-l", "root", "-P", "passwords.txt", f"ssh://{target}", "-t", "4", "-f"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while True:
                out = p.stdout.readline()
                if out == '' and p.poll() is not None: break
                if out: 
                    print(out.strip())
                    if "login:" in out.lower(): SDB.add_finding(target, FindingObject("Hydra", "Creds Found", "Critical", out.strip()))
        except: pass

# --- URL ANALYZER (REAL) ---
class URLAnalyzer:
    def run(self):
        url = input("Enter URL (e.g. google.com): ").strip()
        if not url.startswith("http"): url = "http://" + url
        print(f"\n{CYAN}Analyzing {url}...{RESET}")
        
        # 1. Headers (Requests)
        try:
            r = requests.get(url, timeout=5)
            print(f"{GREEN}[+] Status: {r.status_code}{RESET}")
            print(f"{YELLOW}>> Headers:{RESET}")
            for k, v in r.headers.items():
                if k.lower() in ['server', 'x-powered-by', 'strict-transport-security']:
                    print(f"    {k}: {v}")
        except Exception as e: print(f"{RED}[-] Connection failed: {e}{RESET}"); return

        # 2. WAF Detection (Wafw00f)
        waf = shutil.which("wafw00f")
        if waf:
            print(f"{YELLOW}>> Checking WAF...{RESET}")
            subprocess.run([waf, url], check=False)
        else:
            print(f"{DIM}[*] Wafw00f not installed. Skipping WAF check.{RESET}")

        # 3. Technology (Nuclei)
        print(f"{YELLOW}>> Detecting Tech Stack (Nuclei)...{RESET}")
        bin_path = ToolManager.ensure("nuclei")
        if bin_path:
            cmd = [bin_path, "-u", url, "-t", "technologies", "-silent"]
            subprocess.run(cmd, check=False)

# --- UTILITIES ---

def gen_password(length=12, complexity=4):
    """Generates a random password for the utility menu."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def check_password_strength(password):
    """Analyzes password strength and returns a colored rating."""
    score = 0
    if len(password) >= 8: score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c in string.punctuation for c in password): score += 1
    
    if score == 4: return f"{GREEN}Strong{RESET}"
    elif score >= 2: return f"{YELLOW}Medium{RESET}"
    return f"{RED}Weak{RESET}"

# --- MENUS ---
def handle_password_menu():
    print(f"\n{BOLD}--- Password Utility ---{RESET}")
    print("1. Generate Password")
    print("2. Check Strength")
    c = input("Choice: ")
    if c == '1': print(f"{GREEN}Pass: {gen_password(12, 4)}{RESET}")
    elif c == '2': print(f"Strength: {check_password_strength(input('Pwd: '))}")

def handle_full_auto(target):
    print(f"\n{MAGENTA}{BOLD}=== FULL AUTO MODE STARTED ==={RESET}")
    print(f"{DIM}Target: {target} | Time: {datetime.now().strftime('%H:%M:%S')}{RESET}")
    
    # 1. Recon
    SubfinderWrapper().run(target)
    ActiveReconWrapper().run(target)
    PortScanWrapper().run(target)
    
    # 2. Vuln
    NucleiWrapper().run(target)
    
    # 3. Save
    path = SDB.save()
    print(f"\n{GREEN}{BOLD}✅ FULL AUTO SCAN COMPLETE!{RESET}")
    print(f"Report saved to: {path}")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(HUNTX_MAP + HUNTX_BANNER)
        print(f"{BOLD}Target: {SDB.data['target'] if SDB.data['target'] else 'None'}{RESET}")
        print("1. Set Target")
        print(f"{MAGENTA}2. Full Auto Scan (Recon + Vuln + Report){RESET}")
        print("3. Manual Recon")
        print("4. Manual Vuln")
        print("5. Utilities (Password/URL)")
        print("6. Save Report")
        print("7. Exit")
        
        c = input(f"\n{GREEN}HuntX > {RESET}").lower()
        
        if c == '1': 
            t = input("Enter Target Domain/IP: ")
            if t: SDB.init(t)
        elif c == '2':
            if not SDB.data['target']: print(f"{RED}Set target first!{RESET}"); time.sleep(1); continue
            handle_full_auto(SDB.data['target'])
            input("Press Enter...")
        elif c == '3':
            if not SDB.data['target']: print(f"{RED}Set target first!{RESET}"); time.sleep(1); continue
            print("1. Passive\n2. Active\n3. Port Scan")
            sc = input("Choice: ")
            if sc=='1': SubfinderWrapper().run(SDB.data['target'])
            elif sc=='2': ActiveReconWrapper().run(SDB.data['target'])
            elif sc=='3': PortScanWrapper().run(SDB.data['target'])
            input("Press Enter...")
        elif c == '4':
            print("1. Nuclei\n2. Netcat\n3. Hydra")
            sc = input("Choice: ")
            if sc=='1': NucleiWrapper().run(SDB.data['target'])
            elif sc=='2': 
                t = input(f"Target [{SDB.data['target']}]: ") or SDB.data['target']
                if ":" not in t: t = input("Enter IP:PORT: ")
                NetcatWrapper().run(t)
            elif sc=='3': HydraWrapper().run(input("IP: "))
            input("Press Enter...")
        elif c == '5':
            print("1. Password Tools\n2. URL Analyzer")
            sc = input("Choice: ")
            if sc == '1': handle_password_menu()
            elif sc == '2': URLAnalyzer().run()
            input("Press Enter...")
        elif c == '6':
            path = SDB.save()
            print(f"{GREEN}Report saved: {path}{RESET}")
            input("Press Enter...")
        elif c == '7': sys.exit()

if __name__ == "__main__":
    main()