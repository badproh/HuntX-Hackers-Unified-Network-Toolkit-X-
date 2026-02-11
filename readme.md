# HuntX (Hackers Unified Network Toolkit X)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)

**HuntX** is a modular, CLI-based offensive security framework designed to unify asset discovery, active reconnaissance, port scanning, and vulnerability assessment into a single "Plug & Play" workflow.

## 🚀 Key Features

* **Unified Toolchain:** Automatically manages and runs industry-standard tools:
    * **Recon:** Subfinder, FFUF, Gobuster.
    * **Scanning:** Nmap (with Native Python Socket fallback).
    * **Vulnerability:** Nuclei, Hydra, Netcat.
    * **Analysis:** Wafw00f, Custom URL Headers.
* **Plug & Play Engine:** The `ToolManager` automatically detects missing binaries (e.g., `nuclei`, `subfinder`) and downloads/configures them in a local `bin/` directory. No manual setup required for Go-based tools.
* **Hybrid Port Scanner:** Smart detection—uses `Nmap` if installed; automatically falls back to a custom **Multi-threaded Python Socket Scanner** if Nmap is missing.
* **Full Auto Mode:** One-click pipeline: `Recon` -> `Port Scan` -> `Vuln Scan` -> `JSON Report`.
* **Smart Session (SDB):** In-memory State Data Bus (SDB) handles data passing between modules and saves timestamped JSON reports.

## 📦 Installation

### Prerequisites
HuntX works best on Linux (Kali, Ubuntu, Debian).

### Quick Install (Recommended)
Run the installer to set up system dependencies (Nmap, Hydra, Wireshark, Wafw00f) and Python libraries.

```bash
# 1. Clone the repository
git clone [https://github.com/YOUR_USERNAME/HuntX.git](https://github.com/YOUR_USERNAME/HuntX.git)
cd HuntX

# 2. Run the installer (requires sudo for system tools)
chmod +x install.sh
sudo ./install.sh


### Manual Installation (Optional)
If you prefer not to use the installer script, you can set up the environment manually:

# 1. **Install System Dependencies (Kali/Debian):**
   ```bash
   sudo apt update
   sudo apt install nmap hydra wafw00f wireshark-common

# 2. **Install Python Dependencies:**
   ```bash
   pip3 install -r requirements.txt
   
# 3.**Run HuntX:**
   ```bash
   python3 huntx.py