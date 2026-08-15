# Nmap Security Scanner

A Python-based network security assessment tool built around Nmap. It provides a graphical interface for authorized TCP port scanning, service/version detection, basic rule-based risk analysis, and JSON/HTML report generation.

## 📌 Project Overview

The Nmap Security Scanner was developed as a cybersecurity learning project to understand:

- Network reconnaissance
- TCP port scanning
- Service and version enumeration
- Basic security risk identification
- Automated security reporting
- Python integration with Nmap
- GUI-based security tooling

The project was developed and tested in an isolated VMware cybersecurity lab using Kali Linux and Metasploitable 2.

---

## 🚀 Features

- 🔎 Quick TCP port scanning
- 🔎 Full TCP port scanning
- 🔍 Service and version detection
- 🖥️ Graphical User Interface using Tkinter
- ⚠️ Rule-based security risk classification
- 🔴 HIGH / 🟠 MEDIUM / 🔵 INFO risk levels
- 📄 JSON report generation
- 🌐 HTML report generation
- ✅ IPv4/IPv6 target validation
- 🧵 Background scanning to keep the GUI responsive
- 🛡️ Basic security recommendations
- ❌ Error handling for invalid targets and failed scans

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Application development |
| Nmap | Network scanning |
| python-nmap | Python/Nmap integration |
| Tkinter | Graphical user interface |
| JSON | Structured scan reports |
| HTML/CSS | Security reports |
| Kali Linux | Security testing environment |
| VMware | Virtual lab |
| Metasploitable 2 | Intentionally vulnerable lab target |

---

## 🧪 Scan Modes

| Scan Mode | Nmap Option | Description |
|---|---|---|
| Quick Scan | `-F` | Scans commonly used ports |
| Service & Version Detection | `-sV` | Identifies services and versions |
| Full TCP Port Scan | `-p-` | Scans TCP ports 1–65535 |
| Full TCP + Service Detection | `-p- -sV` | Scans all TCP ports and detects services/versions |

---

## 🔐 Risk Analysis

The scanner performs basic rule-based classification of detected services.

Examples:

| Service / Port | Risk | Reason |
|---|---|---|
| FTP / 21 | HIGH | Traditional FTP does not provide encryption |
| Telnet / 23 | HIGH | Credentials and traffic may be transmitted without encryption |
| SMB / 139, 445 | HIGH | Network file-sharing exposure should be restricted |
| Rexec / 512 | HIGH | Legacy insecure remote service |
| Rlogin / 513 | HIGH | Legacy insecure remote service |
| Rsh / 514 | HIGH | Legacy insecure remote service |
| Bind Shell / 1524 | HIGH | Highly sensitive legacy shell service |
| SSH / 22 | MEDIUM | Requires secure authentication/configuration |
| HTTP / 80 | MEDIUM | Traffic is normally unencrypted |
| MySQL / 3306 | MEDIUM | Database service should be access-controlled |
| PostgreSQL / 5432 | MEDIUM | Database service should be access-controlled |

> **Important:** Risk classifications are rule-based indicators. An open port does not prove that a vulnerability exists. Further authorized security assessment is required to determine actual vulnerabilities.

---

## 🖥️ Application Workflow

```text
                Target IP
                    │
                    ▼
             Tkinter GUI
                    │
                    ▼
              Nmap Scanner
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
    Port Detection      Service Detection
          │                   │
          └─────────┬─────────┘
                    ▼
              Risk Analysis
                    │
             ┌──────┴──────┐
             ▼             ▼
          JSON Report   HTML Report



🧪 Lab Environment

The project was tested in an isolated VMware environment:

┌──────────────────────┐
│      Kali Linux      │
│   Nmap Scanner V8    │
└──────────┬───────────┘
           │
           │ Virtual Network
           │
           ▼
┌──────────────────────┐
│    Metasploitable 2  │
│   Authorized Target  │
└──────────────────────┘

Example lab target:

Metasploitable 2 (isolated lab VM)

The target is an intentionally vulnerable virtual machine used for cybersecurity education and testing.

📊 Example Results

The scanner successfully identified multiple services on the Metasploitable laboratory target, including:

21/tcp    FTP
22/tcp    SSH
23/tcp    Telnet
25/tcp    SMTP
53/tcp    DNS
80/tcp    HTTP
139/tcp   NetBIOS
445/tcp   SMB
3306/tcp  MySQL
5432/tcp  PostgreSQL
5900/tcp  VNC
8180/tcp  HTTP/Tomcat

The V8 GUI also provides a risk summary such as:

HIGH: 9
MEDIUM: 9
INFO: 5


📄 Reports
JSON

The JSON report contains:

Target IP
Scan type
Scan timestamp
Number of open ports
Port information
Protocol
Service
Version
Risk classification
Security recommendation

HTML

The HTML report provides a browser-friendly security assessment containing:

Scan information
Port results
Service/version information
Risk levels
Security recommendations
Security notice

⚙️ Installation

 Requirements

Kali Linux / Linux
Python 3
Nmap
python-nmap
Tkinter

Clone the repository
git clone https://github.com/Priyansh-2006/Nmap-Port-Scanner.git
cd Nmap-Port-Scanner

Create virtual environment
python3 -m venv venv

Activate virtual environment
source venv/bin/activate

Install dependencies
pip install -r requirements.txt

Verify Nmap
nmap --version

▶️ Usage

Start the application:
python gui_scanner_v8.py

Enter an authorized target IP address.
Select a scan type:

Quick Scan
Service & Version Detection
Full TCP Port Scan
Full TCP + Service Detection

Click:
START SCAN

After the scan completes, you can:
SAVE JSON
GENERATE HTML
CLEAR

📁 Project Structure

Nmap-Port-Scanner/
│
├── gui_scanner_v8.py
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE

🔮 Future Improvements

Possible future versions may include:

CVE/CPE correlation
More advanced vulnerability analysis
Improved risk scoring
Scan history
Scan comparison
Additional report formats
Exportable security recommendations
Improved GUI design
Authentication and access controls


⚠️ Security & Authorization

This project is intended for:

Cybersecurity education
Authorized penetration-testing laboratories
Systems owned by the tester
Systems where explicit permission has been granted

Only scan systems that you own or have explicit authorization to test.

The author is not responsible for unauthorized or malicious use of this software.


👨‍💻 Author

Priyansh Saxena

BCA Student | Cybersecurity Enthusiast

Interested in:

Penetration Testing
Network Security
Ethical Hacking
Linux
Python
Cybersecurity Automation


📜 License

This project is licensed under the MIT License.
