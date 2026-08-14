# Nmap Security Scanner

A Python-based network security assessment tool built around Nmap. The project provides a graphical interface for performing authorized TCP port scans, identifying services and versions, classifying basic security risks, and generating JSON and HTML reports.

## Features

- TCP port scanning using Nmap
- Quick port scanning
- Service and version detection
- Full TCP port scanning
- Full TCP scan with service/version detection
- Graphical User Interface (GUI)
- Port and service result visualization
- Rule-based security risk classification
- HIGH, MEDIUM, and INFO risk categories
- JSON report generation
- HTML security report generation
- IPv4/IPv6 target validation
- Background scanning to keep the GUI responsive
- Error handling and scan status information

## Technologies Used

- Python 3
- Nmap
- python-nmap
- Tkinter
- JSON
- HTML/CSS
- VMware
- Kali Linux
- Metasploitable 2

## Project Architecture

```text
Target IP
    |
    v
Tkinter GUI
    |
    v
Nmap Scanner
    |
    v
Port / Service Detection
    |
    +----------------+
    |                |
    v                v
Risk Analysis     Scan Results
    |                |
    +--------+-------+
             |
       +-----+-----+
       |           |
       v           v
     JSON         HTML
    Report       Report
