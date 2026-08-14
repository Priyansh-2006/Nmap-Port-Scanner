import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import nmap
import threading
import json
import ipaddress
from datetime import datetime
from html import escape


# ==========================================================
# RISK ANALYSIS
# ==========================================================

def analyze_risk(port, service):

    high_risk = {
        21: "FTP is normally unencrypted. Prefer SFTP/FTPS where appropriate.",
        23: "Telnet is unencrypted. Replace it with SSH.",
        139: "Legacy NetBIOS/SMB exposure can increase attack surface.",
        445: "SMB exposure should be restricted to trusted networks.",
        512: "Rexec is a legacy insecure remote service.",
        513: "Rlogin is a legacy insecure remote service.",
        514: "Rsh is a legacy insecure remote service.",
        1524: "A bind shell is highly sensitive and should not be exposed.",
        6667: "IRC service is exposed. Verify that it is required."
    }

    medium_risk = {
        22: "SSH should use strong authentication and secure configuration.",
        25: "SMTP is exposed. Verify authentication and relay configuration.",
        53: "DNS is exposed. Restrict zone transfers and unnecessary access.",
        80: "HTTP is unencrypted. Use HTTPS where applicable.",
        3306: "MySQL should normally be restricted to trusted hosts.",
        5432: "PostgreSQL should normally be restricted to trusted hosts.",
        5900: "VNC exposure should be restricted and strongly authenticated.",
        8009: "AJP service exposure should be reviewed and restricted.",
        8180: "Tomcat HTTP service is exposed. Review administration access."
    }

    if port in high_risk:
        return "HIGH", high_risk[port]

    if port in medium_risk:
        return "MEDIUM", medium_risk[port]

    return "INFO", f"Review whether the {service} service is required."


# ==========================================================
# GUI APPLICATION
# ==========================================================

class NmapScannerGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("Nmap Security Scanner V8")
        self.root.geometry("1250x750")

        self.scanner = nmap.PortScanner()

        self.results = []
        self.target = ""
        self.scan_type = ""
        self.scan_time = ""
        self.total_open = 0

        self.build_gui()

    # ------------------------------------------------------
    # GUI
    # ------------------------------------------------------

    def build_gui(self):

        title = tk.Label(
            self.root,
            text="NMAP SECURITY SCANNER V8",
            font=("Arial", 24, "bold")
        )
        title.pack(pady=15)

        subtitle = tk.Label(
            self.root,
            text="Network Port • Service • Risk Analysis",
            font=("Arial", 11)
        )
        subtitle.pack()

        # Target frame
        target_frame = tk.Frame(self.root)
        target_frame.pack(pady=10)

        tk.Label(
            target_frame,
            text="Target IP:",
            font=("Arial", 12)
        ).pack(side=tk.LEFT, padx=5)

        self.target_entry = tk.Entry(
            target_frame,
            width=30,
            font=("Arial", 12)
        )
        self.target_entry.pack(side=tk.LEFT)

        # Scan type
        scan_frame = tk.Frame(self.root)
        scan_frame.pack(pady=5)

        tk.Label(
            scan_frame,
            text="Scan Type:",
            font=("Arial", 12)
        ).pack(side=tk.LEFT, padx=5)

        self.scan_type_box = ttk.Combobox(
            scan_frame,
            width=35,
            state="readonly",
            values=[
                "Quick Scan",
                "Service & Version Detection",
                "Full TCP Port Scan",
                "Full TCP + Service Detection"
            ]
        )

        self.scan_type_box.current(1)
        self.scan_type_box.pack(side=tk.LEFT)

        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        self.scan_button = tk.Button(
            button_frame,
            text="START SCAN",
            width=15,
            command=self.start_scan
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.json_button = tk.Button(
            button_frame,
            text="SAVE JSON",
            width=15,
            command=self.save_json,
            state=tk.DISABLED
        )
        self.json_button.pack(side=tk.LEFT, padx=5)

        self.html_button = tk.Button(
            button_frame,
            text="GENERATE HTML",
            width=15,
            command=self.generate_html,
            state=tk.DISABLED
        )
        self.html_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(
            button_frame,
            text="CLEAR",
            width=15,
            command=self.clear_results
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Status
        self.status_label = tk.Label(
            self.root,
            text="Ready",
            font=("Arial", 11)
        )
        self.status_label.pack(pady=5)

        # Table
        table_frame = tk.Frame(self.root)
        table_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=15,
            pady=10
        )

        columns = (
            "port",
            "protocol",
            "state",
            "service",
            "version",
            "risk"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "port": "Port",
            "protocol": "Protocol",
            "state": "State",
            "service": "Service",
            "version": "Version",
            "risk": "Risk"
        }

        for column, heading in headings.items():
            self.table.heading(column, text=heading)

        self.table.column("port", width=70)
        self.table.column("protocol", width=90)
        self.table.column("state", width=90)
        self.table.column("service", width=140)
        self.table.column("version", width=400)
        self.table.column("risk", width=90)

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        # Analysis
        self.analysis_label = tk.Label(
            self.root,
            text="Security Analysis: No scan performed.",
            font=("Arial", 11),
            justify=tk.LEFT
        )

        self.analysis_label.pack(pady=8)

    # ------------------------------------------------------
    # START SCAN
    # ------------------------------------------------------

    def start_scan(self):

        target = self.target_entry.get().strip()

        if not target:
            messagebox.showerror(
                "Invalid Target",
                "Please enter an IP address."
            )
            return

        try:
            ipaddress.ip_address(target)
        except ValueError:
            messagebox.showerror(
                "Invalid Target",
                "Please enter a valid IPv4 or IPv6 address."
            )
            return

        scan_selection = self.scan_type_box.get()

        scan_options = {
            "Quick Scan": "-F",
            "Service & Version Detection": "-sV",
            "Full TCP Port Scan": "-p-",
            "Full TCP + Service Detection": "-p- -sV"
        }

        arguments = scan_options[scan_selection]

        self.target = target
        self.scan_type = scan_selection
        self.scan_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        self.scan_button.config(state=tk.DISABLED)
        self.json_button.config(state=tk.DISABLED)
        self.html_button.config(state=tk.DISABLED)

        self.status_label.config(
            text=f"Scanning {target}..."
        )

        self.analysis_label.config(
            text="Security Analysis: Scanning..."
        )

        thread = threading.Thread(
            target=self.run_scan,
            args=(target, arguments),
            daemon=True
        )

        thread.start()

    # ------------------------------------------------------
    # RUN NMAP
    # ------------------------------------------------------

    def run_scan(self, target, arguments):

        try:

            self.scanner.scan(
                target,
                arguments=arguments
            )

            self.root.after(
                0,
                self.display_results,
                target
            )

        except Exception as error:

            self.root.after(
                0,
                self.scan_error,
                str(error)
            )

    # ------------------------------------------------------
    # DISPLAY RESULTS
    # ------------------------------------------------------

    def display_results(self, target):

        for item in self.table.get_children():
            self.table.delete(item)

        self.results = []
        self.total_open = 0

        if target not in self.scanner.all_hosts():

            self.status_label.config(
                text="Target unreachable or no results."
            )

            self.scan_button.config(
                state=tk.NORMAL
            )

            return

        high_count = 0
        medium_count = 0
        info_count = 0

        for protocol in self.scanner[target].all_protocols():

            ports = self.scanner[target][protocol].keys()

            for port in sorted(ports):

                info = self.scanner[target][protocol][port]

                state = info.get("state", "unknown")
                service = info.get("name", "unknown")
                product = info.get("product", "")
                version = info.get("version", "")

                version_text = (
                    f"{product} {version}"
                ).strip()

                if state == "open":
                    self.total_open += 1

                risk, recommendation = analyze_risk(
                    port,
                    service
                )

                if risk == "HIGH":
                    high_count += 1
                elif risk == "MEDIUM":
                    medium_count += 1
                else:
                    info_count += 1

                result = {
                    "port": port,
                    "protocol": protocol.upper(),
                    "state": state,
                    "service": service,
                    "version": version_text,
                    "risk": risk,
                    "recommendation": recommendation
                }

                self.results.append(result)

                self.table.insert(
                    "",
                    tk.END,
                    values=(
                        port,
                        protocol.upper(),
                        state,
                        service,
                        version_text,
                        risk
                    )
                )

        self.status_label.config(
            text=f"Scan complete — {self.total_open} open ports"
        )

        self.analysis_label.config(
            text=(
                f"Risk Summary   |   "
                f"HIGH: {high_count}   "
                f"MEDIUM: {medium_count}   "
                f"INFO: {info_count}"
            )
        )

        self.scan_button.config(
            state=tk.NORMAL
        )

        self.json_button.config(
            state=tk.NORMAL
        )

        self.html_button.config(
            state=tk.NORMAL
        )

    # ------------------------------------------------------
    # SAVE JSON
    # ------------------------------------------------------

    def save_json(self):

        if not self.results:
            return

        report = {
            "target": self.target,
            "scan_type": self.scan_type,
            "scan_time": self.scan_time,
            "total_open_ports": self.total_open,
            "results": self.results
        }

        filename = filedialog.asksaveasfilename(
            title="Save JSON Report",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json")
            ]
        )

        if not filename:
            return

        try:

            with open(
                filename,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    indent=4
                )

            messagebox.showinfo(
                "Success",
                f"JSON report saved:\n{filename}"
            )

        except Exception as error:

            messagebox.showerror(
                "Save Error",
                str(error)
            )

    # ------------------------------------------------------
    # GENERATE HTML
    # ------------------------------------------------------

    def generate_html(self):

        if not self.results:
            return

        filename = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            filetypes=[
                ("HTML files", "*.html")
            ]
        )

        if not filename:
            return

        rows = ""

        for item in self.results:

            rows += f"""
            <tr>
                <td>{escape(str(item["port"]))}</td>
                <td>{escape(item["protocol"])}</td>
                <td>{escape(item["state"])}</td>
                <td>{escape(item["service"])}</td>
                <td>{escape(item["version"])}</td>
                <td><strong>{escape(item["risk"])}</strong></td>
                <td>{escape(item["recommendation"])}</td>
            </tr>
            """

        html = f"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<title>Nmap Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 30px;
    color: #222;
}}

.container {{
    max-width: 1400px;
    margin: auto;
}}

.header {{
    background: #1f2937;
    color: white;
    padding: 25px;
    border-radius: 10px;
}}

.card {{
    background: white;
    margin-top: 20px;
    padding: 20px;
    border-radius: 10px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    background: #374151;
    color: white;
    padding: 12px;
    text-align: left;
}}

td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
}}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>Nmap Security Scan Report</h1>

<p>Automated Network Security Assessment</p>

</div>

<div class="card">

<h2>Scan Information</h2>

<p><strong>Target:</strong> {escape(self.target)}</p>

<p><strong>Scan Type:</strong> {escape(self.scan_type)}</p>

<p><strong>Scan Time:</strong> {escape(self.scan_time)}</p>

<p><strong>Open Ports:</strong> {self.total_open}</p>

</div>

<div class="card">

<h2>Port and Risk Analysis</h2>

<table>

<tr>
<th>Port</th>
<th>Protocol</th>
<th>State</th>
<th>Service</th>
<th>Version</th>
<th>Risk</th>
<th>Recommendation</th>
</tr>

{rows}

</table>

</div>

<div class="card">

<h2>Security Notice</h2>

<p>
Risk classifications in this report are rule-based indicators.
An open port does not by itself prove that a vulnerability exists.
Further authorized security testing is required to determine
actual vulnerability status.
</p>

</div>

</div>

</body>
</html>
"""

        try:

            with open(
                filename,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(html)

            messagebox.showinfo(
                "Success",
                f"HTML report saved:\n{filename}"
            )

        except Exception as error:

            messagebox.showerror(
                "Report Error",
                str(error)
            )

    # ------------------------------------------------------
    # CLEAR
    # ------------------------------------------------------

    def clear_results(self):

        for item in self.table.get_children():
            self.table.delete(item)

        self.results = []
        self.target = ""
        self.total_open = 0

        self.target_entry.delete(
            0,
            tk.END
        )

        self.status_label.config(
            text="Ready"
        )

        self.analysis_label.config(
            text="Security Analysis: No scan performed."
        )

        self.json_button.config(
            state=tk.DISABLED
        )

        self.html_button.config(
            state=tk.DISABLED
        )

    # ------------------------------------------------------
    # ERROR
    # ------------------------------------------------------

    def scan_error(self, error):

        self.status_label.config(
            text="Scan failed"
        )

        self.scan_button.config(
            state=tk.NORMAL
        )

        messagebox.showerror(
            "Nmap Error",
            error
        )


# ==========================================================
# START
# ==========================================================

root = tk.Tk()

app = NmapScannerGUI(root)

root.mainloop()
