import os, json, time

REPORTS_DIR = "/storage/emulated/0/EnoVirus/reports"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def save_report(report):
    """Save report as JSON."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"scan_{int(time.time())}.json"
    with open(os.path.join(REPORTS_DIR, filename), "w") as f:
        json.dump(report, f, indent=4)

def view_reports():
    """List saved reports and display the chosen one."""
    if not os.path.exists(REPORTS_DIR):
        print("No reports yet.")
        return
    reports = sorted(os.listdir(REPORTS_DIR))
    if not reports:
        print("No reports found.")
        return

    print("\n📊 Saved Reports")
    for i, r in enumerate(reports, 1):
        filepath = os.path.join(REPORTS_DIR, r)
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            # Decide what to show in list based on scan type
            if data.get("scan_type") == "github":
                print(f"[{i}] GitHub: {data.get('repo_url','')}  |  Score: {data.get('risk_score','?')}  |  Threats: {data.get('threats_found','?')}")
            else:
                print(f"[{i}] {data['file']}  |  Score: {data.get('risk_score','?')}  |  Threats: {data.get('threats_detected','?')}  |  {data.get('date','')}")
        except:
            print(f"[{i}] (corrupted file)")

    choice = input("\nEnter number to view full report (0 to back): ").strip()
    if choice == '0':
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(reports):
            filepath = os.path.join(REPORTS_DIR, reports[idx])
            with open(filepath, "r") as f:
                report = json.load(f)
            if report.get("scan_type") == "github":
                print_github_report(report)
            else:
                print_file_report(report)
            input("\nPress Enter to return to menu...")
        else:
            print("Invalid selection.")
            input("Press Enter to continue...")
    except Exception as e:
        print(f"Error reading report: {e}")
        input("Press Enter to continue...")

def colored_status(score):
    if score <= 30: return f"{GREEN}SAFE{RESET}"
    elif score <= 60: return f"{YELLOW}LOW RISK{RESET}"
    elif score <= 85: return f"{YELLOW}SUSPICIOUS{RESET}"
    else: return f"{RED}DANGEROUS{RESET}"

# ─── File scan report (unchanged) ───
def print_file_report(report):
    print("\n" + "=" * 40)
    print(f"🛡️  EnoVirus-Tester Report")
    print("=" * 40)
    print(f"File: {report['file']}")
    print(f"Path: {report.get('path', 'N/A')}")
    print(f"Type: {report.get('type', 'unknown')}")
    print(f"Size: {report.get('size', '?')} bytes")
    print(f"SHA256: {report.get('hash', 'N/A')}")

    total = report.get("total_scanned_files", 1)
    threats = report.get("threats_detected", 0)
    duration = report.get("scan_duration", "0.0")
    print(f"\nScan Summary:")
    print(f"- Files scanned: {total}")
    print(f"- Threats found: {threats}")
    print(f"- Scan time: {duration} sec")

    score = report.get("risk_score", 0)
    status_text = report.get("status", "UNKNOWN")
    malware = report.get("malware_type", "Unknown")

    print(f"\nFinal Result:")
    print(f"- Risk Score: {score}/100")
    print(f"- Status: {colored_status(score)}")
    print(f"- Malware Type: {malware}")

    reasons = report.get("reasons", [])
    if reasons:
        print(f"\nReasons:")
        for r in reasons:
            print(f"- {r}")

    contents = report.get("contents", [])
    if contents:
        print(f"\nContents:")
        for item in contents:
            fname = item.get("file", "?")
            iscore = item.get("risk_score", 0)
            istatus = item.get("status", "SAFE")
            if iscore <= 30: color_istat = f"{GREEN}{istatus}{RESET}"
            elif iscore <= 60: color_istat = f"{YELLOW}{istatus}{RESET}"
            elif iscore <= 85: color_istat = f"{YELLOW}{istatus}{RESET}"
            else: color_istat = f"{RED}{istatus}{RESET}"
            print(f"└── {fname} → {color_istat}")

    print(f"\nDate: {report.get('date', 'unknown')}")
    print("=" * 40)

# ─── NEW: GitHub online scan report ───
def print_github_report(report):
    print("\n" + "=" * 40)
    print(f"🌐 EnoVirus Online Scan Report")
    print("=" * 40)
    print(f"Repo: {report.get('repo_url', 'Unknown')}")
    print(f"Files scanned: {report.get('files_scanned', 0)}")
    print(f"Threats found: {report.get('threats_found', 0)}")
    duration = report.get("scan_duration", "0.0")
    print(f"Scan time: {duration} sec")

    score = report.get("risk_score", 0)
    print(f"\nFinal Risk Score: {score}/100")
    print(f"Status: {colored_status(score)}")

    reasons = report.get("reasons", [])
    if reasons:
        print(f"\nReasons:")
        for r in reasons:
            print(f"- {r}")

    suspicious = report.get("suspicious_files", [])
    if suspicious:
        print(f"\nSuspicious Files:")
        for f in suspicious:
            print(f"- {f}")

    print(f"\nDate: {report.get('date', 'Unknown')}")
    print("=" * 40)
