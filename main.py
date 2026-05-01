#!/usr/bin/env python3
import os, sys, json, shutil, subprocess, time

# ─── Clear screen helper ───
def clear_screen():
    os.system('clear')

# ─── ANSI colors ───
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ─── Logo color mapping ───
LOGO_COLORS = {
    'white': '\033[97m',
    'green': '\033[92m',
    'blue': '\033[94m',
    'purple': '\033[95m',
    'cyan': '\033[96m',
    'yellow': '\033[93m',
    'red': '\033[91m',
}

# ─── Config paths ───
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
DEFAULT_CONFIG = {
    "base_dir": "/storage/emulated/0/EnoVirus",
    "dangerous_permissions": [
        "android.permission.SEND_SMS", "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS", "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION", "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO", "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS"
    ],
    "risk_weights": {
        "dangerous_permission": 15,
        "max_score": 100
    },
    "theme": "dark",
    "logo_color": "magenta"
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

config = load_config()
BASE_DIR = config["base_dir"]
IMPORT_DIR = os.path.join(BASE_DIR, "imported")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# ─── Auto-install EVT command ───
def ensure_evt_command():
    """Create the EVT wrapper script if it doesn't exist."""
    evt_path = "/data/data/com.termux/files/usr/bin/EVT"
    if os.path.exists(evt_path):
        return  # already installed

    tool_dir = os.path.dirname(os.path.abspath(__file__))
    script_content = f"""#!/data/data/com.termux/files/usr/bin/bash
cd "{tool_dir}" || exit
python main.py "$@"
"""
    try:
        with open(evt_path, "w") as f:
            f.write(script_content)
        os.chmod(evt_path, 0o755)
        print(f"{GREEN}✅ Auto-run command 'EVT' installed. Now you can type 'EVT' anywhere.{RESET}\n")
    except Exception as e:
        print(f"{YELLOW}⚠ Could not auto-install 'EVT': {e}{RESET}")
        print("You can still run the tool manually from its folder.\n")

# ─── Dependency check ───
def check_dependencies():
    missing = []
    for cmd in ["aapt", "file"]:
        if shutil.which(cmd) is None:
            missing.append(cmd)
    if missing:
        print(f"\n{YELLOW}⚠ Required packages missing: {', '.join(missing)}{RESET}")
        choice = input("Do you want to install them now? (y/n): ").strip().lower()
        if choice == 'y':
            for pkg in missing:
                print(f"Installing {pkg}...")
                subprocess.run(["pkg", "install", pkg, "-y"], check=False)
            still_missing = [c for c in missing if shutil.which(c) is None]
            if still_missing:
                print(f"{RED}Installation failed for: {', '.join(still_missing)}{RESET}")
                print("Please install them manually and restart.")
                sys.exit(1)
            else:
                print(f"{GREEN}Dependencies installed successfully!{RESET}\n")
                time.sleep(1)
        else:
            print(f"{RED}Cannot continue without required tools. Exiting.{RESET}")
            sys.exit(1)

# ─── Setup ───
def setup_system():
    for d in [IMPORT_DIR, REPORTS_DIR]:
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
    print(f"{GREEN}Setup completed successfully!{RESET}\n")
    time.sleep(1)

# ─── Big logo with credit ───
def show_logo():
    color_name = config.get("logo_color", "magenta").lower()
    if color_name in LOGO_COLORS:
        color_code = LOGO_COLORS[color_name]
    else:
        try:
            code_num = int(color_name)
            color_code = f"\033[{code_num}m"
        except:
            color_code = MAGENTA

    print(f"""
{color_code}{BOLD}
███████╗ ███╗   ██╗ ██████╗ ██╗   ██╗██╗██████╗ ██╗   ██╗███████╗
██╔════╝ ████╗  ██║██╔═══██╗██║   ██║██║██╔══██╗██║   ██║██╔════╝
█████╗   ██╔██╗ ██║██║   ██║██║   ██║██║██████╔╝██║   ██║███████╗
██╔══╝   ██║╚██╗██║██║   ██║╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║
███████╗ ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║██║  ██║╚██████╔╝███████║
╚══════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{RESET}
{CYAN}{BOLD}               🛡️ EnoVirus-Tester{RESET}
{CYAN}            Advanced File Analyzer{RESET}
{YELLOW}               Made by GamingLifeReal{RESET}
""")

# ─── Import from Downloads ───
def import_file():
    downloads_path = "/storage/emulated/0/Download"
    if not os.path.isdir(downloads_path):
        print(f"{RED}Downloads folder not found!{RESET}")
        manual = input("Do you want to enter a file path manually? (y/n): ").strip().lower()
        if manual == 'y':
            src = input("Full file path: ").strip()
            if os.path.isfile(src):
                _copy_to_import(src)
            else:
                print(f"{RED}File not found.{RESET}")
        return

    all_items = os.listdir(downloads_path)
    files = [f for f in all_items if os.path.isfile(os.path.join(downloads_path, f))]
    if not files:
        print(f"{YELLOW}No files found in Downloads folder.{RESET}")
        manual = input("Enter a full path manually? (y/n): ").strip().lower()
        if manual == 'y':
            src = input("Full file path: ").strip()
            if os.path.isfile(src):
                _copy_to_import(src)
            else:
                print(f"{RED}File not found.{RESET}")
        return

    print(f"\n{CYAN}📂 Files in Downloads:{RESET}")
    for i, fname in enumerate(files, 1):
        print(f"  [{i}] {fname}")
    print(f"  [0] Cancel")
    print(f"  [M] Enter manual path")
    choice = input("Select file: ").strip()
    if choice == '0':
        return
    if choice.upper() == 'M':
        src = input("Full file path: ").strip()
        if os.path.isfile(src):
            _copy_to_import(src)
        else:
            print(f"{RED}File not found.{RESET}")
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            src = os.path.join(downloads_path, files[idx])
            _copy_to_import(src)
        else:
            print(f"{RED}Invalid selection.{RESET}")
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")

def _copy_to_import(src):
    dest = os.path.join(IMPORT_DIR, os.path.basename(src))
    if os.path.exists(dest):
        print(f"{YELLOW}File already imported. Overwriting.{RESET}")
    try:
        shutil.copy2(src, dest)
        print(f"{GREEN}File imported successfully.{RESET}")
    except Exception as e:
        print(f"{RED}Import failed: {e}{RESET}")

# ─── Online GitHub Scan ───
def github_scan():
    from online_scanner import perform_github_scan
    from reports import save_report, print_github_report

    print(f"\n{CYAN}🌐 Online GitHub Scan{RESET}")
    url = input("Enter GitHub URL: ").strip()
    if not url:
        print(f"{RED}No URL entered.{RESET}")
        return

    result = perform_github_scan(url)
    if "error" in result:
        print(f"{RED}Scan failed: {result['error']}{RESET}")
        return

    save_report(result)
    print(f"\n{GREEN}Report saved.{RESET}")
    print_github_report(result)
    input("\nPress Enter to continue...")

# ─── Local file scan menu ───
def scan_menu():
    from scanner import scan_file
    from reports import save_report
    files = [f for f in os.listdir(IMPORT_DIR) if os.path.isfile(os.path.join(IMPORT_DIR, f))]
    if not files:
        print(f"{YELLOW}No files imported yet. Please import first.{RESET}")
        return
    print(f"\n{CYAN}Select file to scan:{RESET}")
    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")
    print("[0] Cancel")
    choice = input("> ").strip()
    if choice == "0":
        return
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(files):
            print(f"{RED}Invalid selection.{RESET}")
            return
        filepath = os.path.join(IMPORT_DIR, files[idx])
        result = scan_file(filepath, config)
        if result:
            save_report(result)
            print(f"{GREEN}Report saved.{RESET}")
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")

# ─── Settings ───
def settings_menu():
    while True:
        print(f"\n{CYAN}⚙️ SETTINGS{RESET}")
        print("[1] Clear all reports")
        print("[2] Reset system (delete all imported files & reports)")
        print("[3] Change logo color")
        print("[4] Back")
        choice = input("> ").strip()
        if choice == "1":
            confirm = input("Delete all reports? (y/n): ").strip().lower()
            if confirm == 'y':
                for f in os.listdir(REPORTS_DIR):
                    os.remove(os.path.join(REPORTS_DIR, f))
                print(f"{GREEN}Reports cleared.{RESET}")
        elif choice == "2":
            confirm = input("This will delete ALL data (imported files + reports). Confirm? (y/n): ").strip().lower()
            if confirm == 'y':
                shutil.rmtree(BASE_DIR, ignore_errors=True)
                os.makedirs(IMPORT_DIR, exist_ok=True)
                os.makedirs(REPORTS_DIR, exist_ok=True)
                print(f"{GREEN}System reset complete.{RESET}")
        elif choice == "3":
            change_logo_color()
        elif choice == "4":
            break
        else:
            print(f"{RED}Invalid option.{RESET}")

def change_logo_color():
    print(f"\n{CYAN}🎨 Change Logo Color{RESET}")
    print("Preset colors:")
    presets = list(LOGO_COLORS.keys())
    for i, name in enumerate(presets, 1):
        print(f"  [{i}] {name.capitalize()}")
    print(f"  [0] Cancel")
    print(f"  [C] Enter custom ANSI color code (e.g., 91 for bright red)")
    choice = input("Choose: ").strip()
    if choice == '0':
        return
    if choice.upper() == 'C':
        code = input("Enter ANSI code (number like 91): ").strip()
        if code:
            config["logo_color"] = code
            save_config()
            print(f"{GREEN}Logo color updated to custom ANSI [{code}].{RESET}")
        else:
            print(f"{RED}Invalid code.{RESET}")
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(presets):
            config["logo_color"] = presets[idx]
            save_config()
            print(f"{GREEN}Logo color changed to {presets[idx].capitalize()}.{RESET}")
        else:
            print(f"{RED}Invalid selection.{RESET}")
    except ValueError:
        print(f"{RED}Invalid input.{RESET}")

def save_config():
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)

# ─── Main menu ───
def main_menu():
    while True:
        print(f"\n{CYAN}{BOLD}📂 MAIN MENU{RESET}")
        print("[1] Import File")
        print("[2] Online GitHub Scan")
        print("[3] Scan File (Local)")
        print("[4] View Reports")
        print("[5] Settings")
        print("[6] Exit")
        choice = input("Select option: ").strip()
        if choice == "1":
            clear_screen()
            import_file()
        elif choice == "2":
            clear_screen()
            github_scan()
        elif choice == "3":
            clear_screen()
            scan_menu()
        elif choice == "4":
            clear_screen()
            from reports import view_reports
            view_reports()
        elif choice == "5":
            clear_screen()
            settings_menu()
        elif choice == "6":
            clear_screen()
            print(f"{GREEN}Saving logs and exiting...{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}Invalid option!{RESET}")
        clear_screen()
        show_logo()

# ─── Startup ───
def main():
    clear_screen()
    show_logo()
    check_dependencies()
    ensure_evt_command()   # Auto-install EVT if missing

    if not os.path.exists(BASE_DIR):
        print(f"{YELLOW}⚠ Setup not found!{RESET}")
        print("EnoVirus system is not initialized.")
        print("[1] Setup (Create required files)")
        print("[2] Exit")
        choice = input("Select: ").strip()
        if choice == "1":
            setup_system()
            clear_screen()
            show_logo()
        else:
            print("Exiting.")
            sys.exit(0)
    else:
        os.makedirs(IMPORT_DIR, exist_ok=True)
        os.makedirs(REPORTS_DIR, exist_ok=True)

    main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Interrupted. Exiting cleanly.{RESET}")
        sys.exit(0)
