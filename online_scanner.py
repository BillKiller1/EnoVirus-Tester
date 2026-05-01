# online_scanner.py – Safe GitHub repository analysis (no code execution)
import os, subprocess, shutil, time, sys, re

# ─── ANSI colors for terminal only ───
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# File extensions to scan
SCAN_EXTENSIONS = {'.py', '.sh', '.js', '.php', '.json', '.txt'}

# ─── Pattern definitions and risk weights ───
TERMINAL_RISKS = [
    ("rm -rf", 25),
    ("curl | bash", 30),
    ("wget http", 20),
    ("chmod 777", 15),
]

PYTHON_RISKS = [
    ("os.system", 30),
    ("subprocess", 25),
    ("eval(", 20),
    ("exec(", 20),
]

JS_RISKS = [
    ("eval(", 20),
    ("fetch(", 15),
]

ALL_PATTERNS = TERMINAL_RISKS + PYTHON_RISKS + JS_RISKS

def clone_repo(url, dest_dir):
    """
    Clone a GitHub repository (shallow, depth 1) into dest_dir.
    Returns True on success, False on failure.
    """
    try:
        # Ensure git command is available
        if shutil.which("git") is None:
            print(f"{YELLOW}Git is not installed. Installing...{RESET}")
            subprocess.run(["pkg", "install", "git", "-y"], check=True)
            if shutil.which("git") is None:
                raise RuntimeError("Git installation failed.")
        subprocess.run(
            ["git", "clone", "--depth", "1", url, dest_dir],
            check=True, capture_output=True, text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}Clone failed: {e.stderr}{RESET}")
        return False
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        return False

def scan_file_for_patterns(filepath):
    """Return a list of matched pattern tuples (pattern_text, risk_score)."""
    matched = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().lower()
        for pattern, score in ALL_PATTERNS:
            if pattern.lower() in content:
                matched.append((pattern, score))
    except Exception:
        pass
    return matched

def scan_repo_folder(repo_path):
    suspicious_files = []
    max_risk = 0
    total_scanned = 0

    for root, dirs, files in os.walk(repo_path):
        if '.git' in dirs:
            dirs.remove('.git')
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS:
                continue
            filepath = os.path.join(root, fname)
            matched = scan_file_for_patterns(filepath)
            total_scanned += 1
            if matched:
                file_risk = min(sum(score for _, score in matched), 100)
                max_risk = max(max_risk, file_risk)
                suspicious_files.append({
                    "relative_path": os.path.relpath(filepath, repo_path),
                    "full_path": filepath,
                    "matched_patterns": [p for p, _ in matched],
                    "file_risk_score": file_risk
                })
    return suspicious_files, max_risk, total_scanned

def perform_github_scan(repo_url):
    # Basic URL validation
    if not repo_url.startswith("https://github.com/") or len(repo_url.strip()) < 20:
        return {
            "scan_type": "github",
            "repo_url": repo_url,
            "error": "Invalid GitHub URL. Must start with 'https://github.com/'."
        }

    start_time = time.time()
    scan_dir = f"/storage/emulated/0/EnoVirus/online_scan_{int(time.time())}"
    os.makedirs(scan_dir, exist_ok=True)

    print(f"{CYAN}Cloning repository...{RESET}")
    if not clone_repo(repo_url, scan_dir):
        shutil.rmtree(scan_dir, ignore_errors=True)
        return {
            "scan_type": "github",
            "repo_url": repo_url,
            "error": "Failed to clone repository."
        }

    print(f"{CYAN}Scanning files...{RESET}")
    suspicious_files, max_risk, total_scanned = scan_repo_folder(scan_dir)

    if max_risk <= 30:
        status = "SAFE"
    elif max_risk <= 60:
        status = "LOW RISK"
    elif max_risk <= 85:
        status = "SUSPICIOUS"
    else:
        status = "DANGEROUS"

    reasons = set()
    for file_info in suspicious_files:
        for pattern in file_info["matched_patterns"]:
            reasons.add(f'Contains "{pattern}"')

    suspicious_files.sort(key=lambda x: x["file_risk_score"], reverse=True)
    duration = round(time.time() - start_time, 2)

    # Clean up cloned repo
    shutil.rmtree(scan_dir, ignore_errors=True)

    report = {
        "scan_type": "github",
        "repo_url": repo_url,
        "files_scanned": total_scanned,
        "threats_found": len(suspicious_files),
        "risk_score": max_risk,
        "status": status,
        "reasons": sorted(list(reasons)),
        "suspicious_files": [s["relative_path"] for s in suspicious_files],
        "suspicious_files_details": suspicious_files,
        "scan_duration": duration,
        "date": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    return report
