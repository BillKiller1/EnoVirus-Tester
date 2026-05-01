import os, subprocess, hashlib, time, sys, zipfile, shutil
from classifier import extract_strings, scan_keywords, detect_malware_type

# ─── ANSI colors (for terminal display only, never stored) ───
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
MAX_ZIP_DEPTH = 3
TEMP_DIR = "/storage/emulated/0/EnoVirus/temp"

# ─── Helper: plain text status label (no color) ───
def plain_status(score):
    if score <= 30:
        return "SAFE"
    elif score <= 60:
        return "LOW RISK"
    elif score <= 85:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"

def colored_status(score):
    """For terminal printing only."""
    if score <= 30:
        return f"{GREEN}SAFE{RESET}"
    elif score <= 60:
        return f"{YELLOW}LOW RISK{RESET}"
    elif score <= 85:
        return f"{YELLOW}SUSPICIOUS{RESET}"
    else:
        return f"{RED}DANGEROUS{RESET}"

# ─── Progress bar ───
def animate_progress_bar(title, duration=0.8):
    bar_length = 30
    print(f"\n{CYAN}{title}{RESET}")
    for i in range(1, bar_length + 1):
        filled = '█' * i
        empty = '▒' * (bar_length - i)
        percent = int((i / bar_length) * 100)
        sys.stdout.write(f"\r  [{filled}{empty}] {percent}%")
        sys.stdout.flush()
        time.sleep(duration / bar_length)
    print()  # newline

# ─── File type & hash ───
def get_file_type(filepath):
    try:
        res = subprocess.run(["file", "-b", "--mime-type", filepath], capture_output=True, text=True)
        return res.stdout.strip()
    except:
        return "unknown"

def get_file_hash(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

# ─── APK permissions ───
def analyze_apk_permissions(apk_path):
    try:
        output = subprocess.check_output(["aapt", "d", "permissions", apk_path], text=True)
        perms = []
        for line in output.splitlines():
            if "uses-permission:" in line and "name=" in line:
                start = line.find("name='") + 6
                end = line.find("'", start)
                if start > 5 and end > start:
                    perms.append(line[start:end].strip())
        return perms
    except:
        return []

# ─── EICAR check ───
def contains_eicar(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return EICAR_STRING in f.read()
    except:
        return False

# ─── Risk score (unchanged) ───
def calculate_risk_score(permissions, file_type, config, eicar_found=False):
    if eicar_found:
        return 100
    if not file_type.startswith("application/vnd.android.package-archive"):
        return 0
    dangerous = config["dangerous_permissions"]
    weight = config["risk_weights"]["dangerous_permission"]
    score = 10
    for perm in permissions:
        if perm in dangerous:
            score += weight
    return min(score, config["risk_weights"]["max_score"])

# ─── Classification wrapper (used inside scanner) ───
def scan_with_classification(filepath, config, permissions, ftype):
    """Return (malware_type, reasons). Pure text, no color."""
    strings = extract_strings(filepath)
    keywords = scan_keywords(strings)
    if contains_eicar(filepath):
        return "EICAR Test File (Simulated Threat)", ["Contains EICAR virus test string"]
    return detect_malware_type(permissions, keywords, 0)

# ─── Scan a single extracted file (used for ZIP recursion) ───
def scan_extracted_file(filepath, config, depth=0):
    """Scan one file and return a dict with plain-text status."""
    ftype = get_file_type(filepath)
    fsize = os.path.getsize(filepath)
    fhash = get_file_hash(filepath)
    permissions = []
    if "android.package" in ftype:
        permissions = analyze_apk_permissions(filepath)

    eicar = contains_eicar(filepath)
    score = calculate_risk_score(permissions, ftype, config, eicar)
    status_text = plain_status(score)
    malware_type, reasons = scan_with_classification(filepath, config, permissions, ftype)

    result = {
        "file": os.path.basename(filepath),
        "path": filepath,
        "hash": fhash,
        "type": ftype,
        "size": fsize,
        "permissions": permissions,
        "risk_score": score,
        "status": status_text,       # plain text
        "malware_type": malware_type,
        "reasons": reasons,
        "date": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Recurse into nested ZIPs if depth allows
    if ("zip" in ftype or filepath.lower().endswith('.zip')) and depth < MAX_ZIP_DEPTH:
        sub_temp = os.path.join(os.path.dirname(filepath), f"_nested{depth+1}_")
        os.makedirs(sub_temp, exist_ok=True)
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                zf.extractall(sub_temp)
            nested_contents = []
            for root, dirs, files in os.walk(sub_temp):
                for fname in files:
                    inner_path = os.path.join(root, fname)
                    inner_res = scan_extracted_file(inner_path, config, depth + 1)
                    nested_contents.append(inner_res)
            result["contents"] = nested_contents
        except Exception as e:
            result["zip_error"] = str(e)
        finally:
            shutil.rmtree(sub_temp, ignore_errors=True)

    return result

# ─── Main ZIP handler ───
def scan_zip_file(filepath, config):
    """Extract, scan all contents, create summary with tree."""
    print(f"{CYAN}Detected ZIP archive. Extracting...{RESET}")

    # Prepare clean temp directory
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            zf.extractall(TEMP_DIR)
    except Exception as e:
        return {
            "file": os.path.basename(filepath),
            "path": filepath,
            "hash": get_file_hash(filepath),
            "type": "application/zip",
            "size": os.path.getsize(filepath),
            "risk_score": 0,
            "status": "ERROR",
            "malware_type": "Unknown",
            "reasons": [f"Extraction failed: {e}"],
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": 0,
            "total_scanned_files": 0,
            "threats_detected": 0,
            "contents": []
        }

    # Walk and scan all extracted files
    all_contents = []
    for root, dirs, files in os.walk(TEMP_DIR):
        for fname in files:
            full_path = os.path.join(root, fname)
            animate_progress_bar(f"Scanning: {fname}", 0.3)
            res = scan_extracted_file(full_path, config, depth=1)
            all_contents.append(res)

    # Clean temp
    shutil.rmtree(TEMP_DIR, ignore_errors=True)

    # Calculate overall risk and threats
    max_score = 0
    threats = 0
    for item in all_contents:
        max_score = max(max_score, item["risk_score"])
        if item["risk_score"] > 30:   # LOW RISK or higher
            threats += 1

    # Overall malware type: take the most severe from contents
    malware_type = "Unknown"
    reasons = []
    if any(c["risk_score"] == 100 and c.get("malware_type") == "EICAR Test File (Simulated Threat)" for c in all_contents):
        malware_type = "EICAR Test File (Simulated Threat)"
        reasons.append("Contains EICAR test string")
    elif threats > 0:
        # Determine main threat type based on highest score
        highest = max(all_contents, key=lambda x: x["risk_score"])
        malware_type = highest.get("malware_type", "Unknown")
        reasons.append("Malicious file found inside ZIP")
    else:
        malware_type = "Unknown"
        reasons.append("No threats detected in ZIP contents")

    total_files = len(all_contents) + 1   # +1 for the ZIP itself
    status_text = plain_status(max_score)

    return {
        "file": os.path.basename(filepath),
        "path": filepath,
        "hash": get_file_hash(filepath),
        "type": "application/zip",
        "size": os.path.getsize(filepath),
        "risk_score": max_score,
        "status": status_text,
        "malware_type": malware_type,
        "reasons": reasons,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_scanned_files": total_files,
        "threats_detected": threats,
        "contents": all_contents
    }

# ─── Main scan function (entry point) ───
def scan_file(filepath, config):
    start_time = time.time()
    ftype = get_file_type(filepath)

    # ZIP branch
    if "zip" in ftype or filepath.lower().endswith('.zip'):
        result = scan_zip_file(filepath, config)
        result["scan_duration"] = round(time.time() - start_time, 2)
        return result

    # ─── Non‑ZIP standard scan ───
    animate_progress_bar("1/5  Detecting file type...", 0.6)
    fsize = os.path.getsize(filepath)
    animate_progress_bar("2/5  Calculating SHA256 hash...", 0.8)
    fhash = get_file_hash(filepath)

    permissions = []
    if "android.package" in ftype:
        animate_progress_bar("3/5  Extracting APK permissions...", 0.7)
        permissions = analyze_apk_permissions(filepath)
    else:
        animate_progress_bar("3/5  Skipping APK permissions...", 0.4)

    animate_progress_bar("4/5  Scanning for malware indicators...", 0.5)
    malware_type, reasons = scan_with_classification(filepath, config, permissions, ftype)

    animate_progress_bar("5/5  Calculating risk score...", 0.5)
    eicar = contains_eicar(filepath)
    score = calculate_risk_score(permissions, ftype, config, eicar)
    status_text = plain_status(score)
    threats = 1 if score > 30 else 0

    # ─── Terminal display (colored) ───
    dangerous_set = set(config["dangerous_permissions"])
    print(f"\n{BOLD}File: {os.path.basename(filepath)}{RESET}")
    print(f"SHA256: {fhash}")
    print(f"Type: {ftype}")
    print(f"Size: {fsize} bytes")
    if permissions:
        print(f"\n{CYAN}Permissions:{RESET}")
        for p in permissions:
            mark = f"{RED}❌{RESET}" if p in dangerous_set else f"{GREEN}✔{RESET}"
            print(f"  {p} {mark}")
    else:
        print("No permissions extracted.")

    print(f"\n{BOLD}Risk Score: {score}/100{RESET}")
    print(f"Status: {colored_status(score)}")
    print(f"Malware Type: {malware_type}")
    if reasons:
        print("Reasons:")
        for r in reasons:
            print(f"  • {r}")

    duration = round(time.time() - start_time, 2)
    print(f"\nScan completed in {duration} sec")

    return {
        "file": os.path.basename(filepath),
        "path": filepath,
        "hash": fhash,
        "type": ftype,
        "size": fsize,
        "permissions": permissions,
        "risk_score": score,
        "status": status_text,
        "malware_type": malware_type,
        "reasons": reasons,
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration": duration,
        "total_scanned_files": 1,
        "threats_detected": threats,
        "contents": []   # non‑ZIP has no contents
    }
