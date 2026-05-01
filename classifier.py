# classifier.py - Malware type detection (heuristic, modular)
import re

def extract_strings(filepath, min_length=4):
    """
    Extract printable strings (ASCII) from a file.
    Works for any binary file.
    """
    strings = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            # extract sequences of printable ASCII characters (with spaces)
            pattern = rb"[ -~]{%d,}" % min_length
            for match in re.finditer(pattern, data):
                strings.append(match.group().decode("ascii", errors="ignore"))
    except Exception:
        pass
    return strings

def scan_keywords(strings):
    """
    Search for suspicious keywords in list of strings.
    Returns list of matched keywords.
    """
    suspicious = [
        "hack", "keylogger", "steal", "password", "encrypt",
        "remote", "upload", "ads", "popup", "banner",
        "log_keys", "input_capture", "decrypt", "lock_files",
        "obfuscated", "payload", "dropper", "crypto",
        "hidden", "phish", "exploit"
    ]
    found = []
    for s in strings:
        lower = s.lower()
        for kw in suspicious:
            if kw in lower and kw not in found:
                found.append(kw)
    return found

def detect_malware_type(permissions, keywords, risk_score):
    """
    Heuristic classification based on permissions and keywords.
    Returns:
        type_label (str)  e.g. "Spyware (High Risk)"
        reasons (list)    e.g. ["Uses READ_SMS", "Contains keyword: steal"]
    """
    reasons = []
    perms = [p.lower() for p in permissions]
    # Helper to check if any permission contains a string
    def has_perm(perm_fragment):
        for p in perms:
            if perm_fragment in p:
                return True
        return False

    # 1. Spyware: READ_SMS, READ_CONTACTS, RECORD_AUDIO (any one)
    if any(has_perm(p) for p in ["read_sms", "read_contacts", "record_audio"]):
        reasons.append("Uses sensitive permissions (SMS/Contacts/Microphone)")
        return "Spyware (High Risk)", reasons

    # 2. Keylogger: accessibility service + relevant keywords
    if has_perm("accessibility") and any(k in ["log_keys", "input_capture"] for k in keywords):
        reasons.append("Accessibility permission + keylogging keywords")
        return "Keylogger (Suspicious)", reasons

    # 3. Ransomware: encryption-related keywords
    if any(k in keywords for k in ["encrypt", "decrypt", "lock_files"]):
        reasons.append("Contains file encryption keywords")
        return "Ransomware (Possible)", reasons

    # 4. Adware: INTERNET + ads keywords
    if has_perm("internet") and any(k in keywords for k in ["ads", "popup", "banner"]):
        reasons.append("Internet permission + ad‑related keywords")
        return "Adware", reasons

    # 5. Trojan: INTERNET + suspicious keywords (obfuscated, remote, hack, etc.)
    trojan_kw = ["hack", "remote", "encrypt", "obfuscated", "payload", "dropper", "hidden", "exploit", "steal"]
    if has_perm("internet") and any(k in keywords for k in trojan_kw):
        reasons.append("Internet permission + suspicious keywords")
        return "Trojan (Possible)", reasons

    # 6. Any other suspicious keyword without specific permission triggers
    if keywords:
        reasons.append(f"Suspicious keywords found: {', '.join(keywords[:3])}")
        return "Suspicious (Unclassified)", reasons

    # Default
    return "Unknown", reasons
