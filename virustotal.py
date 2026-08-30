import requests
import re
import time
import csv
import os

# ================= CONFIGURATION =================
# IMPORTANT:
API_KEY = "YOUR_NEW_VIRUSTOTAL_API_KEY"  
INPUT_FILE = "chk.txt"                
OUTPUT_CSV = "vt_originality_report.csv" 
PROGRESS_FILE = "checked_hashes.txt"  

# Free API: 4 requests per minute (1 per 15 seconds)
RATE_LIMIT_SECONDS = 15
# =================================================

def load_checked_hashes():
    """Load previously checked hashes to skip them if script restarts."""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, 'r') as f:
            return set(line.strip() for line in f)
    return set()

def save_checked_hash(hash_val):
    """Append a successfully checked hash to the progress file."""
    with open(PROGRESS_FILE, 'a') as f:
        f.write(hash_val + "\n")

def extract_hashes_from_file(file_path):
    """Extract SHA256 hashes (64 hex chars) from the input file."""
    hashes = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            # Regex to find a 64-character hexadecimal SHA256 hash
            match = re.search(r'[a-fA-F0-9]{64}', line)
            if match:
                hashes.append(match.group(0).lower())
    return hashes

def check_hash_vt(session, hash_val):
    """Query VirusTotal API for a single hash."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {
        "x-apikey": API_KEY,
        "Accept": "application/json"
    }
    try:
        response = session.get(url, headers=headers, timeout=30)
        return response
    except requests.exceptions.RequestException as e:
        print(f"  [!] Network error: {e}")
        return None

def parse_vt_response(response, hash_val):
    """
    Parse the JSON response.
    Returns: (Hash, Originality_Status, Signer, Malicious_Count, Suspicious_Count, Permalink)
    """
    if response is None:
        return (hash_val, "ERROR", "N/A", "N/A", "N/A", "N/A")

    if response.status_code == 404:
        return (hash_val, "NOT FOUND", "N/A", "N/A", "N/A", "N/A")

    if response.status_code == 429:
        return (hash_val, "RATE LIMITED", "N/A", "N/A", "N/A", "N/A")

    if response.status_code != 200:
        return (hash_val, f"HTTP {response.status_code}", "N/A", "N/A", "N/A", "N/A")

    try:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        
        # 1. Get Signature Information (This tells us if it's original)
        sig_info = attributes.get('signature_info', {})
        signer = sig_info.get('signer', 'N/A')          # e.g., "Microsoft Windows"
        issuer = sig_info.get('issuer', 'N/A')          # e.g., "Microsoft Windows Production PCA 2011"
        
        # 2. Get Malware Statistics
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        # 3. Determine Originality Status
        if "Microsoft" in signer or "Microsoft" in issuer:
            originality = "ORIGINAL (Microsoft Signed)"
        elif signer != "N/A" and signer != "":
            originality = f"3RD PARTY SIGNED ({signer})"
        else:
            originality = "UNSIGNED / NO SIGNATURE"
            
        # Add warning if malware is detected
        if malicious > 0:
            originality += " | !! MALWARE DETECTED !!"
        elif suspicious > 0:
            originality += " | (Suspicious)"
        
        permalink = f"https://www.virustotal.com/gui/file/{hash_val}"
        return (hash_val, originality, signer, malicious, suspicious, permalink)
        
    except (KeyError, ValueError) as e:
        return (hash_val, "PARSE ERROR", "N/A", "N/A", "N/A", "N/A")

def main():
    if API_KEY == "YOUR_NEW_VIRUSTOTAL_API_KEY":
        print("❌ ERROR: Please replace 'YOUR_NEW_VIRUSTOTAL_API_KEY' with your actual API key.")
        return

    print("📂 Reading hashes from file...")
    all_hashes = extract_hashes_from_file(INPUT_FILE)
    print(f"✅ Found {len(all_hashes)} SHA256 hashes.")

    checked_hashes = load_checked_hashes()
    remaining_hashes = [h for h in all_hashes if h not in checked_hashes]
    print(f"⏳ Already checked: {len(checked_hashes)}. Remaining: {len(remaining_hashes)}.")

    if not remaining_hashes:
        print("✅ All hashes have been checked already.")
        return

    # Open CSV file for writing results
    csv_exists = os.path.isfile(OUTPUT_CSV)
    csv_file = open(OUTPUT_CSV, 'a', newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_file)
    
    # Write header if file is new
    if not csv_exists:
        csv_writer.writerow(["SHA256", "Originality Status", "Signer", "Malicious", "Suspicious", "Permalink"])

    session = requests.Session()
    total = len(remaining_hashes)
    
    for idx, hash_val in enumerate(remaining_hashes, 1):
        print(f"\n[{idx}/{total}] Checking: {hash_val[:12]}...")

        # 1. Check the hash
        response = check_hash_vt(session, hash_val)
        
        # 2. Handle Rate Limiting (429)
        while response is not None and response.status_code == 429:
            print("  ⏳ Rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
            response = check_hash_vt(session, hash_val)

        # 3. Parse the response
        result = parse_vt_response(response, hash_val)
        
        # 4. Write to CSV
        csv_writer.writerow(result)
        csv_file.flush()  # Save immediately to disk

        # 5. Save progress to resume later
        save_checked_hash(hash_val)

        # 6. Print result to console
        print(f"  📊 Status: {result[1]} | Signer: {result[2]} | Malicious: {result[3]}")

        # 7. Respect rate limit (15 seconds) - Free API limit
        if idx < total:
            print(f"  ⏱️  Waiting {RATE_LIMIT_SECONDS} seconds...")
            time.sleep(RATE_LIMIT_SECONDS)

    csv_file.close()
    print(f"\n🎉 Done! Results saved to '{OUTPUT_CSV}'.")

if __name__ == "__main__":
    main()
