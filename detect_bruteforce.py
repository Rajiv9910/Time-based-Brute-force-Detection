import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def detect_bruteforce(log_path, threshold=5, window_minutes=2):
    """
    Detects time-based brute-force login attempts in a log file.

    Args:
        log_path (str or Path): Path to the log file.
        threshold (int): Number of failed attempts to trigger an alert.
        window_minutes (int): Time window in minutes for detection.
    """
    log_file = Path(log_path)

    if not log_file.exists():
        print(f"[ERROR] Log file not found: {log_file}")
        return
    
    ip_attempts = defaultdict(list)

    # Regex to capture timestamp + IP
    log_regex = re.compile(
        r"^(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (\d{1,3}(?:\.\d{1,3}){3})"
    )

    current_year = datetime.now().year

    # Parse log file
    with log_file.open("r", encoding="utf-8") as file:
        for line in file:
            match = log_regex.search(line)
            if match:
                timestamp_str = match.group(1)
                ip = match.group(2)

                # Add current year to avoid Python deprecation warning
                timestamp_str_with_year = f"{current_year} {timestamp_str}"
                timestamp = datetime.strptime(timestamp_str_with_year, "%Y %b %d %H:%M:%S")

                ip_attempts[ip].append(timestamp)
    
    # Analyze attempts per IP
    for ip, timestamps in ip_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            count = 1

            for j in range(i + 1, len(timestamps)):
                time_diff = (timestamps[j] - window_start).total_seconds()
                if time_diff <= window_minutes * 60:
                    count += 1
                else:
                    break

            if count >= threshold:
                print(f"[ALERT] {ip} had {count} failed attempts within {window_minutes} minutes")
                break

# USAGE
if __name__ == "__main__":
    LOG_FILE = Path(r"C:\Users\rajiv\OneDrive\Documents\CyberSecurity\Projects\python projects\Time-based Brute-force Detection\auth.log")
    detect_bruteforce(LOG_FILE, threshold=5, window_minutes=2)