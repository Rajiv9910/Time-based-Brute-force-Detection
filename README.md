# Time-Based Brute-Force Detector

Detects failed SSH login attempts from auth log files and raises alerts when a threshold is exceeded within a time window.

## Features

- Parses log files for failed password attempts
- Groups failed attempts by IP address
- Detects repeated failed logins within a configurable time window
- Raises alerts for suspicious activity

## Requirements

- Python 3.10 or higher
- Standard libraries: `re`, `collections`, `datetime`, `pathlib`

## How to Run

1. Place your log file in the project folder (or update the path in the script)
2. Run the script:

```bash
python detect_bruteforce.py