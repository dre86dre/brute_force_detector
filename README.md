# Brute Force Detector

A simple, beginner-friendly Python script that scans log files and detects possible brute-force login attempts using regular expressions and a sliding time-window counter.

This repository contains a standalone script, `brute_force_detector.py`, that uses only the Python standard library and works from the command line.

---

## Features

- Matches common "failed login" log lines (SSH, Apache, etc.) using a configurable regex.
- Parses timestamps when available and counts attempts per IP inside a sliding time window.
- Falls back to total-count detection when timestamps are not available (optional).
- Small, readable codebase intended for learning and light-duty scanning.

---

## Requirements

- Python 3.8+ (uses only standard library modules)

---

## Usage

1. Clone this repository in Terminal:

```
git clone https://github.com/dre86dre/brute_force_detector.git 
```

2. Navigate to the folder:

```
cd brute_force_detector
```

3. Make the script executable (optional):

```
chmod +x brute_force_detector.py
```

4. Run the detector against the example test log provided in folder:

A basic test with a 5-minute window and threshold of 3 attempts

```
python3 brute_force_detector.py -l test_bruteforce.log -w 300 -t 3 -v
```

