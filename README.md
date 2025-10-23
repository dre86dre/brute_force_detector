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
python3 brute_force_detector.py -l test.log -w 300 -t 3 -v
```

Expected output:

```
Potential brute-force sources:
 - 1.2.3.4: 3 hits within 300s (total: 3)
 - 9.10.11.12: 4 hits within 300s (total: 6)
```

---

## Interpreting results

This means:

- The IP "1.2.3.4" made 3 failed attempts within the 5-minute window (and 3 attempts total in the scanned data).
- The IP "9.10.11.12" made 4 failed attempts within the 5-minute window (and 6 attempts total in the scanned data).

Use this information to investigate, tune thresholds, or block IPs (after verifying to avoid false positives).

---

## Contributing

Pull requests and issues are welcome. Suggestions:

- Add more timestamp formats in `try_parse_timestamp`.
- Add optional JSON/CSV output or integration with alerting systems.
- Add a `--tail` mode to watch logs live (careful with resource use).

---

## License

This project is licensed under the [MIT License](https://github.com/dre86dre/brute_force_detector/blob/main/LICENSE).
