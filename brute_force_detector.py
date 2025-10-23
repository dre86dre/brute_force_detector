#!/usr/bin/env python3

import re
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import sys

# -------------------- Timestamp parsing --------------------

def try_parse_timestamp(ts_str):

    """
    Attempt to parse a timestamp string using a few common formats.

    Returns a datetime on success, or None if parsing failed.
    We keep formats short to cover common syslog/apache styles.
    """
    if not ts_str:
        return None
    
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",           # e.g. "Oct 21 14:23:45"
        "%d/%b/%Y:%H:%M:%S",        # e.g. "21/Oct/2023:14:23:45"
    ]

    for fmt in formats:
        try: 
            dt = datetime.strptime(ts_str, fmt)
            # If the format has no year (like "%b %d %H:%M:%S"), add current year
            if "%Y" not in fmt:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None

# -------------------- Detection logic --------------------

def detect_bruteforce(logfile_path, pattern, time_window_seconds=300, threshold=20, require_time=True, verbose=False):

    """
    Scan the logfile and detect IPs that exeed 'threshold' attempts in a sliding window of 'time_window_seconds'.

    - logfile_path: path to logfile
    - pattern: compiled regex with at least group 'ip'; may have groups 'time', 'time2', 'time3'
    - require_time: when True, only timestamped matches are considered for windowed detection
    """

    logfile = Path(logfile_path)
    if not logfile.exists():
        raise FileNotFoundError(f"Log file not found: {logfile}")
    
    # Store parsed timestamps per IP (for windowed analysis) and raw counts per IP (fallback)
    ip_timestamps = defaultdict(list)
    ip_counts = defaultdict(int)

    with logfile.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            m = pattern.search(line)
            if not m:
                continue

            gd = m.groupdict()
            ip = gd.get("ip")
            if not ip:
                if verbose:
                    print(f"Line {lineno}: matched but no 'ip' group — skipping")
                continue

            # Keep a simple total count for fallback or reporting
            ip_counts[ip] += 1

            # Accept commonl;y used time group names: time, time2, time3
            time_str = gd.get("time") or gd.get("time2") or gd.get("time3")
            if time_str:
                dt = try_parse_timestamp(time_str)
                if dt:
                    ip_timestamps[ip].append(dt)
                elif verbose:
                    print(f"Line {lineno}: couldn't parse time '{time_str}'")
            elif require_time and verbose:
                # If timestamps are required and missing, note it in verbose mode
                print(f"Line {lineno}: no timestamp for matched event")

    # Analyse timestamps using deque as a sliding window (0(n) per IP)
    flagged = {}
    window = timedelta(seconds=time_window_seconds)

    for ip, times in ip_timestamps.items():
        if not times:
            continue
        times.sort()
        q = deque()
        max_in_window = 0
        for t in times:
            q.append(t)
            # Remove timestamps older than current - window
            while q and (t - q[0]) > window:
                q.popleft()
            if len(q) > max_in_window:
                max_in_window = len(q)
        if max_in_window >= threshold:
            flagged[ip] = {"max_hits_in_window": max_in_window, "total_hits": len(times), "time_window_seconds": time_window_seconds}
    
    # If no timestamp-based flags and we allow count-only mode, flag by totals
    if not flagged and ip_counts and not ip_timestamps and not require_time:
        for ip, c in ip_counts.items():
            if c >= threshold:
                flagged[ip] = {"max_hits_in_window": None, "total_hits": c, "time_window_seconds": None}

    return flagged

# -------------------- Regex and CLI helpers --------------------

def make_default_pattern():

    """
    Default regex: captures a timestamp (in one of several group names) and an IPv4 'ip' group.
    Modify or pass a custom --pattern if your logs differ.
    """
    p = (
        r"(?:(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})|"
        r"(?P<time2>\w{3} +\d{1,2} \d{2}:\d{2}:\d{2})|"
        r"(?P<time3>\d{1,2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}))?"
        r"[\s\S]*?(?:Failed password|Failed login|authentication failure|Invalid user|401).*?"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )
    return re.compile(p, flags=re.IGNORECASE)




def build_pattern_from_string(pattern_str):

    """Compile the user-provided regex and return it. Expect a named 'ip' group."""
    return re.compile(pattern_str, flags=re.IGNORECASE)




def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect brute-force attempts in log files")
    parser.add_argument("-l", "--logfile", required=True, help="Log file path")
    parser.add_argument("-p", "--pattern", help="Custom regex (must capture 'ip')")
    parser.add_argument("-w", "--time-window", type=int, default=300, help="Window in seconds (default 300)")
    parser.add_argument("-t", "--threshold", type=int, default=20, help="Attempts threshold in window")
    parser.add_argument("--allow-count-only", action="store_true", help="Fallback to counts if no timestamps")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print extra info during parsing")


    args = parser.parse_args(argv)


    if args.pattern:
        try:
            pattern = build_pattern_from_string(args.pattern)
        except re.error as e:
            print(f"Invalid regex pattern: {e}")
            sys.exit(2)
    else:
        pattern = make_default_pattern()


    try:
        flagged = detect_bruteforce(
            logfile_path=args.logfile,
            pattern=pattern,
            time_window_seconds=args.time_window,
            threshold=args.threshold,
            require_time=not args.allow_count_only,
            verbose=args.verbose,
        )
    except Exception as e:
        print(f"Error while scanning logs: {e}")
        sys.exit(1)


    if not flagged:
        print("No suspicious IPs found with the given settings.")
        return


    print("Potential brute-force sources:")
    for ip, info in flagged.items():
        if info["max_hits_in_window"] is None:
            print(f" - {ip}: {info['total_hits']} total hits (no time data)")
        else:
            print(f" - {ip}: {info['max_hits_in_window']} hits within {info['time_window_seconds']}s (total: {info['total_hits']})")


if __name__ == '__main__':
    main()