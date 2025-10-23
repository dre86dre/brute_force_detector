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

