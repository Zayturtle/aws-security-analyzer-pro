# AWS Security Analyzer PRO

A Python-based GUI tool that analyzes AWS CloudTrail logs, detects suspicious activity, and displays results in a dashboard.

## Features
- CloudTrail log parsing
- Suspicious event detection
- Failed login detection
- Risk scoring
- Top IP tracking
- Top event tracking
- Alerts tab
- Logs tab
- Graph support

## Tech Stack
- Python
- Tkinter
- Matplotlib
- AWS CloudTrail Logs

## How to Run
1. Open the app
2. Click **Folder**
3. Choose the folder containing your `.json` CloudTrail logs
4. Click **Scan**
5. Review the results

## Build EXE
```bash
python -m PyInstaller --onefile --windowed gui_analyzer.py

## Screenshots

### Dashboard
![Dashboard](screenshots/dashboard.png)

### Alerts
![Alerts](screenshots/alerts.png)

### Graph
![Graph](screenshots/graph.png)