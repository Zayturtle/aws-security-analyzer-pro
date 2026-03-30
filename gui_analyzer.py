import json
from collections import Counter
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import matplotlib.pyplot as plt
import threading
from datetime import datetime

from aws_fetcher import fetch_logs_from_s3

PIN_CODE = "164231"
MAX_ATTEMPTS = 3
attempts = 0

ip_counter = Counter()
event_counter = Counter()
alerts = []
timeline_entries = []
attack_chain = []
failed_logins = 0
risk_score = 0


# ---------- LOGIN ----------
def login_screen():
    login = tk.Tk()
    login.title("Secure Access")
    login.geometry("280x180")
    login.configure(bg="#0f1115")
    login.resizable(False, False)

    tk.Label(
        login,
        text="AWS Analyzer Login",
        fg="white",
        bg="#0f1115"
    ).pack(pady=10)

    pin_entry = tk.Entry(login, show="*", justify="center")
    pin_entry.pack(pady=5)

    def check():
        global attempts
        if pin_entry.get() == PIN_CODE:
            login.destroy()
            main_app()
        else:
            attempts += 1
            if attempts >= MAX_ATTEMPTS:
                messagebox.showerror("LOCKED", "Too many attempts")
                login.destroy()
            else:
                messagebox.showerror("ERROR", f"Wrong PIN ({attempts}/3)")

    tk.Button(login, text="Login", command=check).pack(pady=8)
    login.mainloop()


# ---------- TIME ----------
def format_time(raw_time):
    try:
        dt = datetime.strptime(raw_time, "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- SCORING + THREAT CLASSIFICATION ----------
def score_event(event, record):
    if event.startswith(("List", "Describe", "Get")) or event == "AssumeRole":
        return 0, None, None, None

    if event in ["ListBuckets", "DescribeInstances"]:
        return 3, "LOW", "Recon", "Discovery"

    if event == "CreateAccessKey":
        return 10, "HIGH", "Credential Access", "Key Creation"

    if event in ["AttachUserPolicy", "PutUserPolicy"]:
        return 10, "HIGH", "Privilege Escalation", "Policy Abuse"

    if event in ["CreateUser", "CreateRole"]:
        return 6, "MEDIUM", "Persistence", "New Identity"

    if event in ["DeleteTrail", "StopLogging"]:
        return 12, "CRITICAL", "Defense Evasion", "Logging Disabled"

    if event == "DeleteBucket":
        return 10, "HIGH", "Impact", "Resource Destruction"

    if event == "ConsoleLogin":
        status = record.get("responseElements", {}).get("ConsoleLogin")
        if status == "Failure":
            return 6, "HIGH", "Credential Access", "Login Failure"

    return 0, None, None, None


def calculate_risk(score):
    if score >= 60:
        return "HIGH", "#ff4d4d"
    elif score >= 20:
        return "MEDIUM", "#ffb84d"
    else:
        return "LOW", "#66ff99"


# ---------- ALERTS ----------
def add_alert(severity, threat, category, event, user, ip, score):
    alerts.append({
        "severity": severity,
        "threat": threat,
        "category": category,
        "event": event,
        "user": user,
        "ip": ip,
        "score": score
    })

    tag = "high"
    if severity == "MEDIUM":
        tag = "medium"
    elif severity == "LOW":
        tag = "low"

    alerts_box.insert(
        tk.END,
        f"{severity} | {threat} | {category} | {event} | {user} | {ip} | +{score}\n",
        tag
    )


def add_timeline(time, threat, category, event, user, ip, severity, score):
    timeline_entries.append({
        "time": time,
        "threat": threat,
        "category": category,
        "event": event,
        "user": user,
        "ip": ip,
        "severity": severity,
        "score": score
    })

    timeline_box.insert(
        tk.END,
        f"{time} | {severity} | {threat} | {category} | {event} | {user} | {ip}\n"
    )


# ---------- ANOMALY DETECTION ----------
def detect_anomalies():
    global risk_score

    safe_values = ["amazonaws.com", "cloudtrail", "resource-explorer"]
    ip_threshold = 100
    event_threshold = 150

    for ip, count in ip_counter.items():
        if any(x in str(ip).lower() for x in safe_values):
            continue

        if ip == "Unknown" or "." not in ip:
            continue

        if count > ip_threshold:
            risk_score += 12
            add_alert("ANOMALY", "Anomaly", "External Spike", "IP Spike", "N/A", ip, 12)
            add_timeline(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Anomaly",
                "External Spike",
                "IP Spike",
                "N/A",
                ip,
                "ANOMALY",
                12
            )

    for event, count in event_counter.items():
        if event.startswith(("List", "Describe", "Get")) or event == "AssumeRole":
            continue

        if count > event_threshold:
            risk_score += 10
            add_alert("ANOMALY", "Anomaly", "Event Spike", event, "N/A", "N/A", 10)
            add_timeline(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Anomaly",
                "Event Spike",
                event,
                "N/A",
                "N/A",
                "ANOMALY",
                10
            )

    if failed_logins > 5:
        risk_score += 20
        add_alert("ANOMALY", "Credential Attack", "Brute Force", "Login Failures", "N/A", "N/A", 20)
        add_timeline(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Credential Attack",
            "Brute Force",
            "Login Failures",
            "N/A",
            "N/A",
            "ANOMALY",
            20
        )


# ---------- ATTACK CHAIN ----------
def detect_attack_chain():
    global risk_score

    unique_stages = list(dict.fromkeys(attack_chain))

    if len(unique_stages) >= 3:
        risk_score += 25
        chain_string = " -> ".join(unique_stages)

        add_alert(
            "CRITICAL",
            "Attack Chain",
            "Multi-Stage Attack",
            chain_string,
            "N/A",
            "N/A",
            25
        )

        add_timeline(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Attack Chain",
            "Multi-Stage Attack",
            chain_string,
            "N/A",
            "N/A",
            "CRITICAL",
            25
        )


# ---------- DASHBOARD ----------
def update_dashboard():
    failed_label.config(text=str(failed_logins), fg="#ffc107")
    alert_label.config(text=str(len(alerts)), fg="#ff4d4d")

    level, color = calculate_risk(risk_score)
    risk_label.config(text=str(risk_score), fg=color)
    level_label.config(text=level, fg=color)

    top_ip_list.delete(0, tk.END)
    event_list.delete(0, tk.END)

    for ip, count in ip_counter.most_common(5):
        top_ip_list.insert(tk.END, f"{ip} -> {count}")

    for event, count in event_counter.most_common(5):
        event_list.insert(tk.END, f"{event} -> {count}")


# ---------- SCAN ----------
def scan_logic():
    global failed_logins, risk_score

    logs_box.delete(1.0, tk.END)
    alerts_box.delete(1.0, tk.END)
    timeline_box.delete(1.0, tk.END)
    top_ip_list.delete(0, tk.END)
    event_list.delete(0, tk.END)

    ip_counter.clear()
    event_counter.clear()
    alerts.clear()
    timeline_entries.clear()
    attack_chain.clear()
    failed_logins = 0
    risk_score = 0

    logs_box.insert(tk.END, "Loading AWS logs...\n")

    logs = fetch_logs_from_s3(
        "xavier-security-lab-logs-154541629988",
        prefix="AWSLogs/154541629988/CloudTrail/"
    )

    for r in logs:
        event = r.get("eventName", "Unknown")
        user = r.get("userIdentity", {}).get("userName", "Unknown")
        ip = r.get("sourceIPAddress", "Unknown")
        raw_time = r.get("eventTime", "")
        time = format_time(raw_time)

        ip_counter[ip] += 1
        event_counter[event] += 1

        logs_box.insert(tk.END, f"{time} | {user} | {event} | {ip}\n")

        score, severity, threat, category = score_event(event, r)

        if score > 0:
            risk_score += score
            add_alert(severity, threat, category, event, user, ip, score)
            add_timeline(time, threat, category, event, user, ip, severity, score)

        if threat:
            attack_chain.append(threat)

        if category == "Login Failure":
            failed_logins += 1

    detect_anomalies()
    detect_attack_chain()
    update_dashboard()

    logs_box.insert(tk.END, "\nScan Complete\n")


def run_scan():
    threading.Thread(target=scan_logic, daemon=True).start()


# ---------- EXPORT ----------
def export_json():
    file = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON Files", "*.json")]
    )
    if not file:
        return

    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_score,
        "risk_level": calculate_risk(risk_score)[0],
        "failed_logins": failed_logins,
        "top_ips": [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(5)],
        "top_events": [{"event": event, "count": count} for event, count in event_counter.most_common(5)],
        "alerts": alerts,
        "timeline": timeline_entries,
        "attack_chain": list(dict.fromkeys(attack_chain))
    }

    with open(file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    messagebox.showinfo("Export", "Saved")


# ---------- GRAPH ----------
def show_graph():
    top = ip_counter.most_common(5)
    if not top:
        return

    ips = [x[0] for x in top]
    counts = [x[1] for x in top]

    plt.figure()
    plt.bar(ips, counts)
    plt.title("Top IP Activity")
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.show()


# ---------- UI ----------
def main_app():
    global logs_box, alerts_box, timeline_box
    global top_ip_list, event_list
    global failed_label, alert_label, risk_label, level_label

    root = tk.Tk()
    root.title("AWS Analyzer PRO")
    root.geometry("820x520")
    root.configure(bg="#0f1115")

    header = tk.Frame(root, bg="#111827", height=45)
    header.pack(fill="x")

    tk.Label(header, text="AWS Analyzer PRO", fg="white", bg="#111827").pack(side="left", padx=10)

    tk.Button(header, text="Scan", command=run_scan).pack(side="right", padx=5)
    tk.Button(header, text="Graph", command=show_graph).pack(side="right", padx=5)
    tk.Button(header, text="Export", command=export_json).pack(side="right", padx=5)

    top_frame = tk.Frame(root, bg="#0f1115")
    top_frame.pack(fill="x")

    def make_card(parent, title):
        frame = tk.Frame(parent, bg="#1b1f27", width=180, height=60)
        frame.pack_propagate(False)
        tk.Label(frame, text=title, fg="white", bg="#1b1f27").pack()
        val = tk.Label(frame, text="0", fg="#66ff99", bg="#1b1f27")
        val.pack()
        return frame, val

    card1, failed_label = make_card(top_frame, "Failed")
    card1.pack(side="left", padx=5)

    card2, alert_label = make_card(top_frame, "Alerts")
    card2.pack(side="left", padx=5)

    card3, risk_label = make_card(top_frame, "Score")
    card3.pack(side="left", padx=5)

    card4, level_label = make_card(top_frame, "Level")
    card4.pack(side="left", padx=5)

    main = tk.Frame(root, bg="#0f1115")
    main.pack(fill="both", expand=True)

    left = tk.Frame(main, bg="#0f1115", width=220)
    left.pack(side="left", fill="y", padx=5)

    tk.Label(left, text="Top IPs", fg="white", bg="#0f1115").pack(anchor="w")
    top_ip_list = tk.Listbox(left, height=8)
    top_ip_list.pack(fill="x", pady=5)

    tk.Label(left, text="Top Events", fg="white", bg="#0f1115").pack(anchor="w")
    event_list = tk.Listbox(left, height=8)
    event_list.pack(fill="x")

    right = tk.Frame(main, bg="#0f1115")
    right.pack(side="left", fill="both", expand=True)

    tabs = ttk.Notebook(right)
    tabs.pack(fill="both", expand=True)

    logs_tab = tk.Frame(tabs)
    alerts_tab = tk.Frame(tabs)
    timeline_tab = tk.Frame(tabs)

    tabs.add(logs_tab, text="Logs")
    tabs.add(alerts_tab, text="Alerts")
    tabs.add(timeline_tab, text="Timeline")

    logs_box = scrolledtext.ScrolledText(logs_tab)
    logs_box.pack(fill="both", expand=True)

    alerts_box = scrolledtext.ScrolledText(alerts_tab)
    alerts_box.pack(fill="both", expand=True)

    timeline_box = scrolledtext.ScrolledText(timeline_tab)
    timeline_box.pack(fill="both", expand=True)

    alerts_box.tag_config("high", foreground="red")
    alerts_box.tag_config("medium", foreground="orange")
    alerts_box.tag_config("low", foreground="#66ff99")

    root.mainloop()


# ---------- START ----------
login_screen()