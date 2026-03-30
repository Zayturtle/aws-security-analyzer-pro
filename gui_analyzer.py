import json
import os
from collections import Counter
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import scrolledtext
import matplotlib.pyplot as plt

# ---------- GLOBALS ----------
selected_folder = ""
ip_counter = Counter()
event_counter = Counter()
alerts = []
failed_logins = 0
risk_score = 0


# ---------- LOAD LOGS ----------
def load_logs(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)
    return data["Records"]


# ---------- UI ACTIONS ----------
def choose_folder():
    global selected_folder
    selected_folder = filedialog.askdirectory()
    folder_label.config(text=selected_folder)


def calculate_risk(score):
    if score >= 15:
        return "HIGH", "#ff4d4d"
    elif score >= 6:
        return "MEDIUM", "#ffb84d"
    else:
        return "LOW", "#66ff99"


def run_scan():
    global failed_logins, risk_score

    if not selected_folder:
        return

    logs_box.delete(1.0, tk.END)
    alerts_box.delete(1.0, tk.END)
    top_ip_list.delete(0, tk.END)
    event_list.delete(0, tk.END)

    ip_counter.clear()
    event_counter.clear()
    alerts.clear()
    failed_logins = 0
    risk_score = 0

    files = os.listdir(selected_folder)

    for file in files:
        if file.endswith(".json"):
            try:
                records = load_logs(os.path.join(selected_folder, file))

                for r in records:
                    event = r.get("eventName", "Unknown")
                    user = r.get("userIdentity", {}).get("userName", "Unknown")
                    ip = r.get("sourceIPAddress", "Unknown")

                    ip_counter[ip] += 1
                    event_counter[event] += 1

                    logs_box.insert(tk.END, f"{user} | {event} | {ip}\n")

                    # HIGH RISK
                    if event in ["DeleteBucket", "StopLogging", "DeleteTrail"]:
                        alerts_box.insert(tk.END, f"HIGH: {event} by {user}\n", "high")
                        alerts.append(event)
                        risk_score += 5

                    # MEDIUM RISK
                    elif event in ["CreateUser", "AttachUserPolicy"]:
                        alerts_box.insert(tk.END, f"MEDIUM: {event} by {user}\n", "medium")
                        alerts.append(event)
                        risk_score += 3

                    # FAILED LOGIN
                    if event == "ConsoleLogin":
                        status = r.get("responseElements", {}).get("ConsoleLogin")
                        if status == "Failure":
                            alerts_box.insert(tk.END, f"FAILED LOGIN: {ip}\n", "medium")
                            failed_logins += 1
                            risk_score += 2

            except Exception as e:
                logs_box.insert(tk.END, f"ERROR: {e}\n")

    update_dashboard()


def update_dashboard():
    failed_label.config(text=str(failed_logins))
    alert_label.config(text=str(len(alerts)))

    level, color = calculate_risk(risk_score)
    risk_label.config(text=str(risk_score), fg=color)
    level_label.config(text=level, fg=color)

    for ip, count in ip_counter.most_common(5):
        top_ip_list.insert(tk.END, f"{ip} → {count}")

    for event, count in event_counter.most_common(5):
        event_list.insert(tk.END, f"{event} → {count}")


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
root = tk.Tk()
root.title("AWS Analyzer")
root.geometry("820x520")
root.configure(bg="#0f1115")

# HEADER
header = tk.Frame(root, bg="#111827", height=45)
header.pack(fill="x")

tk.Label(header, text="AWS Analyzer", fg="white", bg="#111827",
         font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)

tk.Button(header, text="Folder", command=choose_folder, width=8).pack(side="right", padx=5)
tk.Button(header, text="Scan", command=run_scan, width=8).pack(side="right", padx=5)
tk.Button(header, text="Graph", command=show_graph, width=8).pack(side="right", padx=5)

folder_label = tk.Label(root, text="No folder selected", fg="gray", bg="#0f1115")
folder_label.pack(anchor="w", padx=10)

# DASHBOARD
top_frame = tk.Frame(root, bg="#0f1115")
top_frame.pack(fill="x", pady=5)

def make_card(parent, title, color):
    frame = tk.Frame(parent, bg="#1b1f27", width=160, height=60)
    frame.pack_propagate(False)

    tk.Label(frame, text=title, fg="white", bg="#1b1f27").pack(anchor="w", padx=5)
    value = tk.Label(frame, text="0", fg=color, bg="#1b1f27",
                     font=("Segoe UI", 14, "bold"))
    value.pack()

    return frame, value


card1, failed_label = make_card(top_frame, "Failed", "orange")
card1.pack(side="left", padx=5)

card2, alert_label = make_card(top_frame, "Alerts", "red")
card2.pack(side="left", padx=5)

card3, risk_label = make_card(top_frame, "Score", "green")
card3.pack(side="left", padx=5)

card4, level_label = make_card(top_frame, "Level", "green")
card4.pack(side="left", padx=5)

# MAIN
main = tk.Frame(root, bg="#0f1115")
main.pack(fill="both", expand=True)

# LEFT PANEL
left = tk.Frame(main, bg="#0f1115")
left.pack(side="left", fill="y", padx=5)

top_ip_list = tk.Listbox(left, width=25)
top_ip_list.pack(pady=5)

event_list = tk.Listbox(left, width=25)
event_list.pack(pady=5)

# TABS
tabs = ttk.Notebook(main)
tabs.pack(fill="both", expand=True)

logs_tab = tk.Frame(tabs)
alerts_tab = tk.Frame(tabs)

tabs.add(logs_tab, text="Logs")
tabs.add(alerts_tab, text="Alerts")

logs_box = scrolledtext.ScrolledText(logs_tab)
logs_box.pack(fill="both", expand=True)

alerts_box = scrolledtext.ScrolledText(alerts_tab)
alerts_box.pack(fill="both", expand=True)

alerts_box.tag_config("high", foreground="red")
alerts_box.tag_config("medium", foreground="orange")

root.mainloop()