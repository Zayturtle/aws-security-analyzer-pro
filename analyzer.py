import json
import os

def load_logs(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["Records"]

def analyze_logs(records, file_name):
    print(f"\n--- ANALYZING: {file_name} ---\n")

    event_count = {}

    for record in records:
        event = record.get("eventName")
        user = record.get("userIdentity", {}).get("userName", "Unknown")
        source_ip = record.get("sourceIPAddress")

        print(f"User: {user} | Event: {event} | IP: {source_ip}")

        event_count[event] = event_count.get(event, 0) + 1

        if event in ["DeleteBucket", "StopLogging", "PutBucketPolicy"]:
            print("⚠️  CRITICAL ACTION DETECTED")

        if event == "ConsoleLogin":
            login_status = record.get("responseElements", {}).get("ConsoleLogin")
            if login_status == "Failure":
                print("🚨 FAILED LOGIN DETECTED")

    print("\nEvent Summary:")
    for event, count in event_count.items():
        print(f"{event}: {count}")


def main():
    folder = "."  # current folder

    files = os.listdir(folder)

    for file in files:
        if file.endswith(".json"):
            try:
                records = load_logs(file)
                analyze_logs(records, file)
            except Exception as e:
                print(f"Error reading {file}: {e}")

main()