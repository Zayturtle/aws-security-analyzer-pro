from aws_fetcher import fetch_logs_from_s3

BUCKET = "xavier-security-lab-logs-154541629988"

logs = fetch_logs_from_s3(
    BUCKET,
    prefix="AWSLogs/"   # THIS IS CRITICAL
)

print(f"\nLoaded {len(logs)} log records\n")

for log in logs[:10]:
    print(log.get("eventName"), "|", log.get("sourceIPAddress"))