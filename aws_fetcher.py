import boto3
import json
import gzip
from io import BytesIO

def fetch_logs_from_s3(bucket_name, prefix=""):
    s3 = boto3.client('s3', region_name='us-east-1')

    logs = []

    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    if "Contents" not in response:
        print("No files found in bucket")
        return logs

    for obj in response["Contents"]:
        key = obj["Key"]

        if key.endswith(".json") or key.endswith(".json.gz"):
            print(f"Fetching: {key}")

            file_obj = s3.get_object(Bucket=bucket_name, Key=key)
            raw = file_obj["Body"].read()

            try:
                if key.endswith(".gz"):
                    with gzip.GzipFile(fileobj=BytesIO(raw)) as gz:
                        content = gz.read().decode("utf-8")
                else:
                    content = raw.decode("utf-8")

                data = json.loads(content)

                if "Records" in data:
                    logs.extend(data["Records"])

            except Exception as e:
                print(f"Error processing {key}: {e}")

    return logs