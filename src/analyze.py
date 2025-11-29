

import re
import argparse
from collections import Counter
import pandas as pd
import os
from typing import Union

from user_agents import parse
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS


def extract(log_files: list):
    log_pattern = re.compile(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) saatriangle.org - '  # IP address
        r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] ' # Timestamp
        r'"(\w+)\s(.+?)\s(HTTP/\d\.\d)" ' # Request method, URL, HTTP version
        r'(\d{3}) (\d+|-)' # Status code and response size
        r' "-" '
        r'("([^"]*)")' # User-agent (optional)
    )

    rows = []
    for log_file in log_files:
        with open(log_file, "r") as f:
            for line in f:
                match = log_pattern.match(line)
                if match:
                    ip_address, timestamp, method, url, http_version, status_code, response_size, _, user_agent_str = match.groups()
                    user_agent_obj = parse(user_agent_str)
                    print(f"User Agent: {user_agent_str}")
                    print(f"Browser Name: {user_agent_obj.browser.family}")
                    print(f"Browser Version: {user_agent_obj.browser.version_string}")
                    print(f"Operating System: {user_agent_obj.os.family}")
                    print(f"Operating System Version: {user_agent_obj.os.version_string}")
                    print(f"Device Type: {'Mobile' if user_agent_obj.is_mobile else 'Tablet' if user_agent_obj.is_tablet else 'Desktop'}")
                    print(f"Is a bot: {user_agent_obj.is_bot}")
                    print()
                    user_agent = user_agent_obj.browser.family if user_agent_obj.browser.family != "Other" else user_agent_str
                    rows.append((ip_address, timestamp, method, url, http_version, status_code, response_size, user_agent, user_agent_obj.is_bot))

    df = pd.DataFrame(rows, columns=['ip_address', 'timestamp', 'method', 'url', 'http_version', 'status_code', 'response_size', 'user_agent', 'is_bot'])
    return df


def output_hits(df: pd.DataFrame):
    user_agents = df['user_agent'].to_list()
    counts = Counter(user_agents)

    keys =  list(counts.keys())
    values = list(counts.values())
    combined = list(zip(values, keys))
    sorted_list = sorted(combined, reverse=True)

    print("=========== HITS ================")
    for v, k in sorted_list[0:20]:
        print(f"{k}: {v}")

def output_response_size(df: pd.DataFrame):
    response_size_dict = {}
    for index, row in df.iterrows():
        user_agent = row['user_agent']
        response_size = int(row['response_size'])
        if user_agent in response_size_dict:
            response_size_dict[user_agent] += response_size
        else:
            response_size_dict[user_agent] = response_size

    print("=========== RESPONSE SIZE ================")
    sorted_items_desc = sorted(response_size_dict.items(), key=lambda item: item[1], reverse=True)
    for k, v in dict(sorted_items_desc[0:20]).items():
        print(f"{k}: {v}")

def get_secret(key: str) -> Union[str, None]:
    """
    Glue code to integrate with docker compose secrets.

    Parameters
    ----------
    key : str
        Environmental variable pointing to secret file

    Returns
    -------
    Union[str, None]
        Return secret value.
    """
    # Check for _FILE suffix first
    file_env = f"{key}_FILE"
    if file_env in os.environ:
        with open(os.environ[file_env], "r") as f:
            return f.read().strip()
    # Fall back to environment variable
    return os.environ.get(key)

if __name__ == "__main__":
    # 1. Create an ArgumentParser object
    parser = argparse.ArgumentParser(
        description="A simple http access log analyzer"
    )

    # 2. Add arguments
    parser.add_argument("--logfiles", nargs='+', help="The http access log")
    parser.add_argument("--hits", action="store_true", help="Print out hit data")
    parser.add_argument("--size", action="store_true", help="Print out response size data")
    parser.add_argument("--output", default=None, help="Specify the path to the output file.")
    parser.add_argument("--influx", action="store_true", help="Write to influxdb")
    parser.add_argument("--batch", action="store_true", help="Write to influxdb")

    # 3. Parse the arguments
    args = parser.parse_args()

    if args.batch:
        directory_path = "/var/ssa/data"
        entries = os.listdir(directory_path)
        for f in entries:
            print(f)
        #df  = extract(logfiles)

    else:
        df = extract(args.logfiles)

    if args.hits:
         output_hits(df)
    if args.size:
         output_response_size(df)
    if args.output:
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        df['is_bot'] = df['is_bot'].astype(str)
        df['response_size'] = df['response_size'].astype(int)
        df.to_csv(args.output, index=False)
    if args.influx:
        url = "http://18.218.224.50:8086"
        org = "SAA"
        bucket = "SAA-Bucket"
        #token = get_secret("INFLUXDB_TOKEN")
        token = "PnANFW_6sLmiTOwY4lUjLBEKjpZrWF2QaW4_HIN_noooEoc0Bhjw6vnHnNUEha95r_X3NnZAWkYvj9t6oUK5XA=="
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        df['response_size'] = df['response_size'].astype(int)
        with InfluxDBClient(url=url, token=token, org=org) as client:
            # Create a write api instance
            write_api = client.write_api(write_options=SYNCHRONOUS)

            for index, row in df.iterrows():
                # ip_address,timestamp,method,url,http_version,status_code,response_size,user_agent,is_bot
                # Create a data point using the Point structure
                point = Point("http_access_log") \
                        .field("user_agent", row['user_agent']) \
                        .field("ip_address", row['ip_address']) \
                        .field("method", row['method']) \
                        .field("url", row['url']) \
                        .field("http_version", row['http_version']) \
                        .field("status_code", row['status_code']) \
                        .field("response_size", row['response_size']) \
                        .field("is_bot", row['is_bot']) \
                        .time(row['timestamp'], WritePrecision.MS) # Use appropriate precision

                # Write the data point
                write_api.write(bucket=bucket, org=org, record=point)

            print("Metric written successfully!")