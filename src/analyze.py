"""
This file parses the http access file and outputs them in various ways.

Input options:
--batch will process files whose create timestamp is >= the last log created. This option
        is used when being run as a cron.
--logfiles <list of logfiles> will process the arguments given as http access log files.

Output options:
--hits summarizes number of hits by user-agent
--size summarizes response size by user-agent
--output <filename> outputs parsed fields as a csv file
--influx outputs parsed fields as influx db metrics
"""

import re
import argparse
from collections import Counter
import pandas as pd
import os
from typing import Union
import datetime
import time

from user_agents import parse
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS


def extract(log_files: list) -> pd.DataFrame:
    """
    Extract fields from http access log

    Parameters
    ----------
    log_files : list
        List of http access logs to process.

    Returns
    -------
    pd.DataFrame
        A cleaned and processed dataframe derived from the http access log fields.
    """
    log_pattern = re.compile(
            r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?:www[.])?saatriangle.org - '  # IP address
        r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] ' # Timestamp
        r'"(\w+)\s(.+?)\s(HTTP/\d\.\d)" ' # Request method, URL, HTTP version
        r'(\d{3}) (\d+|-)' # Status code and response size
        r' ".*" '
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
                    full_url = url
                    if url.startswith("/?"):
                        url = "/" + url[2:]
                    if '?' in url:
                        url = url.split('?')[0]
                    elif '&' in url:
                        url = url.split('&')[0]
                    print(f"URL: {url}")
                    print(f"Timestamp: {timestamp}")
                    print(f"Logfile: {log_file}")
                    print(f"MATCH: {line}")
                    print()
                    user_agent = user_agent_obj.browser.family if user_agent_obj.browser.family != "Other" else user_agent_str
                    rows.append((ip_address, timestamp, method, url, http_version, status_code, response_size, user_agent, user_agent_obj.is_bot, full_url))
                else:
                    print(f"NO MATCH: {line}")

    df = pd.DataFrame(rows, columns=['ip_address', 'timestamp', 'method', 'url', 'http_version', 'status_code', 'response_size', 'user_agent', 'is_bot', 'full_url'])
    return df


def output_hits(df: pd.DataFrame):
    """
    Summary output of number of hits by user agent.

    Parameters
    ----------
    df : pd.DataFrame
        Input dataframe consisting of fields parsed from the http access logs.
    """
    user_agents = df['user_agent'].to_list()
    counts = Counter(user_agents)

    keys =  list(counts.keys())
    values = list(counts.values())
    combined = list(zip(values, keys))
    sorted_list = sorted(combined, reverse=True)

    print("=========== HITS ================")
    for v, k in sorted_list[0:20]:
        print(f"{k}: {v}")

def output_hits_by_url(df: pd.DataFrame, filter: str = None, ip_filter: str = None):
    """
    Summary output of number of hits by user agent.

    Parameters
    ----------
    df : pd.DataFrame
        Input dataframe consisting of fields parsed from the http access logs.
    """
    if filter:
        filtered_df = df[df['user_agent'].str.contains(filter)]
    else:
        filtered_df = df
    
    if ip_filter:
        filtered_df = filtered_df[filtered_df['ip_address'].str.contains(ip_filter)]

    print(f"{len(df)}; {len(filtered_df)}")
    urls = filtered_df['url'].to_list()
    counts = Counter(urls)

    keys =  list(counts.keys())
    values = list(counts.values())
    combined = list(zip(values, keys))
    sorted_list = sorted(combined, reverse=True)

    print(f"=========== HITS BY URL user_agent={filter} ip_address={ip_filter} ================")
    for v, k in sorted_list[0:20]:
        print(f"{k}: {v}")

def output_hits_by_ip(df: pd.DataFrame, filter: str = None):
    """
    Summary output of number of hits by ip address.

    Parameters
    ----------
    df : pd.DataFrame
        Input dataframe consisting of fields parsed from the http access logs.
    """
    if filter:
        filtered_df = df[df['user_agent'].str.contains(filter)]
    else:
        filtered_df = df
    print(f"{len(df)}; {len(filtered_df)}")
    urls = filtered_df['ip_address'].to_list()
    counts = Counter(urls)

    keys =  list(counts.keys())
    values = list(counts.values())
    combined = list(zip(values, keys))
    sorted_list = sorted(combined, reverse=True)

    print(f"=========== HITS BY IP user_agent={filter} ================")
    for v, k in sorted_list[0:20]:
        print(f"{k}: {v}")

def output_response_size(df: pd.DataFrame):
    """
    Summary output of responsize size by user agent.

    Parameters
    ----------
    df : pd.DataFrame
        Input dataframe consisting of fields parsed from the http access logs.
    """
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

def output_influx(df: pd.DataFrame) -> None:
    """
    Process dataframe and send metrics to influx db.

    Parameters
    ----------
    df : pd.DataFrame
        Input dataframe containing parsed data from http access logs.
    """
    url = "http://127.0.0.1:8086"
    org = "SAA"
    bucket = "SAA-Bucket"
    token_file = "secrets/influxdb_token.txt"
    with open(token_file, "r") as f:
        token = f.read()[:-1]
    token = "XfGouOJU11Hj3mQsYvqqFMzXfg6v1rmP8Uq0AAHni73VEhnWR-auGC3LrjbFPQ3TUksufDjnad5-DS-yoJanYQ=="
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    df['response_size'] = df['response_size'].astype(int)
    with InfluxDBClient(url=url, token=token, org=org) as client:
        # Create a write api instance
        write_api = client.write_api(write_options=SYNCHRONOUS)

        points_block = []
        for index, row in df.iterrows():
            
            print(f"before ts={row['timestamp']}")
            us = abs(hash(row['user_agent'] + row['ip_address'] +  str(row['response_size']) + row['full_url'])) % 1000000
            row['timestamp'] = row['timestamp'] + pd.Timedelta(microseconds=us)
            print(f"after ts={row['timestamp']}")
            
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
                    .time(row['timestamp'], WritePrecision.US) # Use appropriate precision
            points_block.append(point)

        print(f"points_block_len={len(points_block)}")
        # Write the data point
        try:
            chunk_size = 2048
            points_block_chunks = [points_block[i:i + chunk_size] for i in range(0, len(points_block), chunk_size)]
            
            for idx, points_block_chunk in enumerate(points_block_chunks):
                print(f"Sending chunk {idx}")
                write_api.write(bucket=bucket, org=org, record=points_block_chunk)
                time.sleep(1)
        except Exception as e:
            print(f"Error: unexpected exception writing to influxdb. e={e}")

        print("Metric written successfully!")
def process_batch() -> list:
    """
    Do steps to find log file names for batch processing.

    Returns
    -------
    list
        A list of logfiles to be processed
    """
    directory_path = "/var/saa/data"
    ts_file = f"{directory_path}/.ts"
    ts = None
    last_ts = None
    logfiles = []
    if os.path.exists(ts_file):
        with open(ts_file, "r") as f:
            ts_format = "%Y-%m-%d %H:%M:%S.%f"
            ts = datetime.datetime.strptime(f.read(), ts_format)
    entries = os.listdir(directory_path)
    for filename in entries:
        if ts_file == f"{directory_path}/{filename}":
            continue
        else:
            creation_timestamp = os.path.getctime(f"{directory_path}/{filename}")
            creation_datetime = datetime.datetime.fromtimestamp(creation_timestamp)
            if not last_ts or creation_datetime > last_ts:
                last_ts = creation_datetime
            if ts:
                if creation_datetime > ts:
                    logfiles.append(f"{directory_path}/{filename}")
            else:
                logfiles.append(f"{directory_path}/{filename}")
    if last_ts:
        with open(ts_file, "w") as f:
            f.write(str(last_ts))
    return logfiles

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
    parser.add_argument("--filter", default=None, help="User agent filter")
    parser.add_argument("--ip_filter", default=None, help="Print out hit by ip data")
    parser.add_argument("--hits", action="store_true", help="Print out hit data")
    parser.add_argument("--url", action="store_true", help="Print out hit by url data")
    parser.add_argument("--ip", action="store_true", help="Print out hit by ip data")
    parser.add_argument("--size", action="store_true", help="Print out response size data")
    parser.add_argument("--output", default=None, help="Specify the path to the output file.")
    parser.add_argument("--influx", action="store_true", help="Write to influxdb")
    parser.add_argument("--batch", action="store_true", help="Write to influxdb")

     # 3. Process input parameters
    args = parser.parse_args()

    if args.batch:
        logfiles = process_batch()
        df  = extract(logfiles)
    else:
        df = extract(args.logfiles)

    # 4. Process output parameters
    if args.hits:
         output_hits(df)
    if args.size:
         output_response_size(df)
    if args.url:
         output_hits_by_url(df, filter=args.filter, ip_filter=args.ip_filter)
    if args.ip:
         output_hits_by_ip(df, filter=args.filter)

    if args.output:
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        df['is_bot'] = df['is_bot'].astype(str)
        df['response_size'] = df['response_size'].astype(int)
        df.to_csv(args.output, index=False)
    if args.influx:
        output_influx(df)