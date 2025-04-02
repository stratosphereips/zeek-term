#!/usr/bin/env python
import argparse
import os
import json
from datetime import datetime, timezone, timedelta

# ANSI color schemes
background_colors = {
    'conn': '\033[30;41m',
    'http': '\033[30;42m',
    'dns': '\033[30;43m',
    'ssl': '\033[30;46m',
    'x509': '\033[30;45m',
    'files': '\033[30;46m',
    'quic': '\033[30;47m',
    'ntp': '\033[30;100m',
    'dhcp': '\033[30;101m'
}

foreground_colors = {
    'conn': '\033[31m',
    'http': '\033[32m',
    'dns': '\033[33m',
    'ssl': '\033[36m',
    'x509': '\033[35m',
    'files': '\033[36m',
    'quic': '\033[37m',
    'ntp': '\033[90m',
    'dhcp': '\033[91m'
}

reset_color = '\033[0m'

file_patterns = {
    'conn': 'conn.log',
    'http': 'http.log',
    'dns': 'dns.log',
    'ssl': 'ssl.log',
    'x509': 'x509.log',
    'files': 'files.log',
    'quic': 'quic.log',
    'ntp': 'ntp.log',
    'dhcp': 'dhcp.log'
}

# Argument parsing
parser = argparse.ArgumentParser(description='Process Zeek log files with colored output.')
parser.add_argument('-f', '--foreground', action='store_true', default=True, help='Use foreground colors')
parser.add_argument('-d', '--directory', type=str, required=True, help='Zeek log directory')
parser.add_argument('-c', '--filter-conn', action='store_true', default=True,help='Filter conn.log by UID')
parser.add_argument('-n', '--no-ts-conversion', action='store_true', help='Disable timestamp conversion')
parser.add_argument('-t', '--timezone', type=str, default='UTC+2', help='Timezone (e.g. UTC+2)')

args = parser.parse_args()

log_entries = []
conn_entries = []
uids = set()
log_headers = {}

color_scheme = foreground_colors if args.foreground else background_colors

# Parse timezone string
def parse_timezone(tz_str):
    if tz_str == '???':
        return timezone.utc, '???'
    if tz_str.startswith('UTC'):
        sign = 1 if '+' in tz_str else -1
        offset = int(tz_str.split('UTC')[1])
        return timezone(timedelta(hours=sign * offset)), tz_str
    return timezone.utc, 'UTC'

tz, tz_name = parse_timezone(args.timezone)

def convert_ts(ts):
    try:
        ts_float = float(ts)
    except ValueError:
        return ts  # already formatted
    ts_str = f"{ts_float:.6f}"
    dt = datetime.fromtimestamp(ts_float, tz=tz)
    return dt.strftime(f'%Y-%m-%d %H:%M:%S.{ts_str.split(".")[1]} {tz_name}')

def process_text_log_line(log_type, parts):
    header = log_headers.get(log_type)
    if not header or len(parts) != len(header):
        return

    record = dict(zip(header, parts))

    if not args.no_ts_conversion and 'ts' in record:
        record['ts'] = convert_ts(record['ts'])

    if log_type == 'files' and 'uid' in record:
        uids.add(record['uid'])
    elif log_type != 'conn' and 'uid' in record:
        uids.add(record['uid'])

    if log_type == 'conn':
        conn_entries.append(record)
    else:
        line = '\t'.join([
            record.get('ts', '-'),
            log_type,
            record.get('uid', '-')
        ] + [record.get(k, '-') for k in header if k not in ('ts', 'uid')])
        log_entries.append((line, color_scheme[log_type]))

def process_json_log_line(log_type, data):
    if not args.no_ts_conversion and 'ts' in data:
        data['ts'] = convert_ts(data['ts'])

    if 'uid' in data and log_type != 'conn':
        uids.add(data['uid'])

    if log_type == 'conn':
        conn_entries.append(data)
    else:
        line = '\t'.join([
            data.get('ts', '-'),
            log_type,
            data.get('uid', '-')
        ] + [str(v) for k, v in data.items() if k not in ('ts', 'uid')])
        log_entries.append((line, color_scheme[log_type]))

# Read and process each log file
for log_type, filename in file_patterns.items():
    filepath = os.path.join(args.directory, filename)
    if os.path.isfile(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                if line.startswith('#fields'):
                    log_headers[log_type] = line.strip().split('\t')[1:]
                elif not line.startswith('#'):
                    try:
                        data = json.loads(line.strip())
                        process_json_log_line(log_type, data)
                    except json.JSONDecodeError:
                        parts = line.strip().split('\t')
                        process_text_log_line(log_type, parts)

# Handle conn.log with optional UID filtering
for record in conn_entries:
    uid = record.get('uid', '-')
    if args.filter_conn and uid in uids:
        continue

    ts_val = record.get('ts', '0')
    ts_str = ts_val if args.no_ts_conversion or ' ' in str(ts_val) else convert_ts(ts_val)

    # Determine fields to print
    fields = log_headers.get('conn')
    if not fields:
        fields = sorted(k for k in record.keys() if k not in ('ts', 'uid'))

    line = '\t'.join([
        ts_str,
        'conn',
        uid
    ] + [str(record.get(k, '-')) for k in fields])
    log_entries.append((line, color_scheme['conn']))

# Sort log entries by timestamp (handles both formatted and raw timestamps)
def extract_ts(entry):
    ts_str = entry[0].split('\t')[0]
    try:
        if ' ' in ts_str:
            ts_main = ' '.join(ts_str.split(' ')[:2])  # e.g. '2025-03-31 08:41:08.271441'
            return datetime.strptime(ts_main, "%Y-%m-%d %H:%M:%S.%f").timestamp()
        return float(ts_str)
    except:
        return 0

log_entries.sort(key=extract_ts)

# Print results
for line, color in log_entries:
    print(f"{color}{line}{reset_color}")

