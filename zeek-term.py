#!/usr/bin/env python
import argparse
import os
import sys
import json
from datetime import datetime, timezone

# Define ANSI escape codes for background and foreground colors
background_colors = {
    'conn': '\033[30;41m',  # Black text on Red
    'http': '\033[30;42m',  # Black text on Green
    'dns': '\033[30;43m',   # Black text on Yellow
    'ssl': '\033[30;44m',   # Black text on Blue
    'x509': '\033[30;45m',  # Black text on Magenta
    'files': '\033[30;46m', # Black text on Cyan
    'quic': '\033[30;47m',  # Black text on White
    'ntp': '\033[30;100m',  # Black text on Bright Black (Dark Grey)
    'dhcp': '\033[30;101m'  # Black text on Bright Red
}

foreground_colors = {
    'conn': '\033[31m',  # Red
    'http': '\033[32m',  # Green
    'dns': '\033[33m',   # Yellow
    'ssl': '\033[34m',   # Blue
    'x509': '\033[35m',  # Magenta
    'files': '\033[36m', # Cyan
    'quic': '\033[37m',  # White
    'ntp': '\033[90m',   # Bright Black (Dark Grey)
    'dhcp': '\033[91m'   # Bright Red
}

reset_color = '\033[0m'

# Define the file patterns for each log file type
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

# Setup argument parser
parser = argparse.ArgumentParser(description='Process log files with colored output.')
parser.add_argument('--foreground', action='store_true', help='Use foreground colors instead of background colors')
parser.add_argument('--directory', type=str, required=True, help='Directory where the Zeek log files are located')
parser.add_argument('--filter-conn', action='store_true', help='Filter conn.log lines based on UIDs present in other logs')
parser.add_argument('--no-ts-conversion', action='store_true', help='Disable conversion of ts to human-readable format')

args = parser.parse_args()

log_entries = []
conn_entries = []
uids = set()

# Select the appropriate color scheme
color_scheme = foreground_colors if args.foreground else background_colors

def convert_ts(ts):
    """Convert a Zeek timestamp to a human-readable format with timezone."""
    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return dt.strftime('%Y-%m-%d %H:%M:%S %Z')

def process_text_log_line(log_type, parts):
    if args.no_ts_conversion is False:
        parts[0] = convert_ts(parts[0])
    if log_type == 'files' and len(parts) > 3:
        uids.add(parts[2])  # Collect UID from files.log
        parts = [parts[0]] + [log_type] + [parts[2]] + parts[3:]  # Remove FUID, keep UID
    elif log_type != 'conn' and len(parts) > 1:
        uids.add(parts[1])  # Collect UID from other logs
        parts = [parts[0]] + [log_type] + [parts[1]] + parts[2:]  # Keep UID column, add log type
        log_entries.append(('\t'.join(parts), color_scheme[log_type]))
    elif log_type == 'conn' and len(parts) > 1:
        conn_entries.append(parts)

def process_json_log_line(log_type, data):
    if args.no_ts_conversion is False:
        data['ts'] = convert_ts(data['ts'])
    if 'uid' in data:
        uid = data['uid']
        if log_type == 'files':
            uids.add(uid)  # Collect UID from files.log
        elif log_type != 'conn':
            uids.add(uid)  # Collect UID from other logs
            data = {'ts': data['ts'], 'log_type': log_type, 'uid': uid, **data}
            log_entries.append((json.dumps(data), color_scheme[log_type]))
        elif log_type == 'conn':
            conn_entries.append(data)
    else:
        data = {'ts': data['ts'], 'log_type': log_type, **data}
        log_entries.append((json.dumps(data), color_scheme.get(log_type, reset_color)))

# Read and process each file
for log_type, filename in file_patterns.items():
    filepath = os.path.join(args.directory, filename)
    if os.path.isfile(filepath):
        with open(filepath, 'r') as file:
            for line in file:
                if not line.startswith('#'):
                    try:
                        # Try to parse JSON
                        data = json.loads(line.strip())
                        process_json_log_line(log_type, data)
                    except json.JSONDecodeError:
                        # Fallback to text-based processing
                        parts = line.strip().split('\t')
                        process_text_log_line(log_type, parts)

# Process conn.log entries and filter based on UIDs
if args.filter_conn:
    for parts in conn_entries:
        if parts['uid'] not in uids:
            data = {'ts': parts['ts'], 'log_type': 'conn', 'uid': parts['uid'], **parts}
            log_entries.append((json.dumps(data), color_scheme['conn']))
else:
    for parts in conn_entries:
        data = {'ts': parts['ts'], 'log_type': 'conn', 'uid': parts['uid'], **parts}
        log_entries.append((json.dumps(data), color_scheme['conn']))

# Sort the log entries by the timestamp (first column)
log_entries.sort(key=lambda x: float(x[0].split('\t')[0]) if '\t' in x[0] else json.loads(x[0])['ts'])

# Print the sorted log entries with appropriate colors
for entry, color in log_entries:
    print(f"{color}{entry}{reset_color}")

