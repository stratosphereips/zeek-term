#!/usr/bin/env python
import argparse
import os
import sys
import json
import gzip
import glob
from datetime import datetime, timezone, timedelta
import math

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
parser.add_argument('-c', '--filter-conn', action='store_true', default=True, help='Filter conn.log by UID')
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
    # Preserve empty/missing values and already non-numeric strings.
    ts_raw = str(ts).strip()
    if ts is None or ts_raw in ('', '-'):
        return ts_raw if ts is not None else '-'

    try:
        ts_float = float(ts_raw)
        # Avoid platform errors for nan/inf or out-of-range values.
        if not math.isfinite(ts_float):
            return ts_raw
        dt = datetime.fromtimestamp(ts_float, tz=tz)
    except (TypeError, ValueError, OverflowError, OSError):
        return ts_raw

    ts_str = f"{ts_float:.6f}"
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
            str(data.get('ts', '-')),
            log_type,
            str(data.get('uid', '-'))
        ] + [str(v) for k, v in data.items() if k not in ('ts', 'uid')])
        log_entries.append((line, color_scheme[log_type]))

# Read and process all log files for each type (including rotated and .gz files)
for log_type, pattern in file_patterns.items():
    base = os.path.join(args.directory, pattern.replace('.log', ''))
    candidates = glob.glob(f"{base}*.log") + glob.glob(f"{base}*.log.gz")

    for filepath in sorted(candidates):
        open_func = gzip.open if filepath.endswith('.gz') else open
        mode = 'rt' if filepath.endswith('.gz') else 'r'

        try:
            with open_func(filepath, mode) as f:
                for line in f:
                    if line.startswith('#fields'):
                        log_headers[log_type] = line.strip().split('\t')[1:]
                    elif not line.startswith('#'):
                        raw = line.strip()
                        if not raw:
                            continue

                        parsed = False
                        try:
                            data = json.loads(raw)

                            if isinstance(data, dict):
                                process_json_log_line(log_type, data)
                                parsed = True
                            elif isinstance(data, str):
                                # Handle double-encoded JSON objects.
                                try:
                                    nested = json.loads(data)
                                    if isinstance(nested, dict):
                                        process_json_log_line(log_type, nested)
                                        parsed = True
                                except json.JSONDecodeError:
                                    pass
                            elif isinstance(data, list):
                                # Handle a list of JSON records.
                                if data and all(isinstance(item, dict) for item in data):
                                    for item in data:
                                        process_json_log_line(log_type, item)
                                    parsed = True
                        except json.JSONDecodeError as e:
                            # Handle concatenated JSON objects on a single line.
                            if raw.startswith('{') and 'Extra data' in str(e):
                                decoder = json.JSONDecoder()
                                idx = 0
                                while idx < len(raw):
                                    while idx < len(raw) and raw[idx].isspace():
                                        idx += 1
                                    if idx >= len(raw):
                                        break
                                    try:
                                        item, end = decoder.raw_decode(raw, idx)
                                    except json.JSONDecodeError:
                                        break
                                    if isinstance(item, dict):
                                        process_json_log_line(log_type, item)
                                        parsed = True
                                    idx = end

                        if not parsed:
                            parts = raw.split('\t')
                            process_text_log_line(log_type, parts)
        except Exception as e:
            print(f"Failed to read {filepath}: {e}", file=sys.stderr)

# Handle conn.log with optional UID filtering
for record in conn_entries:
    uid = record.get('uid', '-')
    if args.filter_conn and uid in uids:
        continue
    ts_val = record.get('ts', '0')
    ts_str = ts_val if args.no_ts_conversion or ' ' in str(ts_val) else convert_ts(ts_val)
    fields = log_headers.get('conn')
    if not fields:
        fields = sorted(k for k in record.keys() if k not in ('ts', 'uid'))
    line = '\t'.join([
        ts_str,
        'conn',
        uid
    ] + [str(record.get(k, '-')) for k in fields if k not in ('ts', 'uid')])
    log_entries.append((line, color_scheme['conn']))

# Sort log entries by timestamp
def extract_ts(entry):
    ts_str = entry[0].split('\t')[0]
    try:
        if ' ' in ts_str:
            ts_main = ' '.join(ts_str.split(' ')[:2])
            return datetime.strptime(ts_main, "%Y-%m-%d %H:%M:%S.%f").timestamp()
        return float(ts_str)
    except:
        return 0

log_entries.sort(key=extract_ts)

# Print results
for line, color in log_entries:
    print(f"{color}{line}{reset_color}")
