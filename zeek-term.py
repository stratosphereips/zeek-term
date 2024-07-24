import argparse
import os
import sys

# Define ANSI escape codes for background and foreground colors
background_colors = {
    'conn': '\033[41m',  # Red
    'http': '\033[42m',  # Green
    'dns': '\033[43m',   # Yellow
    'ssl': '\033[44m',   # Blue
    'x509': '\033[45m',  # Magenta
    'files': '\033[46m', # Cyan
    'quic': '\033[47m',  # White
    'ntp': '\033[40m'    # Black
}

foreground_colors = {
    'conn': '\033[31m',  # Red
    'http': '\033[32m',  # Green
    'dns': '\033[33m',   # Yellow
    'ssl': '\033[34m',   # Blue
    'x509': '\033[35m',  # Magenta
    'files': '\033[36m', # Cyan
    'quic': '\033[37m',  # White
    'ntp': '\033[33m'    # Yellow
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
    'ntp': 'ntp.log'
}

# Setup argument parser
parser = argparse.ArgumentParser(description='Process log files with colored output.')
parser.add_argument('--foreground', action='store_true', help='Use foreground colors instead of background colors')
parser.add_argument('--directory', type=str, required=True, help='Directory where the Zeek log files are located')
parser.add_argument('--filter-conn', action='store_true', help='Filter conn.log lines based on UIDs present in other logs')

args = parser.parse_args()

log_entries = []
conn_entries = []
uids = set()

# Select the appropriate color scheme
color_scheme = foreground_colors if args.foreground else background_colors

# Read and process each file
for log_type, filename in file_patterns.items():
    filepath = os.path.join(args.directory, filename)
    if os.path.isfile(filepath):
        with open(filepath, 'r') as file:
            for line in file:
                if not line.startswith('#'):
                    parts = line.strip().split('\t')
                    if log_type == 'files' and len(parts) > 3:
                        uids.add(parts[2])  # Collect UID from files.log
                        parts = [parts[0]] + [log_type] + [parts[2]] + parts[3:]  # Remove FUID, keep UID
                    elif log_type != 'conn' and len(parts) > 1:
                        uids.add(parts[1])  # Collect UID from other logs
                        parts = [parts[0]] + [log_type] + [parts[1]] + parts[2:]  # Keep UID column, add log type
                        log_entries.append(('\t'.join(parts), color_scheme[log_type]))
                    elif log_type == 'conn' and len(parts) > 1:
                        conn_entries.append(parts)

# Process conn.log entries and filter based on UIDs
if args.filter_conn:
    for parts in conn_entries:
        if parts[1] not in uids:
            parts = [parts[0]] + ['conn'] + [parts[1]] + parts[2:]  # Keep UID column, add log type
            log_entries.append(('\t'.join(parts), color_scheme['conn']))
else:
    for parts in conn_entries:
        parts = [parts[0]] + ['conn'] + [parts[1]] + parts[2:]  # Keep UID column, add log type
        log_entries.append(('\t'.join(parts), color_scheme['conn']))

# Sort the log entries by the timestamp (first column)
log_entries.sort(key=lambda x: float(x[0].split('\t')[0]))

# Print the sorted log entries with appropriate colors
for entry, color in log_entries:
    print(f"{color}{entry}{reset_color}")

