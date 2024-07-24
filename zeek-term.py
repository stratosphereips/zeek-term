import argparse
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

args = parser.parse_args()

log_entries = []

# Select the appropriate color scheme
color_scheme = foreground_colors if args.foreground else background_colors

# Read and process each file
for log_type, pattern in file_patterns.items():
    with open(pattern, 'r') as file:
        for line in file:
            if not line.startswith('#'):
                parts = line.strip().split('\t')
                if log_type == 'files' and len(parts) > 3:
                    parts = [parts[0]] + [log_type] + [parts[2]] + parts[3:]  # Remove FUID, keep UID
                elif len(parts) > 1:
                    parts = [parts[0]] + [log_type] + [parts[1]] + parts[2:]  # Keep UID column, add log type
                log_entries.append(('\t'.join(parts), color_scheme[log_type]))

# Sort the log entries by the timestamp (first column)
log_entries.sort(key=lambda x: float(x[0].split('\t')[0]))

# Print the sorted log entries with appropriate colors
for entry, color in log_entries:
    print(f"{color}{entry}{reset_color}")

