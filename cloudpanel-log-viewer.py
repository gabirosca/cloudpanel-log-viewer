#!/usr/bin/env python3
"""
CloudPanel Log Viewer
Displays logs from /home/{user}/logs in a human-readable format.
Requires sudo privileges to read the logs.
"""

import os
import sys
import re
import json
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# Cache for IP geolocation lookups
geo_cache = {}

# Server's public IP (will be fetched on demand)
server_public_ip = None
filter_server_ip = False


# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def get_server_public_ip():
    """Get the server's public IP address."""
    global server_public_ip

    if server_public_ip is not None:
        return server_public_ip

    try:
        url = "https://api.seeip.org"
        req = urllib.request.Request(url, headers={"User-Agent": "CloudPanel-Log-Viewer/1.0"})

        with urllib.request.urlopen(req, timeout=5) as response:
            server_public_ip = response.read().decode("utf-8").strip()
            return server_public_ip

    except Exception:
        return None


def get_ip_geolocation(ip_address):
    """Get geolocation info for an IP address using seeip.org API."""
    # Skip private/local IPs
    if ip_address.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.",
                               "172.18.", "172.19.", "172.20.", "172.21.",
                               "172.22.", "172.23.", "172.24.", "172.25.",
                               "172.26.", "172.27.", "172.28.", "172.29.",
                               "172.30.", "172.31.", "::1", "fe80:")):
        return None

    # Check cache first
    if ip_address in geo_cache:
        return geo_cache[ip_address]

    try:
        url = f"https://api.seeip.org/geoip/{ip_address}"
        req = urllib.request.Request(url, headers={"User-Agent": "CloudPanel-Log-Viewer/1.0"})

        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))

            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")

            # Handle empty values
            if not city or city == "":
                city = "Unknown"
            if not country or country == "":
                country = "Unknown"

            result = {"country": country, "city": city}
            geo_cache[ip_address] = result
            return result

    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        geo_cache[ip_address] = None
        return None
    except Exception:
        geo_cache[ip_address] = None
        return None


def format_ip_with_location(ip_address):
    """Format IP address with geolocation info."""
    geo = get_ip_geolocation(ip_address)
    if geo:
        return f"{ip_address} ({geo['country']}, {geo['city']})"
    return ip_address


def check_sudo():
    """Check if script is running with sudo privileges."""
    if os.geteuid() != 0:
        print("This script requires sudo privileges to read logs.")
        print("Please run with: sudo python3 cloudpanel_logs.py")
        sys.exit(1)


def get_users_with_logs():
    """Get list of users that have a logs directory."""
    users = []
    home_dir = Path("/home")

    if not home_dir.exists():
        return users

    for user_dir in home_dir.iterdir():
        if user_dir.is_dir():
            logs_dir = user_dir / "logs"
            if logs_dir.exists() and logs_dir.is_dir():
                users.append(user_dir.name)

    return sorted(users)


def get_log_types():
    """Return available log types."""
    return {
        "1": ("php", "PHP Logs"),
        "2": ("nginx", "Nginx Logs"),
        "3": ("varnish", "Varnish Cache Logs"),
    }


def find_log_files(user, log_type):
    """Find log files for a specific user and log type."""
    logs_dir = Path(f"/home/{user}/logs")
    log_files = []

    # Directory names for each log type
    type_dirs = {
        "php": ["php"],
        "nginx": ["nginx"],
        "varnish": ["varnish", "varnish-cache"],
    }

    # Get directories to search
    dirs_to_search = type_dirs.get(log_type, [log_type])

    for dir_name in dirs_to_search:
        type_dir = logs_dir / dir_name
        if type_dir.exists() and type_dir.is_dir():
            # Get all log files in this directory (including rotated logs)
            for f in type_dir.iterdir():
                if f.is_file() and (f.suffix == ".log" or ".log-" in f.name or f.name.endswith(".log")):
                    log_files.append(f)

    # Remove duplicates and filter only non-empty files
    seen = set()
    unique_files = []
    for f in log_files:
        if f not in seen:
            seen.add(f)
            # Include file even if empty, but we can note it
            unique_files.append(f)

    return sorted(unique_files, key=lambda x: x.stat().st_mtime, reverse=True)


def format_size(size_bytes):
    """Format file size in human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def format_timestamp(timestamp):
    """Format timestamp in human-readable format."""
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_status_color(status_code):
    """Get color based on HTTP status code."""
    try:
        code = int(status_code)
        if 200 <= code < 300:
            return GREEN
        elif 300 <= code < 400:
            return CYAN
        elif 400 <= code < 500:
            return YELLOW
        elif code >= 500:
            return RED
    except (ValueError, TypeError):
        pass
    return RESET


def parse_nginx_access_log(line):
    """Parse Nginx access log line (combined format)."""
    # Combined log format:
    # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    pattern = r'^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
    match = re.match(pattern, line)

    if match:
        remote_addr, remote_user, time_local, request, status, bytes_sent, referer, user_agent = match.groups()

        # Parse request to get method, path, protocol
        request_parts = request.split(" ")
        method = request_parts[0] if len(request_parts) > 0 else "-"
        path = request_parts[1] if len(request_parts) > 1 else "-"
        protocol = request_parts[2] if len(request_parts) > 2 else "-"

        return {
            "type": "nginx_access",
            "remote_addr": remote_addr,
            "remote_user": remote_user if remote_user != "-" else None,
            "time_local": time_local,
            "method": method,
            "path": path,
            "protocol": protocol,
            "status": status,
            "bytes_sent": bytes_sent,
            "referer": referer if referer != "-" else None,
            "user_agent": user_agent,
        }
    return None


def parse_nginx_error_log(line):
    """Parse Nginx error log line."""
    # Error log format: YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message
    pattern = r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+#\d+): (?:\*(\d+) )?(.+)'
    match = re.match(pattern, line)

    if match:
        timestamp, level, pid_tid, cid, message = match.groups()

        # Try to extract client IP and other info from message
        client_match = re.search(r'client: ([\d.]+)', message)
        request_match = re.search(r'request: "([^"]+)"', message)

        return {
            "type": "nginx_error",
            "timestamp": timestamp,
            "level": level,
            "pid_tid": pid_tid,
            "connection_id": cid,
            "message": message,
            "client": client_match.group(1) if client_match else None,
            "request": request_match.group(1) if request_match else None,
        }
    return None


def parse_php_log(line):
    """Parse PHP error log line."""
    # PHP log format: [DD-Mon-YYYY HH:MM:SS TZ] PHP Level: message
    pattern = r'^\[([^\]]+)\] (PHP )?(\w+ ?\w*): (.+)'
    match = re.match(pattern, line)

    if match:
        timestamp, _, level, message = match.groups()

        # Extract file and line if present
        file_match = re.search(r'in (.+) on line (\d+)', message)

        return {
            "type": "php",
            "timestamp": timestamp,
            "level": level.strip(),
            "message": message,
            "file": file_match.group(1) if file_match else None,
            "line": file_match.group(2) if file_match else None,
        }
    return None


def parse_varnish_log(line):
    """Parse Varnish log line."""
    # Varnish NCSA format similar to Nginx combined
    parsed = parse_nginx_access_log(line)
    if parsed:
        parsed["type"] = "varnish"
        return parsed

    # Try alternative varnish format
    pattern = r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-)'
    match = re.match(pattern, line)

    if match:
        client, identity, user, timestamp, request, status, size = match.groups()
        request_parts = request.split(" ")

        return {
            "type": "varnish",
            "remote_addr": client,
            "time_local": timestamp,
            "method": request_parts[0] if request_parts else "-",
            "path": request_parts[1] if len(request_parts) > 1 else "-",
            "protocol": request_parts[2] if len(request_parts) > 2 else "-",
            "status": status,
            "bytes_sent": size,
        }
    return None


def display_nginx_access_entry(entry, index):
    """Display a parsed Nginx access log entry."""
    status_color = get_status_color(entry["status"])
    ip_with_location = format_ip_with_location(entry["remote_addr"])

    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"{BOLD}Entry #{index}{RESET}")
    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"  {BOLD}Remote Address:{RESET}  {CYAN}{ip_with_location}{RESET}")
    print(f"  {BOLD}Time Local:{RESET}      {entry['time_local']}")
    print(f"  {BOLD}Method:{RESET}          {MAGENTA}{entry['method']}{RESET}")
    print(f"  {BOLD}Request Path:{RESET}    {entry['path']}")
    print(f"  {BOLD}Protocol:{RESET}        {entry['protocol']}")
    print(f"  {BOLD}Status Code:{RESET}     {status_color}{entry['status']}{RESET}")
    print(f"  {BOLD}Bytes Sent:{RESET}      {entry['bytes_sent']}")

    if entry.get("referer"):
        print(f"  {BOLD}Referer:{RESET}         {entry['referer']}")

    if entry.get("user_agent"):
        ua = entry["user_agent"]
        if len(ua) > 70:
            ua = ua[:70] + "..."
        print(f"  {BOLD}User Agent:{RESET}      {DIM}{ua}{RESET}")

    print()


def display_nginx_error_entry(entry, index):
    """Display a parsed Nginx error log entry."""
    level_colors = {
        "emerg": RED,
        "alert": RED,
        "crit": RED,
        "error": RED,
        "warn": YELLOW,
        "notice": GREEN,
        "info": CYAN,
        "debug": DIM,
    }
    level_color = level_colors.get(entry["level"], RESET)

    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"{BOLD}Entry #{index}{RESET}")
    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"  {BOLD}Timestamp:{RESET}       {entry['timestamp']}")
    print(f"  {BOLD}Level:{RESET}           {level_color}{entry['level'].upper()}{RESET}")

    if entry.get("client"):
        client_with_location = format_ip_with_location(entry["client"])
        print(f"  {BOLD}Client:{RESET}          {CYAN}{client_with_location}{RESET}")

    if entry.get("request"):
        print(f"  {BOLD}Request:{RESET}         {entry['request']}")

    print(f"  {BOLD}Message:{RESET}         {entry['message']}")
    print()


def display_php_entry(entry, index):
    """Display a parsed PHP log entry."""
    level_colors = {
        "Fatal error": RED,
        "Parse error": RED,
        "Warning": YELLOW,
        "Notice": CYAN,
        "Deprecated": MAGENTA,
        "Strict Standards": DIM,
    }
    level_color = level_colors.get(entry["level"], RESET)

    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"{BOLD}Entry #{index}{RESET}")
    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"  {BOLD}Timestamp:{RESET}       {entry['timestamp']}")
    print(f"  {BOLD}Level:{RESET}           {level_color}{entry['level']}{RESET}")

    if entry.get("file"):
        print(f"  {BOLD}File:{RESET}            {entry['file']}")

    if entry.get("line"):
        print(f"  {BOLD}Line:{RESET}            {entry['line']}")

    # Wrap message if too long
    message = entry["message"]
    if len(message) > 80:
        words = message.split()
        lines = []
        current = ""
        for word in words:
            if len(current) + len(word) + 1 <= 80:
                current = current + " " + word if current else word
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)

        print(f"  {BOLD}Message:{RESET}")
        for line in lines:
            print(f"    {line}")
    else:
        print(f"  {BOLD}Message:{RESET}         {message}")

    print()


def display_raw_entry(line, index):
    """Display a raw log line when parsing fails."""
    line = line.strip()
    if not line:
        return

    # Basic colorization
    if "error" in line.lower() or "fatal" in line.lower():
        color = RED
    elif "warning" in line.lower() or "warn" in line.lower():
        color = YELLOW
    elif "notice" in line.lower() or "info" in line.lower():
        color = GREEN
    else:
        color = RESET

    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"{BOLD}Entry #{index}{RESET}")
    print(f"{DIM}{'─' * 50}{RESET}")
    print(f"  {color}{line}{RESET}")
    print()


def display_log_file(filepath, log_type, num_lines=50):
    """Display log file contents in a human-readable format."""
    try:
        stat = filepath.stat()
        print(f"\n{BOLD}{'=' * 60}{RESET}")
        print(f"{BOLD}File:{RESET} {CYAN}{filepath}{RESET}")
        print(f"{BOLD}Size:{RESET} {format_size(stat.st_size)}")
        print(f"{BOLD}Last Modified:{RESET} {format_timestamp(stat.st_mtime)}")
        print(f"{BOLD}{'=' * 60}{RESET}")
        if filter_server_ip and server_public_ip:
            print(f"{DIM}(Filtering out server IP: {server_public_ip}){RESET}")
        print(f"{DIM}(Looking up IP locations via seeip.org...){RESET}\n")

        # Detect if access or error log
        path_str = str(filepath).lower()
        is_error_log = "error" in path_str

        # Read and display last N lines
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()

        if not lines:
            print("  (Empty log file)")
            return

        start_idx = max(0, len(lines) - num_lines)
        if start_idx > 0:
            print(f"  {DIM}... showing last {num_lines} of {len(lines)} lines ...{RESET}\n")

        entry_num = 1
        skipped_count = 0
        for line in lines[start_idx:]:
            line = line.strip()
            if not line:
                continue

            parsed = None

            if log_type == "nginx":
                if is_error_log:
                    parsed = parse_nginx_error_log(line)
                    # Filter out server IP if enabled
                    if parsed and filter_server_ip and server_public_ip:
                        if parsed.get("client") == server_public_ip:
                            skipped_count += 1
                            continue
                    if parsed:
                        display_nginx_error_entry(parsed, entry_num)
                else:
                    parsed = parse_nginx_access_log(line)
                    # Filter out server IP if enabled
                    if parsed and filter_server_ip and server_public_ip:
                        if parsed.get("remote_addr") == server_public_ip:
                            skipped_count += 1
                            continue
                    if parsed:
                        display_nginx_access_entry(parsed, entry_num)

            elif log_type == "php":
                parsed = parse_php_log(line)
                if parsed:
                    display_php_entry(parsed, entry_num)

            elif log_type == "varnish":
                parsed = parse_varnish_log(line)
                # Filter out server IP if enabled
                if parsed and filter_server_ip and server_public_ip:
                    if parsed.get("remote_addr") == server_public_ip:
                        skipped_count += 1
                        continue
                if parsed:
                    display_nginx_access_entry(parsed, entry_num)

            if not parsed:
                display_raw_entry(line, entry_num)

            entry_num += 1

        if skipped_count > 0:
            print(f"\n{DIM}(Skipped {skipped_count} entries from server IP {server_public_ip}){RESET}")

    except PermissionError:
        print(f"  Permission denied: {filepath}")
    except Exception as e:
        print(f"  Error reading file: {e}")


def select_user(users):
    """Select a user from the list. Returns user name or None to exit."""
    global filter_server_ip, server_public_ip

    # Show filter status
    if filter_server_ip:
        filter_status = f"{GREEN}ON{RESET}"
        ip_display = f" ({server_public_ip})" if server_public_ip else ""
    else:
        filter_status = f"{DIM}OFF{RESET}"
        ip_display = ""

    print(f"\n{BOLD}Available users with logs:{RESET}")
    for i, user in enumerate(users, 1):
        print(f"  {i}. {user}")
    print(f"\n  {YELLOW}f. Filter server IP: [{filter_status}]{ip_display}{RESET}")
    print(f"  {DIM}q. Quit{RESET}")

    while True:
        try:
            choice = input(f"\n{BOLD}Select user (1-{len(users)}):{RESET} ").strip().lower()

            if choice == "q":
                return None
            if choice == "f":
                # Toggle filter
                if not filter_server_ip:
                    # Turning on - fetch server IP if not already fetched
                    print(f"\n{DIM}Fetching server public IP...{RESET}")
                    ip = get_server_public_ip()
                    if ip:
                        filter_server_ip = True
                        print(f"{GREEN}Filter enabled.{RESET} Server IP: {CYAN}{ip}{RESET}")
                    else:
                        print(f"{RED}Could not fetch server IP. Filter not enabled.{RESET}")
                else:
                    filter_server_ip = False
                    print(f"{YELLOW}Filter disabled.{RESET}")
                return "refresh"  # Signal to refresh the menu

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(users):
                    return users[idx]
                print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a number, 'f', or 'q'.")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)


def select_log_type():
    """Select log type. Returns (type_key, type_name) or 'back' or None."""
    log_types = get_log_types()
    print(f"\n{BOLD}Log types:{RESET}")
    for key, (_, name) in log_types.items():
        print(f"  {key}. {name}")
    print(f"\n  {DIM}b. Back | q. Quit{RESET}")

    while True:
        try:
            choice = input(f"\n{BOLD}Select log type (1-3):{RESET} ").strip().lower()

            if choice == "q":
                return None, None
            if choice == "b":
                return "back", None

            if choice in log_types:
                return log_types[choice]

            print("Invalid selection. Please try again.")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)


def select_log_file(log_files, selected_type):
    """Select a log file to view. Returns file index, 'back', or None."""
    # Current/active log files (no date suffix)
    current_logs = {"access.log", "error.log", "purge.log"}

    print(f"\n{BOLD}Found {len(log_files)} log file(s):{RESET}")
    for i, f in enumerate(log_files, 1):
        size = f.stat().st_size
        size_str = format_size(size)

        # Highlight current logs in green
        if f.name in current_logs:
            name_display = f"{GREEN}{f.name}{RESET}"
        else:
            name_display = f"{DIM}{f.name}{RESET}"

        if size == 0:
            print(f"  {i}. {name_display} {DIM}(empty){RESET}")
        else:
            print(f"  {i}. {name_display} ({size_str})")
    print(f"\n  0. View all files")
    print(f"\n  {DIM}b. Back | q. Quit{RESET}")

    while True:
        try:
            choice = input(f"\n{BOLD}Select file (0-{len(log_files)}):{RESET} ").strip().lower()

            if choice == "q":
                return None
            if choice == "b":
                return "back"

            try:
                idx = int(choice)
                if 0 <= idx <= len(log_files):
                    return idx
                print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a number, 'b', or 'q'.")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)


def interactive_menu():
    """Run the interactive menu."""
    print(f"\n{BOLD}{CYAN}CloudPanel Log Viewer{RESET}")
    print(f"{BOLD}{GREEN}Author: Gabriel Rosca")
    print(f"{BOLD}{GREEN}GitHub: https://github.com/gabirosca/cloudpanel-log-viewer")
    print(f"{BOLD}{GREEN}Support: https://blackwolf.link/q/dPOCrsKYq{RESET}")
    print("=" * 40)

    # Get available users
    users = get_users_with_logs()

    if not users:
        print("\nNo users with log directories found in /home/")
        sys.exit(1)

    while True:
        # Step 1: Select user
        selected_user = select_user(users)
        if selected_user is None:
            print("\nExiting...")
            return
        if selected_user == "refresh":
            continue  # Refresh the user selection menu

        go_to_user_select = False

        while True:
            # Step 2: Select log type
            selected_type, type_name = select_log_type()
            if selected_type is None:
                print("\nExiting...")
                return
            if selected_type == "back":
                break  # Go back to user selection

            print(f"\n{BOLD}Searching for {type_name} in /home/{selected_user}/logs...{RESET}")

            # Find log files
            log_files = find_log_files(selected_user, selected_type)

            if not log_files:
                print(f"\nNo {selected_type} log files found for user '{selected_user}'.")
                print(f"Searched in: /home/{selected_user}/logs/")

                # Show what files are available
                logs_dir = Path(f"/home/{selected_user}/logs")
                if logs_dir.exists():
                    print(f"\nAvailable files in logs directory:")
                    for f in logs_dir.rglob("*"):
                        if f.is_file():
                            print(f"  - {f.relative_to(logs_dir)}")

                input(f"\n{DIM}Press Enter to go back...{RESET}")
                continue  # Go back to log type selection

            while True:
                # Step 3: Select file
                file_choice = select_log_file(log_files, selected_type)
                if file_choice is None:
                    print("\nExiting...")
                    return
                if file_choice == "back":
                    break  # Go back to log type selection

                # Display selected file(s)
                if file_choice == 0:
                    for log_file in log_files:
                        display_log_file(log_file, selected_type)
                else:
                    display_log_file(log_files[file_choice - 1], selected_type)

                # After viewing, ask what to do next
                print(f"\n{DIM}{'─' * 40}{RESET}")
                print(f"  {BOLD}1.{RESET} View another file")
                print(f"  {BOLD}2.{RESET} Change log type")
                print(f"  {BOLD}3.{RESET} Change user")
                print(f"  {DIM}q. Quit{RESET}")

                try:
                    next_action = input(f"\n{BOLD}What next? (1-3):{RESET} ").strip().lower()

                    if next_action == "q":
                        print("\nExiting...")
                        return
                    elif next_action == "2":
                        break  # Go back to log type selection
                    elif next_action == "1":
                        continue  # Stay in file selection loop
                    elif next_action == "3":
                        go_to_user_select = True
                        break  # Will break twice to go to user selection

                except KeyboardInterrupt:
                    print("\n\nExiting...")
                    sys.exit(0)

            if go_to_user_select:
                go_to_user_select = False
                break  # Break out to user selection


def main():
    check_sudo()
    interactive_menu()
    print("\nDone.")


if __name__ == "__main__":
    main()
