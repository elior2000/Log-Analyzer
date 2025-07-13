#!/usr/bin/env python3
"""
Log Analyzer - Analyze Linux auth.log files for security events
Author: Elior Salimi

This script analyzes /var/log/auth.log for security-related events:
- Command usage (sudo, su) with timestamp, user, command.
- User add/delete events with timestamp.
- Password changes with timestamp.
- Alerts for failed sudo attempts.
If /var/log/auth.log does not exist, the script offers to install and enable rsyslog to generate it.
"""

import re
import os
import sys
import subprocess
import time

LOG_FILE = "/var/log/auth.log"

def ensure_auth_log_exists():
    """
    Checks if /var/log/auth.log exists.
    If not, offers to install & enable rsyslog and waits for file to appear.
    """
    if os.path.isfile(LOG_FILE):
        return True

    print(f"\n[!] {LOG_FILE} not found.")
    answer = input("Do you want to install & enable rsyslog to generate this log? [Y/n]: ").strip().lower()
    if answer not in ("", "y", "yes"):
        print("Exiting. Cannot continue without auth.log.")
        sys.exit(1)
    # Try to install rsyslog (Debian/Ubuntu style)
    subprocess.run(["sudo", "apt-get", "update"])
    subprocess.run(["sudo", "apt-get", "install", "-y", "rsyslog"])
    subprocess.run(["sudo", "systemctl", "enable", "rsyslog"])
    subprocess.run(["sudo", "systemctl", "start", "rsyslog"])

    # Wait for the log to be created (up to 10 seconds)
    print("[*] Waiting for auth.log to be created...")
    for _ in range(10):
        if os.path.isfile(LOG_FILE):
            print("[*] auth.log is now available.\n")
            return True
        time.sleep(1)
    print("[!] auth.log was not created. Please check rsyslog/service configuration.")
    sys.exit(1)

def parse_log_line(line):
    """
    Parse lines in ISO or syslog format.
    Returns timestamp, host, process, message.
    """
    # ISO format (modern Ubuntu/Kali)
    regex_iso = r'^(\d{4}-\d{2}-\d{2}T[\d:\.\-\+]+)\s+([\w\-]+)\s+([\w\-/]+):\s+(.*)'
    match = re.match(regex_iso, line)
    if match:
        date_str, host, process, message = match.groups()
        return date_str, host, process, message
    # syslog legacy format (optional)
    regex_syslog = r'^([A-Z][a-z]{2}\s+\d+\s[\d:]+)\s+([\w\-]+)\s+([\w\-/]+):\s+(.*)'
    match = re.match(regex_syslog, line)
    if match:
        date_str, host, process, message = match.groups()
        return date_str, host, process, message
    return None, None, None, None

def extract_sudo_command(message):
    """
    Extracts sudo command usage (with username and command).
    """
    sudo_regex = r'(\w+)\s*:\s*TTY=.*USER=.*;\s*COMMAND=(.*)'
    sudo_match = re.search(sudo_regex, message)
    if sudo_match:
        user, command = sudo_match.groups()
        return user, command.strip()
    return None, None

def extract_failed_sudo(message):
    """
    Detects failed sudo attempts.
    """
    fail_regex = r'sudo: (.*authentication failure|.*incorrect password|.*pam_authenticate: Authentication failure)'
    match = re.search(fail_regex, message, re.IGNORECASE)
    return bool(match)

def extract_su_command(message):
    """
    Detects use of su command.
    """
    su_regex = r'su: session opened for user (\w+) by (\w+)'
    match = re.search(su_regex, message)
    if match:
        target_user, by_user = match.groups()
        return target_user, by_user
    return None, None

def extract_session_event(message):
    """
    Checks for sudo session opened/closed events.
    """
    opened_regex = r'session opened for user (\w+).*by (\w+)\('
    closed_regex = r'session closed for user (\w+)'
    open_match = re.search(opened_regex, message)
    close_match = re.search(closed_regex, message)
    if open_match:
        return 'opened', open_match.groups()
    if close_match:
        return 'closed', (close_match.group(1),)
    return None, None

def extract_user_add(line):
    add_regex = r'useradd\[\d+\]: new user: name=(\w+)'
    match = re.search(add_regex, line)
    if match:
        return match.group(1)
    return None

def extract_user_delete(line):
    del_regex = r'userdel\[\d+\]: delete user \'?(\w+)\'?'
    match = re.search(del_regex, line)
    if match:
        return match.group(1)
    return None

def extract_password_change(line):
    passwd_regex = r'passwd\[\d+\]: password for user (\w+) changed'
    match = re.search(passwd_regex, line)
    if match:
        return match.group(1)
    return None

def main():
    ensure_auth_log_exists()
    with open(LOG_FILE, "r") as logfile:
        for line in logfile:
            date, host, process, message = parse_log_line(line)
            if not date:
                continue

            # User added
            user_added = extract_user_add(line)
            if user_added:
                print(f"[{date}] New user added: {user_added}")
                continue

            # User deleted
            user_deleted = extract_user_delete(line)
            if user_deleted:
                print(f"[{date}] User deleted: {user_deleted}")
                continue

            # Password changed
            pw_user = extract_password_change(line)
            if pw_user:
                print(f"[{date}] Password changed for user: {pw_user}")
                continue

            # Sudo command usage
            user, command = extract_sudo_command(message)
            if user and command:
                print(f"[{date}] [sudo] {user} ran: {command}")
                continue

            # Failed sudo attempt
            if extract_failed_sudo(message):
                print(f"[{date}] ALERT! Failed sudo attempt detected: {message.strip()}")
                continue

            # su usage
            target_user, by_user = extract_su_command(message)
            if target_user and by_user:
                print(f"[{date}] [su] {by_user} used su to switch to {target_user}")
                continue

            # Session opened/closed (for sudo/su)
            action, details = extract_session_event(message)
            if action == 'opened':
                target, by = details
                print(f"[{date}] [sudo] Session opened for user {target} by {by}")
            elif action == 'closed':
                (target,) = details
                print(f"[{date}] [sudo] Session closed for user {target}")

if __name__ == "__main__":
    main()
