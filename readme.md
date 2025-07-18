# Log Analyzer

A powerful Python tool to analyze Linux authentication logs (`/var/log/auth.log`) and extract key security events and insights for system monitoring and cyber investigations.

---

## Features

- **Command Usage Detection:**\
  Detects all commands executed via `sudo` and `su` with timestamps and users.

- **User Management Events:**\
  Identifies when users are added or deleted, including timestamps.

- **Password Changes:**\
  Tracks password changes with user and time.

- **Session Monitoring:**\
  Reports when authentication sessions are opened or closed (including by whom and for whom).

- **Failed sudo Alerts:**\
  Raises clear ALERTs for failed `sudo` attempts.

---

## Example Output

```
[2025-07-09T13:11:34.985081-04:00] [sudo] kali ran: ./Nett040Crafts.sh
[2025-07-09T13:11:34.992057-04:00] [sudo] Session opened for user root by kali
[2025-07-09T13:14:21.427462-04:00] [sudo] Session closed for user root
[2025-07-13T17:49:37.9274-04:00] [sudo] kali ran: ./Nett040Crafts.sh
```

---

## How It Works

The script scans each line of `/var/log/auth.log` and applies multiple regular expressions to detect:

- When and which commands were run using `sudo` or `su`
- Additions and deletions of user accounts
- Password changes for users
- Sessions opened or closed via authentication
- Failed attempts to run `sudo` commands

All detected events are printed to the console in a clear, timestamped format.

---

## Installation

1. Clone the repository or download the script:

   ```bash
   git clone https://github.com/elior2000/Log-Analyzer.git
   cd Log-Analyzer
   ```

2. Make sure you have Python 3 installed (recommended: latest version).

---

## Usage

> \*\*Requires root privileges to access \*\*``

```bash
sudo python3 Log_Analyzer.py
```

If you want to test with a different log file, edit the `LOG_FILE` variable at the top of the script.

---

## Real-World Relevance

- Useful for blue-team analysts, system administrators, and anyone responsible for Linux security monitoring.
- Helps identify suspicious activity, privilege escalations, and unauthorized user management actions.
- Assists in incident response, log forensics, and system audits.

---

## Credits

- **Author:** [Elior Salimi](https://github.com/elior2000)
- **Inspired by:** ThinkCyber Python Fundamentals Project

---

## License

This project is for educational and research purposes only.

---



