#!/bin/bash

LOGFILE="/var/log/clamav/home-scan.log"

# Ensure log directory exists
mkdir -p /var/log/clamav

echo "=== Scan started on $(date) ===" >> "$LOGFILE"

# Run scan with auto-removal
if systemctl is-active --quiet clamav-daemon; then
    # Use clamdscan (daemon version)
    clamdscan --infected --remove=yes /home >> "$LOGFILE" 2>&1
else
    # Fall back to clamscan
    clamscan --infected --remove=yes -r /home >> "$LOGFILE" 2>&1
fi

echo "=== Scan finished on $(date) ===" >> "$LOGFILE"
echo "" >> "$LOGFILE"
