#!/bin/bash
# Simple alert script that emails when new connections are detected

LOG_FILE="/opt/honeypot/logs/connections.log"
TMP_FILE="/tmp/last_connections.tmp"
ADMIN_EMAIL="admin@yourdomain.com"

if [ ! -f "$TMP_FILE" ]; then
    touch "$TMP_FILE"
fi

NEW_CONNS=$(comm -23 <(sort "$LOG_FILE") <(sort "$TMP_FILE"))

if [ -n "$NEW_CONNS" ]; then
    echo -e "New honeypot connections detected:\n\n$NEW_CONNS" | mail -s "Honeypot Alert" "$ADMIN_EMAIL"
    sort "$LOG_FILE" > "$TMP_FILE"
fi
