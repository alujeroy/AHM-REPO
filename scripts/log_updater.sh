while true; do
  python3 /opt/honeypot/scripts/format_combined_logs.py
  sleep 300  # every 5 minutes
done
