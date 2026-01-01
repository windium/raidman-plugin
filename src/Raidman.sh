#!/bin/bash
############
SERVICE_URL="http://127.0.0.1:9876/api/internal/push"

############
############
# Quick test with default values:
#   bash /boot/config/plugins/dynamix/notifications/agents/Raidman
# Quick test with values set through environment (all vars are optional)
#   EVENT="My Event" SUBJECT="My Subject" DESCRIPTION="My Description" CONTENT="My Message" IMPORTANCE="alert" LINK="/Dashboard" bash /boot/config/plugins/dynamix/notifications/agents/Raidman
# Full test of notification system (at least one param is required)
#   /usr/local/emhttp/webGui/scripts/notify -e "My Event" -s "My Subject" -d "My Description" -m "My Message" -i "alert" -l "/Dashboard"
#
# If a notification does not go through, check the /var/log/notify_Raidman file for hints
############
############
# Available fields from notification system
# HOSTNAME
# EVENT (notify -e)
# IMPORTANCE (notify -i)
# SUBJECT (notify -s)
# DESCRIPTION (notify -d)
# CONTENT (notify -m)
# LINK (notify -l)
# TIMESTAMP (seconds from epoch)

SCRIPTNAME=$(basename "$0")
LOG="/var/log/notify_${SCRIPTNAME}"

# For quick test, setup environment to mimic notify script
EVENT="${EVENT:-Unraid Status}"
SUBJECT="${SUBJECT:-Notification}"
DESCRIPTION="${DESCRIPTION:-No description}"
IMPORTANCE="${IMPORTANCE:-normal}"
CONTENT="${CONTENT:-}"
LINK="${LINK:-}"
HOSTNAME="${HOSTNAME:-$(hostname)}"
TIMESTAMP="${TIMESTAMP:-$(date +%s)}"

{
  echo "----------------------------------------"
  echo "$(date) - [Raidman Agent] Script started"
  echo "EVENT: $EVENT"
  echo "SUBJECT: $SUBJECT"
  echo "DESCRIPTION: $DESCRIPTION"
  echo "IMPORTANCE: $IMPORTANCE"
  echo "CONTENT: $CONTENT"
  echo "LINK: $LINK"
  echo "HOSTNAME: $HOSTNAME"
  echo "TIMESTAMP: $TIMESTAMP"
} >> "$LOG"

# Construct JSON payload
PAYLOAD_FILE="/tmp/raidman_payload_$$.json"

# Escape quotes for JSON
safe_event=$(echo "$EVENT" | sed 's/"/\\"/g')
safe_severity=$(echo "$IMPORTANCE" | sed 's/"/\\"/g')
safe_subject=$(echo "$SUBJECT" | sed 's/"/\\"/g')
safe_description=$(echo "$DESCRIPTION" | sed 's/"/\\"/g')
safe_link=$(echo "$LINK" | sed 's/"/\\"/g')
safe_content=$(echo "$CONTENT" | sed 's/"/\\"/g')
safe_hostname=$(echo "$HOSTNAME" | sed 's/"/\\"/g')

# Build JSON
cat > "$PAYLOAD_FILE" <<EOF
{
  "event": "$safe_event",
  "severity": "$safe_severity",
  "subject": "$safe_subject",
  "description": "$safe_description",
  "link": "$safe_link",
  "content": "$safe_content",
  "hostname": "$safe_hostname",
  "timestamp": $TIMESTAMP
}
EOF

# Log payload
{
  echo "Payload:"
  cat "$PAYLOAD_FILE"
} >> "$LOG"

# Send to Raidman service
echo "Sending to $SERVICE_URL..." >> "$LOG"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST -H "Content-Type: application/json" -d @"$PAYLOAD_FILE" "$SERVICE_URL" 2>&1)

{
  echo "Response: $RESPONSE"
  echo "Script completed"
  echo ""
} >> "$LOG"

# Cleanup
rm -f "$PAYLOAD_FILE"

# Log to syslog on failure
if [[ "$RESPONSE" != *"HTTP_CODE:200"* ]]; then
  logger -t "$SCRIPTNAME" -- "Failed sending notification to Raidman service"
fi
