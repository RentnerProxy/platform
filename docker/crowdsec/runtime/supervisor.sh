#!/usr/bin/env bash
set -Eeuo pipefail
unset SMTP_USER SMTP_PASSWORD
exec /usr/local/bin/rentnerproxy-controller --appliance-supervisor crowdsec
