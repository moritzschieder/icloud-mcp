#!/bin/sh
# Fetch the Cloudflare Access team keys for the owner SSO check. The app container cannot reach Cloudflare (egress rules),
# so the host refreshes the file and the app re-reads it on change (OWNER_ACCESS_CERTS_FILE=/data/access-certs.json).
set -eu
TEAM=schieder.cloudflareaccess.com
DIR=/var/lib/docker/volumes/icloud-mcp_icloud_mcp_data/_data
TMP=$(mktemp "$DIR/.access-certs.XXXXXX")
trap 'rm -f "$TMP"' EXIT
curl -fsS --max-time 15 -A icloud-mcp-access-certs/1.0 "https://$TEAM/cdn-cgi/access/certs" -o "$TMP"
grep -q '"keys"' "$TMP"                     # a key set, not an error page
chown 10001 "$TMP"; chmod 0644 "$TMP"
mv -f "$TMP" "$DIR/access-certs.json"
trap - EXIT
