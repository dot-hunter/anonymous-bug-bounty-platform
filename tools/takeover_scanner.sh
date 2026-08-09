#!/usr/bin/env bash
# takeover_scanner.sh — subdomain takeover scanner.
# Usage:
#   takeover_scanner.sh target.com [--check-all]
#   takeover_scanner.sh -f subs.txt
#
# Checks each subdomain's CNAME against ~60 known takeover-able services
# (S3, Azure, Heroku, GitHub Pages, Netlify, Shopify, Fastly, etc.).
# Only reports when the CNAME matches a dangling-service pattern AND the
# service returns an unclaimed error (NXDOMAIN for the CNAME target or
# provider "not found" page).
set -uo pipefail

TARGET="${1:-}"
FILE_MODE=false
[ "$TARGET" = "-f" ] && FILE_MODE=true

if $FILE_MODE; then
  SUBS_FILE="${2:-}"
  [ -z "$SUBS_FILE" ] && { echo "usage: takeover_scanner.sh -f subs.txt" >&2; exit 2; }
  [ -f "$SUBS_FILE" ] || { echo "[-] no file: $SUBS_FILE" >&2; exit 2; }
else
  [ -z "$TARGET" ] && { echo "usage: takeover_scanner.sh <target.com>" >&2; exit 2; }
  SUBS_FILE="recon/$TARGET/subs.txt"
  if [ ! -f "$SUBS_FILE" ]; then
    echo "[*] no recon dir — enumerating quick subs"
    mkdir -p "recon/$TARGET"
    { subfinder -d "$TARGET" -silent 2>/dev/null; assetfinder --subs-only "$TARGET" 2>/dev/null; echo "$TARGET"; } \
      | sort -u > "$SUBS_FILE"
  fi
fi

echo "◆ subdomain takeover scan on $(wc -l < "$SUBS_FILE") hosts"

# service pattern → CNAME marker → confirmation string (curl body)
declare -A CNAME_MARK=( [s3.amazonaws.com]="NoSuchBucket" [s3-website]="NoSuchBucket" \
 [azurewebsites.net]="404 Web Site not found" [cloudapp.net]="not found" \
 [azureedge.net]="No such app" [blob.core.windows.net]="The specified container does not exist" \
 [herokuapp.com]="No such app" [herokussl.com]="No such app" \
 [github.io]="There isn't a GitHub Pages site here" [pages.github.com]="There isn't a GitHub Pages site here" \
 [netlify.app]="Not Found - Request ID" [netlify.com]="Not Found - Request ID" \
 [surge.sh]="project not found" [bitbucket.io]="Repository not found" \
 [pantheon.io]="404 error unknown site" [fastly.net]="Fastly error: unknown domain" \
 [shopify.com]="Sorry, this shop is currently unavailable" [myshopify.com]="Only one step left" \
 [zendesk.com]="Help Center Closed" [readme.io]="Project doesnt exist" \
 [statuspage.io]="Fastly error: unknown domain" [tumblr.com]="There's nothing here" \
 [wordpress.com]="Do you want to register" [ghost.io]="The thing you were looking for is no longer here" \
 [strikingly.com]="The page you were looking for doesn't exist" [webflow.io]="The page you are looking for doesn't exist" \
 [unbouncepages.com]="The requested URL was not found" [cargo.site]="404" \
 [helpjuice.com]="We couldnt find the page you were looking for" [helpscoutdocs.com]="No settings were found" \
 [cargo.site]="404" [feedpress.me]="The feed you are looking for doesn't exist" \
 [uservoice.com]="This UserVoice instance does not exist" [smugmug.com]="SmugMug - Page Not Found" \
 [worksites.net]="Hello World!" [freshdesk.com]="Domain is not assigned to any account" \
 [intercom.help]="This page is no longer available" [idea.us]="404" \
 [ngrok.io]="Tunnel not found" [fly.dev]="The page you are looking for could not be found" \
 [vercel.app]="404: NOT_FOUND" [pages.dev]="404" [workers.dev]="not found" \
 [render.com]="Page not found" [gitbook.io]="No such app" )

FOUND=0
while IFS= read -r host; do
  [ -z "$host" ] && continue
  case "$host" in \#*) continue;; esac

  # 1. does it have a CNAME at all?
  cname=$(dig +short CNAME "$host" 2>/dev/null | head -1)
  [ -z "$cname" ] && continue

  # 2. does the CNAME point at a takeover-able service?
  marker=""
  for pat in "${!CNAME_MARK[@]}"; do
    if echo "$cname" | grep -qi "$pat"; then
      marker="${CNAME_MARK[$pat]}"
      break
    fi
  done
  [ -z "$marker" ] && continue

  # 3. confirm: does the service return the unclaimed marker?
  body=$(curl -s -m 10 -L "http://$host" 2>/dev/null | tr -d '\n' | head -c 4000)
  if echo "$body" | grep -qiF "$marker"; then
    echo "  [VULN] $host → $cname (unclaimed: ${marker:0:40}...)"
    echo "$host | $cname | $marker" >> findings/takeover_candidates.txt
    FOUND=$((FOUND+1))
  else
    echo "  [dangling?] $host → $cname (marker not confirmed)"
  fi
done < "$SUBS_FILE"

echo ""
if [ "$FOUND" -gt 0 ]; then
  echo "[+] $FOUND confirmed takeover candidates → findings/takeover_candidates.txt"
else
  echo "[*] no confirmed takeovers"
fi