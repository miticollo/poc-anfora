#!/usr/bin/env bash
#
# Check if an .mobileprovision file is expired.

set -e

function err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: ${*}" >&2
}

function usage() {
  echo "Check if an .mobileprovision file is expired."
  echo "Usage: $(basename "${0}") <path_to_mobileprovision>"
}

if [[ ${#} -ne 1 ]]; then
  usage
  exit 1
fi

if [[ ! -f "${1}" ]]; then
  err "Error: file ${1} not found"
  usage
  exit 1
fi

# https://github.com/stendahls/cert-downloader/blob/07d20758ea9eaa88c16e6004020627b281b873ca/index.js#L138
expiration_date=$(openssl smime -in "${1}" -inform der -verify 2>/dev/null | plutil -extract 'ExpirationDate' 'raw' -expect 'date' -)
if [[ -z ${expiration_date} ]]; then
  err "Error: unable to extract expiration date from ${1}"
  usage
  exit 1
fi

expiration_timestamp=$(date -jf '%Y-%m-%dT%H:%M:%SZ' "${expiration_date}" '+%s')
current_timestamp=$(date '+%s')

if [[ ${expiration_timestamp} -lt ${current_timestamp} ]]; then
  echo "The mobileprovision has expired."
else
  echo "The mobileprovision is still valid."
fi