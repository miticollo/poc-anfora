#!/usr/bin/env bash
#
# Retrieve your DEVELOPMENT_TEAM from certs.

function err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function is_email_valid() {
  local regex="^(([A-Za-z0-9]+((\.|\-|\_|\+)?[A-Za-z0-9]?)*[A-Za-z0-9]+)|[A-Za-z0-9]+)@(([A-Za-z0-9]+)+((\.|\-|\_)?([A-Za-z0-9]+)+)*)+\.([A-Za-z]{2,})+$"
  [[ "${1}" =~ ${regex} ]]
}

#######################################
# Retrieve your DEVELOPMENT_TEAM from certs.
# Arguments:
#   Your Apple ID.
# Returns:
#   0 if DEVELOPMENT_TEAM is printed, non-zero on error.
#######################################
function main() {
  # requires openssl@3 from Homebrew
  _openssl=$(brew --prefix openssl 2>/dev/null)/bin/openssl
  [[ -x $_openssl ]] || { err "missing openssl, try \`brew install openssl\`"; exit 1; }

  if [ -z "$1" ]; then
    echo "Usage: ${0} APPLE_ID"
    exit 1
  fi

  if ! is_email_valid "${1}" ;then
    err "Error: Invalid Apple ID"
    exit 1
  fi

  local found
  found=$(security find-certificate -c "${1}" -Z login.keychain 2> /dev/null | grep -c ^SHA-1)
  echo "I found ${found} certificate(s)"
  if [[ "${found}" -eq 0 ]]; then
    exit 2
  fi
  # https://stackoverflow.com/a/74194064
  # https://stackoverflow.com/a/70464809
  local dev_team
  dev_team=$(security find-certificate -c "${1}" -p login.keychain | "${_openssl}" x509 -noout -subject -nameopt multiline | grep 'organizationalUnitName' | awk '{ print $3 }')
  echo "DEVELOPMENT_TEAM=${dev_team}"

}

main "${@}"
exit 0

