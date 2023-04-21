#!/usr/bin/env bash
#
# A script for streaming from an WDA MJPEG Server!

set +x

function err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function show_usage() {
    echo "Usage: $(basename "${0}") <port> [-h|--help]"
    echo "A script for streaming from an WDA MJPEG Server!"
}

function check_dependencies() {
    command -v "${1}" >/dev/null 2>&1 || { err "Error: ${1} not found in \$PATH. Exiting."; exit 1; }
}

function main() {
  if [[ "${#}" -eq 0 ]]; then
    show_usage
    exit 1
  fi

  if [[ "${1}" == "-h" ]] || [[ "${1}" == "--help" ]]; then
    show_usage
    exit 0
  fi

  check_dependencies "mpv"
  check_dependencies "iproxy"

  if [[ ! "${1}" =~ ^[0-9]+$ ]] || (( "${1}" < 1024 || "${1}" > 65535 )); then
    err "Error: Invalid port number provided. Exiting."
    exit 1
  fi

  iproxy "${1}":"${1}" &> /dev/null &

  mpv \
    --demuxer-lavf-format=mjpeg \
    --profile=low-latency \
    --untimed \
    --autofit=25% \
    --no-osc \
    http://localhost:"${1}"

  kill %1
}

main "${@}"
exit 0
