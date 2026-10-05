#!/usr/bin/env bash
# One aggregation run. Creates ETI/.venv on first use; arguments go to `python -m eti`.
#
#   ./run.sh               fetch, score, write output/<datetime>.csv, update state/
#   ./run.sh --no-state    the same, leaving state/ alone so it can be repeated
#   ./run.sh test          the test suite (no network)

set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ] || [ requirements.txt -nt .venv/.eti-installed ]; then
  [ -x .venv/bin/python ] || python3 -m venv .venv
  .venv/bin/pip -q --disable-pip-version-check install -r requirements.txt pytest
  touch .venv/.eti-installed
fi

case "${1:-}" in
  test) .venv/bin/python -m pytest -q tests "${@:2}" ;;
  *)    .venv/bin/python -m eti "$@" ;;
esac
