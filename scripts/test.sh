#!/bin/sh
# Run the full local test suite (no third-party Python packages required).
set -eu
cd "$(dirname "$0")/.."
PYTHONPATH=src exec python3 -m unittest discover -s tests -t . -v
