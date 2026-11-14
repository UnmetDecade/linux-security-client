#!/bin/sh
# Create the industry-standard EICAR test file (harmless) in a scan directory.
set -eu
dest=${1:-./scan-data}
name=${2:-eicar-test.txt}
mkdir -p "$dest"
printf '%s' 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=' \
    | base64 -d > "$dest/$name"
printf '\n' >> "$dest/$name"
echo "Created EICAR test file: $dest/$name"
